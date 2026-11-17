package account

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	moveJournalPrefix  = ".account-move-"
	moveJournalSuffix  = ".json"
	moveJournalVersion = 1
	maxMoveJournalSize = 64 << 10
)

type moveJournal struct {
	Version      int    `json:"version"`
	MoveID       string `json:"move_id"`
	AccountID    string `json:"account_id"`
	Source       string `json:"source"`
	HiddenSource string `json:"hidden_source"`
	Staging      string `json:"staging"`
	Final        string `json:"final"`
}

func (j moveJournal) filename(targetRoot string) string {
	return filepath.Join(targetRoot, moveJournalPrefix+j.MoveID+moveJournalSuffix)
}

func writeMoveJournal(path string, journal moveJournal) error {
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".move-journal-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := errors.Join(temporary.Sync(), temporary.Close()); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func readMoveJournal(path string) (moveJournal, error) {
	file, err := os.Open(path)
	if err != nil {
		return moveJournal{}, err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxMoveJournalSize+1))
	decoder.DisallowUnknownFields()
	var journal moveJournal
	if err := decoder.Decode(&journal); err != nil {
		return moveJournal{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return moveJournal{}, errors.New("move journal contains trailing data")
	}
	return journal, nil
}

func recoverMoves(roots []Root) error {
	rootPaths := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		absolute, err := filepath.Abs(root.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return err
		}
		rootPaths[filepath.Clean(absolute)] = struct{}{}
	}
	for _, root := range roots {
		entries, err := os.ReadDir(root.Path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), moveJournalPrefix) || !strings.HasSuffix(entry.Name(), moveJournalSuffix) {
				continue
			}
			path := filepath.Join(root.Path, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("invalid account move journal %q", path)
			}
			journal, err := readMoveJournal(path)
			if err != nil {
				return fmt.Errorf("read account move journal %q: %w", path, err)
			}
			if err := validateMoveJournal(journal, rootPaths, root.Path, entry.Name()); err != nil {
				return fmt.Errorf("validate account move journal %q: %w", path, err)
			}
			if err := recoverMove(path, journal); err != nil {
				return fmt.Errorf("recover account move %q: %w", journal.MoveID, err)
			}
		}
	}
	return nil
}

func validateMoveJournal(journal moveJournal, roots map[string]struct{}, targetRoot, filename string) error {
	if journal.Version != moveJournalVersion || !accountIDPattern.MatchString(journal.AccountID) || !strings.HasPrefix(journal.MoveID, "mov_") {
		return errors.New("invalid move journal identity")
	}
	if filename != moveJournalPrefix+journal.MoveID+moveJournalSuffix {
		return errors.New("move journal filename does not match identity")
	}
	for _, path := range []string{journal.Source, journal.HiddenSource, journal.Staging, journal.Final} {
		if _, configured := roots[filepath.Clean(filepath.Dir(path))]; !configured {
			return fmt.Errorf("move path %q is outside configured roots", path)
		}
	}
	if filepath.Clean(filepath.Dir(journal.Final)) != filepath.Clean(targetRoot) || filepath.Base(journal.Source) != journal.AccountID || filepath.Base(journal.Final) != journal.AccountID || filepath.Base(journal.Staging) != "."+journal.MoveID || filepath.Base(journal.HiddenSource) != ".moved-"+journal.AccountID+"-"+journal.MoveID {
		return errors.New("move journal paths do not match identity")
	}
	return nil
}

func recoverMove(journalPath string, journal moveJournal) error {
	sourceExists, err := safeDirectoryExists(journal.Source)
	if err != nil {
		return err
	}
	hiddenExists, err := safeDirectoryExists(journal.HiddenSource)
	if err != nil {
		return err
	}
	finalExists, err := validMovedAccount(journal.Final, journal.AccountID)
	if err != nil {
		return err
	}
	stagingExists, err := validMovedAccount(journal.Staging, journal.AccountID)
	if err != nil {
		return err
	}

	switch {
	case finalExists && !sourceExists:
		if stagingExists {
			if err := os.RemoveAll(journal.Staging); err != nil {
				return err
			}
		}
	case sourceExists && !hiddenExists && !finalExists:
		if stagingExists {
			if err := os.RemoveAll(journal.Staging); err != nil {
				return err
			}
		}
	case !sourceExists && hiddenExists && stagingExists && !finalExists:
		if err := os.Rename(journal.Staging, journal.Final); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(journal.Final)); err != nil {
			return err
		}
	case !sourceExists && hiddenExists && !stagingExists && !finalExists:
		if err := os.Rename(journal.HiddenSource, journal.Source); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(journal.Source)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("ambiguous move state source=%t hidden=%t staging=%t final=%t", sourceExists, hiddenExists, stagingExists, finalExists)
	}
	if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(journalPath))
}

func safeDirectoryExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("move path %q is not a safe directory", path)
	}
	return true, nil
}

func validMovedAccount(path, accountID string) (bool, error) {
	exists, err := safeDirectoryExists(path)
	if err != nil || !exists {
		return exists, err
	}
	manifest, err := ReadManifest(filepath.Join(path, ManifestFilename))
	if err != nil {
		return false, fmt.Errorf("validate moved account at %q: %w", path, err)
	}
	if manifest.ID != accountID {
		return false, errors.New("moved account identity mismatch")
	}
	return true, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
