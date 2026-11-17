package releasebuild

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

const buildInfoName = "BUILD-INFO.json"

// BuildOptions identifies one reproducible release build.
type BuildOptions struct {
	Root          string
	OutputDir     string
	Tag           string
	Commit        string
	BuiltAt       time.Time
	WorkflowRunID string
	GOOS          string
	GOARCH        string
	Variant       string
}

// BuildInfo is embedded in every release archive.
type BuildInfo struct {
	SchemaVersion int      `json:"schema_version"`
	Tag           string   `json:"tag"`
	Commit        string   `json:"commit"`
	BuiltAt       string   `json:"built_at"`
	GoVersion     string   `json:"go_version"`
	WorkflowRunID string   `json:"workflow_run_id"`
	GOOS          string   `json:"goos"`
	GOARCH        string   `json:"goarch"`
	Variant       string   `json:"variant"`
	BuildTags     []string `json:"build_tags"`
	Features      []string `json:"features"`
	BinarySHA256  string   `json:"binary_sha256"`
}

// Artifact describes one archive in the aggregate release manifest.
type Artifact struct {
	Name         string   `json:"name"`
	GOOS         string   `json:"goos"`
	GOARCH       string   `json:"goarch"`
	Variant      string   `json:"variant"`
	BuildTags    []string `json:"build_tags"`
	Features     []string `json:"features"`
	SHA256       string   `json:"sha256"`
	BinarySHA256 string   `json:"binary_sha256"`
	Size         int64    `json:"size"`
}

// Fragment is the independently produced manifest record for one artifact.
type Fragment struct {
	SchemaVersion int      `json:"schema_version"`
	Tag           string   `json:"tag"`
	Commit        string   `json:"commit"`
	BuiltAt       string   `json:"built_at"`
	GoVersion     string   `json:"go_version"`
	WorkflowRunID string   `json:"workflow_run_id"`
	Artifact      Artifact `json:"artifact"`
}

// Manifest is the traceability record published with a release.
type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Tag           string     `json:"tag"`
	Commit        string     `json:"commit"`
	BuiltAt       string     `json:"built_at"`
	GoVersion     string     `json:"go_version"`
	WorkflowRunID string     `json:"workflow_run_id"`
	Artifacts     []Artifact `json:"artifacts"`
}

// BuildOne cross-compiles and packages one matrix entry.
func BuildOne(ctx context.Context, options BuildOptions) (Fragment, error) {
	if err := validateBuildOptions(options); err != nil {
		return Fragment{}, err
	}
	variant, _ := VariantByName(options.Variant)
	artifactName, _ := ArtifactName(options.Tag, options.GOOS, options.GOARCH, options.Variant)
	goVersion, err := commandOutput(ctx, options.Root, nil, "go", "env", "GOVERSION")
	if err != nil {
		return Fragment{}, fmt.Errorf("identify Go toolchain: %w", err)
	}
	if err := os.MkdirAll(options.OutputDir, 0o755); err != nil {
		return Fragment{}, fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.MkdirTemp("", "veksel-release-")
	if err != nil {
		return Fragment{}, fmt.Errorf("create build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	binary := filepath.Join(temporary, binaryName)
	if options.GOOS == "windows" {
		binary += ".exe"
	}
	ldflags := strings.Join([]string{
		"-s", "-w", "-buildid=",
		"-X", "main.buildVersion=" + options.Tag,
		"-X", "main.buildTime=" + options.BuiltAt.UTC().Format(time.RFC3339),
		"-X", "main.buildCommit=" + options.Commit,
	}, " ")
	arguments := []string{"build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags}
	if len(variant.BuildTags) > 0 {
		arguments = append(arguments, "-tags", strings.Join(variant.BuildTags, ","))
	}
	arguments = append(arguments, "-o", binary, "./cmd/veksel")
	environment := append(os.Environ(), "CGO_ENABLED=0", "GOOS="+options.GOOS, "GOARCH="+options.GOARCH)
	if _, err := commandOutput(ctx, options.Root, environment, "go", arguments...); err != nil {
		return Fragment{}, fmt.Errorf("build %s/%s %s: %w", options.GOOS, options.GOARCH, options.Variant, err)
	}
	if NativeTarget(options.GOOS, options.GOARCH) {
		output, runErr := commandOutput(ctx, options.Root, nil, binary, "--version")
		want := fmt.Sprintf("veksel %s\ncommit %s\nbuilt %s", options.Tag, options.Commit, options.BuiltAt.UTC().Format(time.RFC3339))
		if runErr != nil {
			return Fragment{}, fmt.Errorf("verify native build metadata: %w", runErr)
		}
		if output != want {
			return Fragment{}, fmt.Errorf("native build metadata mismatch: got %q, want %q", output, want)
		}
	}
	binaryHash, _, err := fileDigest(binary)
	if err != nil {
		return Fragment{}, fmt.Errorf("hash binary: %w", err)
	}
	info := BuildInfo{
		SchemaVersion: ManifestSchema, Tag: options.Tag, Commit: options.Commit,
		BuiltAt: options.BuiltAt.UTC().Format(time.RFC3339), GoVersion: goVersion,
		WorkflowRunID: options.WorkflowRunID, GOOS: options.GOOS, GOARCH: options.GOARCH,
		Variant: variant.Name, BuildTags: variant.BuildTags, Features: variant.Features,
		BinarySHA256: binaryHash,
	}
	infoData, err := marshalJSON(info)
	if err != nil {
		return Fragment{}, fmt.Errorf("encode build information: %w", err)
	}
	archivePath := filepath.Join(options.OutputDir, artifactName)
	if err := writeArchive(archivePath, filepath.Base(binary), binary, infoData, options.BuiltAt.UTC()); err != nil {
		return Fragment{}, err
	}
	archiveHash, archiveSize, err := fileDigest(archivePath)
	if err != nil {
		return Fragment{}, fmt.Errorf("hash artifact: %w", err)
	}
	fragment := Fragment{
		SchemaVersion: ManifestSchema, Tag: options.Tag, Commit: options.Commit,
		BuiltAt: info.BuiltAt, GoVersion: goVersion, WorkflowRunID: options.WorkflowRunID,
		Artifact: Artifact{
			Name: artifactName, GOOS: options.GOOS, GOARCH: options.GOARCH, Variant: variant.Name,
			BuildTags: variant.BuildTags, Features: variant.Features, SHA256: archiveHash,
			BinarySHA256: binaryHash, Size: archiveSize,
		},
	}
	fragmentData, err := marshalJSON(fragment)
	if err != nil {
		return Fragment{}, fmt.Errorf("encode artifact fragment: %w", err)
	}
	fragmentPath := filepath.Join(options.OutputDir, artifactName+".fragment.json")
	if err := os.WriteFile(fragmentPath, fragmentData, 0o644); err != nil {
		return Fragment{}, fmt.Errorf("write artifact fragment: %w", err)
	}
	return fragment, nil
}

func validateBuildOptions(options BuildOptions) error {
	if err := ValidateTag(options.Tag); err != nil {
		return err
	}
	if !SupportsTarget(options.GOOS, options.GOARCH) {
		return fmt.Errorf("unsupported release target %s/%s", options.GOOS, options.GOARCH)
	}
	if _, err := VariantByName(options.Variant); err != nil {
		return err
	}
	if len(options.Commit) != 40 {
		return errors.New("full 40-character source commit is required")
	}
	if _, err := hex.DecodeString(options.Commit); err != nil {
		return errors.New("source commit must be hexadecimal")
	}
	if options.BuiltAt.IsZero() || options.BuiltAt.Location() != time.UTC {
		return errors.New("UTC build time is required")
	}
	if strings.TrimSpace(options.WorkflowRunID) == "" || strings.ContainsAny(options.WorkflowRunID, "\r\n\t") {
		return errors.New("workflow run ID is required")
	}
	if options.Root == "" || options.OutputDir == "" {
		return errors.New("repository root and output directory are required")
	}
	if _, err := os.Stat(filepath.Join(options.Root, "go.mod")); err != nil {
		return fmt.Errorf("repository root has no go.mod: %w", err)
	}
	return nil
}

func commandOutput(ctx context.Context, directory string, environment []string, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	if environment != nil {
		command.Env = environment
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w\n%s", name, err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func writeArchive(path, archivedBinary, binaryPath string, info []byte, modified time.Time) (resultErr error) {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create artifact: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	if strings.HasSuffix(path, ".zip") {
		writer := zip.NewWriter(file)
		if err := writeZipContents(writer, archivedBinary, binaryPath, info, modified); err != nil {
			_ = writer.Close()
			return err
		}
		return writer.Close()
	}
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("initialize gzip: %w", err)
	}
	gzipWriter.ModTime = modified
	gzipWriter.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	if err := writeTarContents(tarWriter, archivedBinary, binaryPath, info, modified); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return err
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return fmt.Errorf("close tar artifact: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip artifact: %w", err)
	}
	return nil
}

func writeTarContents(writer *tar.Writer, archivedBinary, binaryPath string, info []byte, modified time.Time) error {
	binary, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("open release binary: %w", err)
	}
	defer func() { _ = binary.Close() }()
	stat, err := binary.Stat()
	if err != nil {
		return fmt.Errorf("stat release binary: %w", err)
	}
	entries := []struct {
		name string
		mode int64
		size int64
		read io.Reader
	}{
		{name: archivedBinary, mode: 0o755, size: stat.Size(), read: binary},
		{name: buildInfoName, mode: 0o644, size: int64(len(info)), read: strings.NewReader(string(info))},
	}
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: entry.mode, Size: entry.size, ModTime: modified, AccessTime: modified, ChangeTime: modified, Format: tar.FormatPAX}
		if err := writer.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header %s: %w", entry.name, err)
		}
		if _, err := io.Copy(writer, entry.read); err != nil {
			return fmt.Errorf("write tar entry %s: %w", entry.name, err)
		}
	}
	return nil
}

func writeZipContents(writer *zip.Writer, archivedBinary, binaryPath string, info []byte, modified time.Time) error {
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read release binary: %w", err)
	}
	for _, entry := range []struct {
		name string
		mode fs.FileMode
		data []byte
	}{{archivedBinary, 0o755, binary}, {buildInfoName, 0o644, info}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		header.Modified = modified
		destination, err := writer.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("create zip entry %s: %w", entry.name, err)
		}
		if _, err := destination.Write(entry.data); err != nil {
			return fmt.Errorf("write zip entry %s: %w", entry.name, err)
		}
	}
	return nil
}

// Assemble verifies every expected fragment and writes release assets.
func Assemble(inputDir, outputDir string) (Manifest, error) {
	fragments, archives, err := readParts(inputDir)
	if err != nil {
		return Manifest{}, err
	}
	if len(fragments) == 0 {
		return Manifest{}, errors.New("no artifact fragments found")
	}
	first := fragments[0]
	manifest := Manifest{
		SchemaVersion: ManifestSchema, Tag: first.Tag, Commit: first.Commit, BuiltAt: first.BuiltAt,
		GoVersion: first.GoVersion, WorkflowRunID: first.WorkflowRunID,
	}
	seen := make(map[MatrixEntry]struct{}, len(fragments))
	for _, fragment := range fragments {
		if fragment.SchemaVersion != ManifestSchema || fragment.Tag != manifest.Tag || fragment.Commit != manifest.Commit || fragment.BuiltAt != manifest.BuiltAt || fragment.GoVersion != manifest.GoVersion || fragment.WorkflowRunID != manifest.WorkflowRunID {
			return Manifest{}, fmt.Errorf("artifact fragment %q has inconsistent release metadata", fragment.Artifact.Name)
		}
		entry := MatrixEntry{GOOS: fragment.Artifact.GOOS, GOARCH: fragment.Artifact.GOARCH, Variant: fragment.Artifact.Variant}
		if _, duplicate := seen[entry]; duplicate {
			return Manifest{}, fmt.Errorf("duplicate artifact for %+v", entry)
		}
		seen[entry] = struct{}{}
		expectedName, nameErr := ArtifactName(manifest.Tag, entry.GOOS, entry.GOARCH, entry.Variant)
		if nameErr != nil || expectedName != fragment.Artifact.Name {
			return Manifest{}, fmt.Errorf("invalid artifact name %q", fragment.Artifact.Name)
		}
		archivePath, ok := archives[fragment.Artifact.Name]
		if !ok {
			return Manifest{}, fmt.Errorf("artifact %q is missing", fragment.Artifact.Name)
		}
		digest, size, digestErr := fileDigest(archivePath)
		if digestErr != nil {
			return Manifest{}, digestErr
		}
		if digest != fragment.Artifact.SHA256 || size != fragment.Artifact.Size {
			return Manifest{}, fmt.Errorf("artifact %q does not match its fragment", fragment.Artifact.Name)
		}
		variant, _ := VariantByName(entry.Variant)
		if !slices.Equal(fragment.Artifact.BuildTags, variant.BuildTags) || !slices.Equal(fragment.Artifact.Features, variant.Features) {
			return Manifest{}, fmt.Errorf("artifact %q has incorrect feature metadata", fragment.Artifact.Name)
		}
		info, inspectErr := InspectArtifact(archivePath)
		if inspectErr != nil {
			return Manifest{}, fmt.Errorf("inspect artifact %q: %w", fragment.Artifact.Name, inspectErr)
		}
		if info.SchemaVersion != ManifestSchema || info.Tag != fragment.Tag || info.Commit != fragment.Commit || info.BuiltAt != fragment.BuiltAt || info.GoVersion != fragment.GoVersion || info.WorkflowRunID != fragment.WorkflowRunID || info.GOOS != entry.GOOS || info.GOARCH != entry.GOARCH || info.Variant != entry.Variant || info.BinarySHA256 != fragment.Artifact.BinarySHA256 || !slices.Equal(info.BuildTags, variant.BuildTags) || !slices.Equal(info.Features, variant.Features) {
			return Manifest{}, fmt.Errorf("artifact %q build information does not match its fragment", fragment.Artifact.Name)
		}
		manifest.Artifacts = append(manifest.Artifacts, fragment.Artifact)
	}
	matrix := Matrix{Include: make([]MatrixEntry, 0, len(seen))}
	for entry := range seen {
		matrix.Include = append(matrix.Include, entry)
	}
	if err := ValidateMatrix(matrix, true); err != nil {
		return Manifest{}, err
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].Name < manifest.Artifacts[j].Name })
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("create release output: %w", err)
	}
	existing, err := os.ReadDir(outputDir)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect release output: %w", err)
	}
	if len(existing) != 0 {
		return Manifest{}, errors.New("release output directory must be empty")
	}
	for _, artifact := range manifest.Artifacts {
		if err := copyFile(archives[artifact.Name], filepath.Join(outputDir, artifact.Name)); err != nil {
			return Manifest{}, err
		}
	}
	manifestData, err := marshalJSON(manifest)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(outputDir, "manifest.json"), manifestData, 0o644); err != nil {
		return Manifest{}, fmt.Errorf("write release manifest: %w", err)
	}
	var checksums strings.Builder
	for _, artifact := range manifest.Artifacts {
		fmt.Fprintf(&checksums, "%s  %s\n", artifact.SHA256, artifact.Name)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "SHA256SUMS"), []byte(checksums.String()), 0o644); err != nil {
		return Manifest{}, fmt.Errorf("write release checksums: %w", err)
	}
	return manifest, nil
}

// InspectArtifact verifies the two-file archive layout and embedded binary digest.
func InspectArtifact(path string) (BuildInfo, error) {
	if strings.HasSuffix(path, ".zip") {
		return inspectZip(path)
	}
	if strings.HasSuffix(path, ".tar.gz") {
		return inspectTar(path)
	}
	return BuildInfo{}, errors.New("unsupported artifact archive")
}

func inspectZip(path string) (BuildInfo, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return BuildInfo{}, err
	}
	defer func() { _ = reader.Close() }()
	if len(reader.File) != 2 {
		return BuildInfo{}, fmt.Errorf("archive contains %d entries, want 2", len(reader.File))
	}
	var info BuildInfo
	var binaryHash string
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			return BuildInfo{}, err
		}
		switch entry.Name {
		case "veksel.exe":
			if entry.Mode()&0o111 == 0 {
				_ = input.Close()
				return BuildInfo{}, errors.New("release binary is not executable")
			}
			binaryHash, err = readerDigest(input)
		case buildInfoName:
			err = decodeBoundedJSON(input, &info)
		default:
			err = fmt.Errorf("unexpected archive entry %q", entry.Name)
		}
		closeErr := input.Close()
		if err != nil {
			return BuildInfo{}, err
		}
		if closeErr != nil {
			return BuildInfo{}, closeErr
		}
	}
	return validateInspectedInfo(info, binaryHash)
}

func inspectTar(path string) (BuildInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return BuildInfo{}, err
	}
	defer func() { _ = file.Close() }()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return BuildInfo{}, err
	}
	defer func() { _ = gzipReader.Close() }()
	reader := tar.NewReader(gzipReader)
	var info BuildInfo
	var binaryHash string
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return BuildInfo{}, err
		}
		entries++
		switch header.Name {
		case binaryName:
			if header.FileInfo().Mode()&0o111 == 0 {
				return BuildInfo{}, errors.New("release binary is not executable")
			}
			binaryHash, err = readerDigest(reader)
		case buildInfoName:
			err = decodeBoundedJSON(reader, &info)
		default:
			err = fmt.Errorf("unexpected archive entry %q", header.Name)
		}
		if err != nil {
			return BuildInfo{}, err
		}
	}
	if entries != 2 {
		return BuildInfo{}, fmt.Errorf("archive contains %d entries, want 2", entries)
	}
	return validateInspectedInfo(info, binaryHash)
}

func readerDigest(reader io.Reader) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func decodeBoundedJSON(reader io.Reader, destination any) error {
	limited := io.LimitReader(reader, 1<<20)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("build information contains trailing data")
	}
	return nil
}

func validateInspectedInfo(info BuildInfo, binaryHash string) (BuildInfo, error) {
	if binaryHash == "" {
		return BuildInfo{}, errors.New("archive has no release binary")
	}
	if info.SchemaVersion == 0 {
		return BuildInfo{}, errors.New("archive has no build information")
	}
	if info.BinarySHA256 != binaryHash {
		return BuildInfo{}, errors.New("embedded binary digest does not match")
	}
	return info, nil
}

func readParts(root string) ([]Fragment, map[string]string, error) {
	var fragments []Fragment
	archives := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".fragment.json") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var fragment Fragment
			if err := json.Unmarshal(data, &fragment); err != nil {
				return fmt.Errorf("decode %s: %w", path, err)
			}
			fragments = append(fragments, fragment)
			return nil
		}
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip") {
			if previous := archives[name]; previous != "" {
				return fmt.Errorf("duplicate artifact name %q in %s and %s", name, previous, path)
			}
			archives[name] = path
		}
		return nil
	})
	return fragments, archives, err
}

// VerifyAssets proves an existing release has exactly the expected assets and bytes.
func VerifyAssets(expectedDir, actualDir string) error {
	expected, err := regularFiles(expectedDir)
	if err != nil {
		return err
	}
	actual, err := regularFiles(actualDir)
	if err != nil {
		return err
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("release has %d assets, want %d", len(actual), len(expected))
	}
	for name, expectedPath := range expected {
		actualPath, ok := actual[name]
		if !ok {
			return fmt.Errorf("release asset %q is missing", name)
		}
		expectedHash, expectedSize, err := fileDigest(expectedPath)
		if err != nil {
			return err
		}
		actualHash, actualSize, err := fileDigest(actualPath)
		if err != nil {
			return err
		}
		if expectedHash != actualHash || expectedSize != actualSize {
			return fmt.Errorf("release asset %q differs from expected content", name)
		}
	}
	return nil
}

func regularFiles(root string) (map[string]string, error) {
	result := make(map[string]string)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, fmt.Errorf("unexpected directory %q in release assets", entry.Name())
		}
		if previous := result[entry.Name()]; previous != "" {
			return nil, fmt.Errorf("duplicate release asset %q", entry.Name())
		}
		result[entry.Name()] = filepath.Join(root, entry.Name())
	}
	return result, nil
}

// ValidateChecksums verifies SHA256SUMS against the adjacent assets.
func ValidateChecksums(directory string) error {
	file, err := os.Open(filepath.Join(directory, "SHA256SUMS"))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		digest, name, ok := strings.Cut(line, "  ")
		if !ok || len(digest) != sha256.Size*2 || filepath.Base(name) != name || name == "" {
			return fmt.Errorf("invalid checksum line %q", line)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("duplicate checksum for %q", name)
		}
		seen[name] = struct{}{}
		actual, _, err := fileDigest(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if actual != digest {
			return fmt.Errorf("checksum mismatch for %q", name)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			return fmt.Errorf("unexpected directory %q in release assets", name)
		}
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip") {
			if _, ok := seen[name]; !ok {
				return fmt.Errorf("release artifact %q is absent from SHA256SUMS", name)
			}
			continue
		}
		if name != "manifest.json" && name != "SHA256SUMS" {
			return fmt.Errorf("unexpected release asset %q", name)
		}
	}
	return nil
}

func fileDigest(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func marshalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func copyFile(source, destination string) (resultErr error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, output.Close()) }()
	_, err = io.Copy(output, input)
	return err
}

// ExpectedAssetNames returns the complete sorted public release asset set.
func ExpectedAssetNames(tag string) ([]string, error) {
	result := make([]string, 0, len(ReleaseMatrix().Include)+2)
	for _, entry := range ReleaseMatrix().Include {
		name, err := ArtifactName(tag, entry.GOOS, entry.GOARCH, entry.Variant)
		if err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	result = append(result, "manifest.json", "SHA256SUMS")
	sort.Strings(result)
	return result, nil
}

// WriteReleaseNotes writes concise generated notes tied to the manifest.
func WriteReleaseNotes(path string, manifest Manifest) error {
	content := fmt.Sprintf("Veksel %s standalone release\n\nSource commit: `%s`\nBuilt at: `%s`\nGo toolchain: `%s`\nWorkflow run: `%s`\n\nThis release contains %d directly compiled archives across four protocol feature sets. Verify downloads with `SHA256SUMS`; `manifest.json` records the platform, feature set, binary digest, archive digest, and build provenance for every artifact.\n",
		manifest.Tag, manifest.Commit, manifest.BuiltAt, manifest.GoVersion, manifest.WorkflowRunID, len(manifest.Artifacts))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write release notes: %w", err)
	}
	return nil
}

// NativeTarget reports whether a matrix entry can run on this host.
func NativeTarget(goos, goarch string) bool { return goos == runtime.GOOS && goarch == runtime.GOARCH }
