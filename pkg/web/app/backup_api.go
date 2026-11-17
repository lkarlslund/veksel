package app

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/backup"
)

const maxBackupUploadBytes = 500 << 20

// installationSource describes this running installation for online backup.
func (h *Handler) installationSource() backup.InstallationSource {
	configPath := ""
	if h.configService != nil {
		configPath = h.configService.Path()
	}
	return backup.LiveSource(h.ts.Store(), h.ts.Backend(), h.accountManager, configPath)
}

// apiAdminDownloadBackup streams a full installation archive, or with
// ?scope=system the system-store-only archive that apiAdminRestoreBackup
// accepts on a running server.
func (h *Handler) apiAdminDownloadBackup(w http.ResponseWriter, r *http.Request) {
	// Archives carry the raw configuration with its secrets, every password
	// hash, and the owners' mailboxes, so like restore they are owner-only.
	if !h.requireOwnerAPI(w, r) {
		return
	}
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = backup.ArchiveKindInstallation
	}
	if scope != backup.ArchiveKindInstallation && scope != backup.ArchiveKindSystem {
		jsonError(w, http.StatusBadRequest, "scope must be installation or system")
		return
	}
	actor := currentActor(r).ID
	stamp := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	archive := &countingWriter{w: w}
	var err error
	if scope == backup.ArchiveKindSystem {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "veksel-system-backup-"+stamp+".tar.gz"))
		err = backup.BackupContext(r.Context(), h.ts.Store(), archive, string(h.ts.Backend()))
	} else {
		// One online installation backup at a time: a download and a
		// scheduled run share the scheduler's gate.
		err = h.backupScheduler.Exclusive(func() error {
			w.Header().Set("Content-Type", "application/x-tar")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "veksel-backup-"+stamp+".tar"))
			return backup.WriteInstallation(r.Context(), h.installationSource(), archive)
		})
		if errors.Is(err, backup.ErrBackupRunning) {
			jsonError(w, http.StatusConflict, err.Error())
			return
		}
	}
	if err != nil {
		h.audit.Log(actor, "backup.create", scope, map[string]string{"result": "failed", "error": err.Error()})
		if archive.n == 0 {
			w.Header().Del("Content-Disposition")
			jsonError(w, http.StatusInternalServerError, "backup failed: "+err.Error())
			return
		}
		// The 200 status and part of the archive are already sent. Breaking
		// the connection instead of ending the response normally makes the
		// client report a failed transfer rather than keep a truncated
		// archive that looks complete.
		panic(http.ErrAbortHandler)
	}
	h.audit.Log(actor, "backup.create", scope, map[string]string{"result": "succeeded", "format": backup.InstallationFormat, "version": strconv.Itoa(backup.InstallationFormatVersion)})
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func (h *Handler) apiAdminVerifyBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadBytes)
	source, closeSource, err := backupUpload(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer closeSource()
	actor := currentActor(r).ID
	verification, err := backup.VerifyArchive(r.Context(), source, h.installationSource().TempDir)
	if err != nil {
		h.audit.Log(actor, "backup.verify", "full", map[string]string{"result": "failed", "error": err.Error()})
		jsonError(w, http.StatusBadRequest, "backup verification failed: "+err.Error())
		return
	}
	h.audit.Log(actor, "backup.verify", "full", map[string]string{
		"result": "succeeded", "kind": verification.Kind, "version": verification.Metadata.Version,
		"verified": strconv.FormatBool(verification.Verified), "total_keys": strconv.Itoa(verification.Metadata.TotalKeys),
	})
	jsonResponse(w, http.StatusOK, verification)
}

// apiAdminRestoreBackup replaces (or with ?mode=merge, merges into) the system
// store of the running server from a ?scope=system archive. Installation
// archives need the offline restore command.
func (h *Handler) apiAdminRestoreBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireOwnerAPI(w, r) {
		return
	}
	mode, modeName := backup.Replace, "replace"
	switch r.URL.Query().Get("mode") {
	case "", "replace":
	case "merge":
		mode, modeName = backup.Merge, "merge"
	default:
		jsonError(w, http.StatusBadRequest, "mode must be replace or merge")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadBytes)
	source, closeSource, err := backupUpload(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer closeSource()
	kind, source, err := backup.DetectArchive(source)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "restore failed: "+err.Error())
		return
	}
	if kind != backup.ArchiveKindSystem {
		jsonError(w, http.StatusBadRequest, "installation archives cannot be restored into a running server; stop it and use `veksel restore`, or send a ?scope=system backup")
		return
	}
	actor := currentActor(r).ID
	meta, err := backup.Restore(h.ts.Store(), source, mode)
	if err != nil {
		h.audit.Log(actor, "backup.restore", backup.ArchiveKindSystem, map[string]string{"result": "failed", "mode": modeName, "error": err.Error()})
		jsonError(w, http.StatusBadRequest, "restore failed: "+err.Error())
		return
	}
	h.audit.Log(actor, "backup.restore", backup.ArchiveKindSystem, map[string]string{"result": "succeeded", "mode": modeName, "total_keys": strconv.Itoa(meta.TotalKeys)})
	jsonResponse(w, http.StatusOK, map[string]any{"status": "restored", "mode": modeName, "total_keys": meta.TotalKeys, "namespaces": meta.Namespaces})
}

// backupUpload returns the uploaded archive: the multipart "backup" file
// or the raw request body.
func backupUpload(r *http.Request) (io.Reader, func(), error) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return r.Body, func() {}, nil
	}
	if err := r.ParseMultipartForm(maxBackupUploadBytes); err != nil {
		return nil, nil, errors.New("backup upload is too large or invalid")
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		return nil, nil, errors.New("missing backup file")
	}
	return file, func() { _ = file.Close() }, nil
}

// ConfigureBackupScheduler installs scheduled backups and the single-flight
// gate shared with administrator downloads.
func (h *Handler) ConfigureBackupScheduler(scheduler *backup.Scheduler) {
	h.backupScheduler = scheduler
}

func (h *Handler) apiAdminBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.backupScheduler == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled backups are unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, h.backupScheduler.Status())
}

// apiAdminRunBackup starts a scheduled-style backup into the configured
// backup directory now; progress and the result appear in the schedule status.
func (h *Handler) apiAdminRunBackup(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.backupScheduler == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled backups are unavailable")
		return
	}
	actor := currentActor(r).ID
	if err := h.backupScheduler.Trigger(actor); err != nil {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	h.audit.Log(actor, "backup.run.request", "scheduled", nil)
	jsonResponse(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// apiAdminDownloadScheduledBackup serves a retained scheduled archive when
// the backup directory lies inside the data directory.
func (h *Handler) apiAdminDownloadScheduledBackup(w http.ResponseWriter, r *http.Request) {
	// Owner-only for the same reason as apiAdminDownloadBackup.
	if !h.requireOwnerAPI(w, r) {
		return
	}
	if h.backupScheduler == nil {
		jsonError(w, http.StatusServiceUnavailable, "scheduled backups are unavailable")
		return
	}
	file, archive, err := h.backupScheduler.OpenArchive(r.PathValue("name"))
	switch {
	case errors.Is(err, os.ErrPermission):
		jsonError(w, http.StatusForbidden, "archives outside the data directory cannot be downloaded here; copy them from the backup directory")
		return
	case err != nil:
		jsonError(w, http.StatusNotFound, "scheduled backup not found")
		return
	}
	defer file.Close()
	contentType := "application/x-tar"
	if archive.Encrypted {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(archive.Size, 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", archive.Name))
	h.audit.Log(currentActor(r).ID, "backup.download", "scheduled", map[string]string{"archive": archive.Name})
	_, _ = io.Copy(w, file)
}
