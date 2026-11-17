package app

import (
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

type responseByteCounter struct {
	http.ResponseWriter
	written int64
}

func (w *responseByteCounter) Write(payload []byte) (int, error) {
	refreshExportWriteDeadline(w.ResponseWriter)
	n, err := w.ResponseWriter.Write(payload)
	w.written += int64(n)
	return n, err
}

func refreshExportWriteDeadline(w http.ResponseWriter) {
	// Large authenticated exports legitimately exceed the server's ordinary
	// request write timeout. Refresh a bounded idle deadline on each streamed
	// chunk so a healthy download can continue without allowing a stalled
	// client to retain the connection indefinitely.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))
}

func (h *Handler) apiWorkspaceFolderExport(w http.ResponseWriter, r *http.Request) {
	folderID := r.PathValue("id")
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	folder, err := h.folderSpace.GetFolder(r.Context(), access, folderID)
	if err != nil {
		apiError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": folder.Name + ".zip"}); disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	refreshExportWriteDeadline(w)

	counter := &responseByteCounter{ResponseWriter: w}
	report, err := service.ExportFolder(r.Context(), h.folderSpace, access, folderID, counter)
	if err != nil {
		details := map[string]string{"subject_id": currentSubject(r).ID, "result": "failed", "error": err.Error()}
		h.audit.Log(currentActor(r).ID, "folder.export", folderID, details)
		if counter.written == 0 {
			w.Header().Del("Content-Disposition")
			w.Header().Set("Content-Type", "application/json")
			apiError(w, err)
		}
		return
	}
	h.audit.Log(currentActor(r).ID, "folder.export", folderID, map[string]string{
		"subject_id": currentSubject(r).ID,
		"result":     "succeeded",
		"items":      strconv.FormatInt(report.Items, 10),
		"bytes":      strconv.FormatInt(report.Bytes, 10),
	})
	if counter.written == 0 {
		w.WriteHeader(http.StatusOK)
	}
}
