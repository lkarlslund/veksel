package app

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/contactport"
	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const contactImportMultipartOverhead = 1 << 20

type contactImportProjection struct {
	Format      contactport.Format    `json:"format"`
	Valid       bool                  `json:"valid"`
	Contacts    int                   `json:"contacts"`
	SampleNames []string              `json:"sample_names,omitempty"`
	Problems    []contactport.Problem `json:"problems"`
	MaxContacts int                   `json:"max_contacts"`
	MaxBytes    int                   `json:"max_bytes"`
}

type contactImportResult struct {
	FolderID string             `json:"folder_id"`
	Format   contactport.Format `json:"format"`
	Imported int                `json:"imported"`
}

func (h *Handler) apiWorkspaceContactImportPreview(w http.ResponseWriter, r *http.Request) {
	if _, err := h.workspaceFolder(r, r.URL.Query().Get("folder_id"), model.FolderTypeContacts); err != nil {
		apiError(w, err)
		return
	}
	document, err := readContactImport(w, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, projectContactImport(document))
}

func (h *Handler) apiWorkspaceContactImport(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	if _, err := h.workspaceFolder(r, folderID, model.FolderTypeContacts); err != nil {
		apiError(w, err)
		return
	}
	document, err := readContactImport(w, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !document.Valid() {
		jsonResponse(w, http.StatusUnprocessableEntity, projectContactImport(document))
		return
	}
	creator, ok := h.folderSpace.(service.FolderItemBatchCreator)
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "atomic contact import is unavailable")
		return
	}
	inputs := make([]service.ItemInput, len(document.Contacts))
	for index, card := range document.Contacts {
		inputs[index] = service.ItemInput{Data: card, Headers: map[string]string{"Content-Type": "text/vcard; charset=utf-8"}}
	}
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	items, err := creator.CreateItems(r.Context(), access, folderID, inputs)
	if err != nil {
		apiError(w, err)
		return
	}
	actor, subject := currentActor(r).ID, currentSubject(r).ID
	recipients := []string{actor}
	if subject != actor {
		recipients = append(recipients, subject)
	}
	details := map[string]string{"subject_id": subject, "format": string(document.Format), "items": strconv.Itoa(len(items))}
	h.audit.Log(actor, "contacts.import", folderID, details)
	h.events.Publish(events.Event{Type: "contacts.imported", Resource: folderID, Data: map[string]any{"folder_id": folderID, "items": len(items)}, Recipients: recipients})
	jsonResponse(w, http.StatusCreated, contactImportResult{FolderID: folderID, Format: document.Format, Imported: len(items)})
}

func (h *Handler) apiWorkspaceContactExport(w http.ResponseWriter, r *http.Request) {
	folderID := r.URL.Query().Get("folder_id")
	format := contactport.Format(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))))
	if format != contactport.FormatVCard && format != contactport.FormatCSV {
		jsonError(w, http.StatusBadRequest, "format must be vcard or csv")
		return
	}
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	folder, err := h.folderSpace.GetFolder(r.Context(), access, folderID)
	if err != nil {
		apiError(w, err)
		return
	}
	if folder.Type != model.FolderTypeContacts || !folder.TrashedAt.IsZero() {
		apiError(w, service.ErrForbidden)
		return
	}
	pager, ok := h.folderSpace.(service.FolderItemPager)
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "bounded contact export is unavailable")
		return
	}
	extension, contentType := ".vcf", "text/vcard; charset=utf-8"
	if format == contactport.FormatCSV {
		extension, contentType = ".csv", "text/csv; charset=utf-8"
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": folder.Name + extension}); disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	refreshExportWriteDeadline(w)
	counter := &responseByteCounter{ResponseWriter: w}
	exporter, err := contactport.NewExporter(counter, format)
	if err == nil {
		err = exportContacts(r, h.folderSpace, pager, access, folder, exporter)
	}
	if exporter != nil {
		if closeErr := exporter.Close(); err == nil {
			err = closeErr
		}
	}
	actor, subject := currentActor(r).ID, currentSubject(r).ID
	if err != nil {
		h.audit.Log(actor, "contacts.export", folderID, map[string]string{"subject_id": subject, "format": string(format), "result": "failed", "error": err.Error()})
		if counter.written == 0 {
			w.Header().Del("Content-Disposition")
			w.Header().Set("Content-Type", "application/json")
			apiError(w, err)
		}
		return
	}
	h.audit.Log(actor, "contacts.export", folderID, map[string]string{"subject_id": subject, "format": string(format), "result": "succeeded"})
	if counter.written == 0 {
		w.WriteHeader(http.StatusOK)
	}
}

func readContactImport(w http.ResponseWriter, r *http.Request) (contactport.Document, error) {
	r.Body = http.MaxBytesReader(w, r.Body, contactport.MaxDocumentBytes+contactImportMultipartOverhead)
	if err := r.ParseMultipartForm(contactport.MaxDocumentBytes + contactImportMultipartOverhead); err != nil {
		return contactport.Document{}, errors.New("contact upload must be bounded multipart form data")
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return contactport.Document{}, errors.New("file is required")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, contactport.MaxDocumentBytes+1))
	if err != nil {
		return contactport.Document{}, errors.New("read contact upload")
	}
	format, err := contactport.DetectFormat(r.URL.Query().Get("format"), header.Filename)
	if err != nil {
		return contactport.Document{}, err
	}
	return contactport.Parse(format, data), nil
}

func projectContactImport(document contactport.Document) contactImportProjection {
	sample := document.Names
	if len(sample) > 5 {
		sample = sample[:5]
	}
	return contactImportProjection{Format: document.Format, Valid: document.Valid(), Contacts: len(document.Contacts), SampleNames: append([]string(nil), sample...), Problems: document.Problems, MaxContacts: contactport.MaxContacts, MaxBytes: contactport.MaxDocumentBytes}
}

func exportContacts(r *http.Request, space service.FolderSpace, pager service.FolderItemPager, access service.AccessContext, folder model.Folder, exporter *contactport.Exporter) error {
	var beforeUID uint32
	for {
		if err := r.Context().Err(); err != nil {
			return err
		}
		page, err := pager.ListItemPage(r.Context(), access, folder.ID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: 200})
		if err != nil {
			return fmt.Errorf("list contact export page: %w", err)
		}
		for _, summary := range page.Items {
			item, err := space.GetItem(r.Context(), access, summary.ID)
			if err != nil {
				return fmt.Errorf("read contact export item: %w", err)
			}
			if item.FolderID != folder.ID || !item.TrashedAt.IsZero() {
				return errors.New("contact changed during export")
			}
			if err := exporter.Write(item.Data); err != nil {
				return err
			}
		}
		if page.NextBeforeUID == 0 {
			return nil
		}
		if page.NextBeforeUID == beforeUID || len(page.Items) == 0 {
			return errors.New("contact export paging did not advance")
		}
		beforeUID = page.NextBeforeUID
	}
}
