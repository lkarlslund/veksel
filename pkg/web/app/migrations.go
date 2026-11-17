package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/events"
	"github.com/lkarlslund/veksel/pkg/migration"
)

type migrationRequest struct {
	SourceType           string                         `json:"source_type"`
	DestinationID        string                         `json:"destination_id,omitempty"`
	SourceIdentity       string                         `json:"source_identity,omitempty"`
	FolderIDs            []string                       `json:"folder_ids,omitempty"`
	Connection           migration.SourceOptions        `json:"connection"`
	PersistPassword      bool                           `json:"persist_password"`
	Schedule             migration.Schedule             `json:"schedule"`
	SourceDeletionPolicy migration.SourceDeletionPolicy `json:"source_deletion_policy"`
	ConflictPolicy       migration.ConflictPolicy       `json:"conflict_policy"`
	FolderTargets        map[string]string              `json:"folder_targets,omitempty"`
}

type syncJobResponse struct {
	migration.Job
	Source migration.SourceDescriptor `json:"source"`
}

func describeSyncJob(job migration.Job) syncJobResponse {
	return syncJobResponse{Job: job, Source: migration.DescribeSource(job.SourceType)}
}

func (h *Handler) apiMigrations(w http.ResponseWriter, r *http.Request) {
	actor := currentActor(r).ID
	owner := actor
	if h.isAdmin(r.Context(), actor) && r.URL.Query().Get("all") == "true" {
		owner = ""
	}
	jobs, err := h.migrationJobs.List(r.Context(), owner)
	if err != nil {
		apiError(w, err)
		return
	}
	sources := make([]string, 0, len(h.migrationSources))
	for source := range h.migrationSources {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	descriptors := make([]migration.SourceDescriptor, 0, len(sources))
	for _, source := range sources {
		descriptors = append(descriptors, migration.DescribeSource(source))
	}
	responses := make([]syncJobResponse, 0, len(jobs))
	for _, job := range jobs {
		responses = append(responses, describeSyncJob(job))
	}
	jsonResponse(w, http.StatusOK, map[string]any{"jobs": responses, "sources": sources, "source_descriptors": descriptors})
}

func (h *Handler) apiMigration(w http.ResponseWriter, r *http.Request) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	jsonResponse(w, http.StatusOK, describeSyncJob(job))
}

func (h *Handler) apiCreateMigration(w http.ResponseWriter, r *http.Request) {
	var request migrationRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	request.SourceType = strings.ToLower(strings.TrimSpace(request.SourceType))
	if h.migrationSources[request.SourceType] == nil {
		jsonError(w, http.StatusBadRequest, "source is unavailable in this build")
		return
	}
	actor := currentActor(r).ID
	destination := currentSubject(r).ID
	if request.DestinationID != "" && request.DestinationID != destination {
		if !h.isAdmin(r.Context(), actor) {
			jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		destination = strings.ToLower(strings.TrimSpace(request.DestinationID))
	}
	if _, err := h.users.Get(r.Context(), destination); err != nil {
		jsonError(w, http.StatusBadRequest, "destination account does not exist")
		return
	}
	if len(request.FolderIDs) == 0 {
		jsonError(w, http.StatusBadRequest, "select at least one source folder")
		return
	}
	if request.Schedule == "" {
		request.Schedule = migration.ScheduleManual
	}
	if request.SourceDeletionPolicy == "" {
		request.SourceDeletionPolicy = migration.SourceDeletionRetain
	}
	if request.ConflictPolicy == "" {
		request.ConflictPolicy = migration.ConflictSourceWins
	}
	if !request.Schedule.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid sync schedule")
		return
	}
	if !request.SourceDeletionPolicy.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid source deletion policy")
		return
	}
	if !migration.DescribeSource(request.SourceType).Capabilities.SourceDeletionTracking && request.SourceDeletionPolicy != migration.SourceDeletionRetain {
		jsonError(w, http.StatusBadRequest, "source does not provide deletion tracking")
		return
	}
	if !request.ConflictPolicy.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid conflict policy")
		return
	}
	if request.Schedule.Interval() > 0 && !request.PersistPassword {
		jsonError(w, http.StatusBadRequest, "scheduled sync requires a stored password")
		return
	}
	job, err := h.migrationJobs.Create(r.Context(), migration.Job{
		OwnerID: actor, DestinationID: destination, SourceType: request.SourceType,
		SourceIdentity:       strings.TrimSpace(request.SourceIdentity),
		Connection:           migration.NewConnectionProfile(request.Connection),
		SelectedFolderIDs:    request.FolderIDs,
		SourceDeletionPolicy: request.SourceDeletionPolicy,
		ConflictPolicy:       request.ConflictPolicy,
		FolderTargets:        request.FolderTargets,
		Schedule:             request.Schedule, CredentialStored: request.PersistPassword,
	})
	if err != nil {
		apiError(w, err)
		return
	}
	if request.PersistPassword {
		if err := h.migrationJobs.SaveCredential(r.Context(), job.ID, request.Connection.Password); err != nil {
			_ = h.migrationJobs.Delete(r.Context(), job.ID)
			apiError(w, err)
			return
		}
	}
	if interval := job.Schedule.Interval(); interval > 0 {
		job.NextRunAt = time.Now().UTC().Add(interval)
		if err := h.migrationJobs.Save(r.Context(), job); err != nil {
			apiError(w, err)
			return
		}
	}
	h.audit.Log(actor, "sync.create", job.ID, map[string]string{"source": job.SourceType, "destination": destination})
	jsonResponse(w, http.StatusCreated, describeSyncJob(job))
}

func (h *Handler) apiMigrationInventory(w http.ResponseWriter, r *http.Request) {
	var request migrationRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	factory := h.migrationSources[strings.ToLower(strings.TrimSpace(request.SourceType))]
	if factory == nil {
		jsonError(w, http.StatusBadRequest, "source is unavailable in this build")
		return
	}
	source, err := factory(r.Context(), request.Connection)
	if err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("unable to connect to source: %v", err))
		return
	}
	defer func() { _ = source.Close() }()
	folders, err := migration.Inventory(r.Context(), source)
	if err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("unable to inventory source: %v", err))
		return
	}
	destination := currentSubject(r).ID
	if request.DestinationID != "" && request.DestinationID != destination {
		if !h.isAdmin(r.Context(), currentActor(r).ID) {
			jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		destination = strings.ToLower(strings.TrimSpace(request.DestinationID))
	}
	preflight, err := h.migrationRunner.PreflightFolders(r.Context(), destination, folders, request.FolderIDs, request.FolderTargets)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"source_identity": source.ID(), "source": migration.DescribeSource(request.SourceType), "folders": folders, "preflight": preflight})
}

func (h *Handler) apiMigrationPreflight(w http.ResponseWriter, r *http.Request) {
	var request struct {
		DestinationID string             `json:"destination_id,omitempty"`
		Folders       []migration.Folder `json:"folders"`
		FolderIDs     []string           `json:"folder_ids,omitempty"`
		FolderTargets map[string]string  `json:"folder_targets,omitempty"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	destination := currentSubject(r).ID
	if request.DestinationID != "" && request.DestinationID != destination {
		if !h.isAdmin(r.Context(), currentActor(r).ID) {
			jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		destination = strings.ToLower(strings.TrimSpace(request.DestinationID))
	}
	if _, err := h.users.Get(r.Context(), destination); err != nil {
		jsonError(w, http.StatusBadRequest, "destination account does not exist")
		return
	}
	preflight, err := h.migrationRunner.PreflightFolders(r.Context(), destination, request.Folders, request.FolderIDs, request.FolderTargets)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, preflight)
}

func (h *Handler) apiStartMigration(w http.ResponseWriter, r *http.Request) {
	h.apiBeginMigration(w, r, false)
}

func (h *Handler) apiCutoverMigration(w http.ResponseWriter, r *http.Request) {
	h.apiBeginMigration(w, r, true)
}

func (h *Handler) apiBeginMigration(w http.ResponseWriter, r *http.Request, cutover bool) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if job.State == migration.StateRunning {
		jsonError(w, http.StatusConflict, "sync job is already running")
		return
	}
	job, err := h.migrationJobs.PrepareRun(r.Context(), job)
	if err != nil {
		apiError(w, err)
		return
	}
	var request struct {
		Password   string                  `json:"password"`
		Connection migration.SourceOptions `json:"connection"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	factory := h.migrationSources[job.SourceType]
	if factory == nil {
		jsonError(w, http.StatusBadRequest, "source is unavailable in this build")
		return
	}
	password := request.Password
	if password == "" {
		password = request.Connection.Password
	}
	if password == "" && job.CredentialStored {
		password, err = h.migrationJobs.Credential(r.Context(), job.ID)
		if err != nil {
			jsonError(w, http.StatusConflict, "stored sync credential is unavailable")
			return
		}
	}
	options := job.Connection.SourceOptions(password)
	// Jobs created by earlier versions did not persist a connection profile.
	if options.Endpoint == "" {
		options = request.Connection
	}
	source, err := factory(r.Context(), options)
	if err != nil {
		_, _ = h.migrationJobs.RecordFatalAttempt(r.Context(), job.ID, fmt.Errorf("connect to source: %w", err), migration.FailureContext{Phase: migration.FailurePhaseConnect})
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("unable to connect to source: %v", err))
		return
	}
	job.CutoverRequested = cutover
	if cutover {
		job.CutoverState = "pending"
	}
	if err := h.migrationJobs.Save(r.Context(), job); err != nil {
		_ = source.Close()
		apiError(w, err)
		return
	}
	action := "sync.start"
	if cutover {
		action = "sync.cutover"
	}
	h.audit.Log(currentActor(r).ID, action, job.ID, map[string]string{"source": job.SourceType, "destination": job.DestinationID})
	h.publishSyncStarted(job)
	h.runSync(job, source)
	status := "starting"
	if cutover {
		status = "starting final cutover sync"
	}
	jsonResponse(w, http.StatusAccepted, map[string]string{"status": status, "id": job.ID})
}

func (h *Handler) publishSyncStarted(job migration.Job) {
	h.events.Publish(events.Event{Type: "sync.started", Resource: job.ID, Recipients: []string{job.OwnerID}})
}

func (h *Handler) syncRunEventType(ctx context.Context, jobID string, runErr error) string {
	if runErr != nil {
		return "sync.failed"
	}
	job, err := h.migrationJobs.Get(ctx, jobID)
	if err == nil && job.RunOutcome == migration.RunOutcomeCompletedWithErrors {
		return "sync.completed_with_errors"
	}
	return "sync.completed"
}

func (h *Handler) apiMigrationRuns(w http.ResponseWriter, r *http.Request) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	pageSize := 10
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 50 {
			jsonError(w, http.StatusBadRequest, "page_size must be between 1 and 50")
			return
		}
		pageSize = parsed
	}
	before := ""
	if cursor := strings.TrimSpace(r.URL.Query().Get("cursor")); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(decoded) > 256 {
			jsonError(w, http.StatusBadRequest, "invalid sync run cursor")
			return
		}
		before = string(decoded)
	}
	runs, total, nextBefore, err := h.migrationJobs.RunsPage(r.Context(), job.ID, before, pageSize)
	if err != nil {
		if before != "" && strings.Contains(err.Error(), "cursor") {
			jsonError(w, http.StatusBadRequest, "invalid sync run cursor")
			return
		}
		apiError(w, err)
		return
	}
	nextCursor := ""
	if nextBefore != "" {
		nextCursor = base64.RawURLEncoding.EncodeToString([]byte(nextBefore))
	}
	for index := range runs {
		runs[index].FolderFailures = nil
		runs[index].FolderResults = nil
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"runs": runs, "total": total, "page_size": pageSize, "next_cursor": nextCursor,
	})
}

func (h *Handler) apiMigrationRun(w http.ResponseWriter, r *http.Request) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	run, err := h.migrationJobs.Run(r.Context(), job.ID, r.PathValue("run_id"))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, run)
}

func (h *Handler) apiUpdateSyncJob(w http.ResponseWriter, r *http.Request) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var request struct {
		Schedule             migration.Schedule             `json:"schedule"`
		Password             string                         `json:"password"`
		PersistPassword      bool                           `json:"persist_password"`
		SourceDeletionPolicy migration.SourceDeletionPolicy `json:"source_deletion_policy"`
		ConflictPolicy       migration.ConflictPolicy       `json:"conflict_policy"`
		FolderTargets        map[string]string              `json:"folder_targets,omitempty"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if request.Schedule == "" {
		request.Schedule = migration.ScheduleManual
	}
	if request.SourceDeletionPolicy == "" {
		request.SourceDeletionPolicy = job.SourceDeletionPolicy
	}
	if request.ConflictPolicy == "" {
		request.ConflictPolicy = job.ConflictPolicy
	}
	if request.ConflictPolicy == "" {
		request.ConflictPolicy = migration.ConflictSourceWins
	}
	if request.SourceDeletionPolicy == "" {
		request.SourceDeletionPolicy = migration.SourceDeletionRetain
	}
	if !request.Schedule.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid sync schedule")
		return
	}
	if !request.SourceDeletionPolicy.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid source deletion policy")
		return
	}
	if !migration.DescribeSource(job.SourceType).Capabilities.SourceDeletionTracking && request.SourceDeletionPolicy != migration.SourceDeletionRetain {
		jsonError(w, http.StatusBadRequest, "source does not provide deletion tracking")
		return
	}
	if !request.ConflictPolicy.Valid() {
		jsonError(w, http.StatusBadRequest, "invalid conflict policy")
		return
	}
	if request.Schedule.Interval() > 0 && !request.PersistPassword {
		jsonError(w, http.StatusBadRequest, "scheduled sync requires a stored password")
		return
	}
	if request.PersistPassword {
		if request.Password != "" {
			if err := h.migrationJobs.SaveCredential(r.Context(), job.ID, request.Password); err != nil {
				apiError(w, err)
				return
			}
		} else if !job.CredentialStored {
			jsonError(w, http.StatusBadRequest, "password is required to enable credential storage")
			return
		}
	} else if err := h.migrationJobs.DeleteCredential(r.Context(), job.ID); err != nil {
		apiError(w, err)
		return
	}
	job.CredentialStored, job.Schedule, job.SourceDeletionPolicy = request.PersistPassword, request.Schedule, request.SourceDeletionPolicy
	job.ConflictPolicy = request.ConflictPolicy
	if request.FolderTargets != nil {
		job.FolderTargets = request.FolderTargets
		job.FolderMap = make(map[string]string)
		job.Checkpoints = make(map[string]string)
	}
	job.NextRunAt = time.Time{}
	if interval := job.Schedule.Interval(); interval > 0 {
		job.NextRunAt = time.Now().UTC().Add(interval)
	}
	if err := h.migrationJobs.Save(r.Context(), job); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "sync.update", job.ID, map[string]string{"schedule": string(job.Schedule)})
	jsonResponse(w, http.StatusOK, describeSyncJob(job))
}

func (h *Handler) apiDeleteMigration(w http.ResponseWriter, r *http.Request) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if job.State == migration.StateRunning {
		jsonError(w, http.StatusConflict, "pause the sync job before deleting it")
		return
	}
	if err := h.migrationJobs.Delete(r.Context(), job.ID); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "sync.delete", job.ID, map[string]string{"source": job.SourceType, "destination": job.DestinationID})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) apiPauseMigration(w http.ResponseWriter, r *http.Request) {
	job, ok := h.authorizedMigration(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !h.migrationRunner.Pause(job.ID) {
		jsonError(w, http.StatusConflict, "sync job is not running")
		return
	}
	h.audit.Log(currentActor(r).ID, "sync.pause", job.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) authorizedMigration(w http.ResponseWriter, r *http.Request, id string) (migration.Job, bool) {
	job, err := h.migrationJobs.Get(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "sync job not found")
		return migration.Job{}, false
	}
	actor := currentActor(r).ID
	if job.OwnerID != actor && !h.isAdmin(r.Context(), actor) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return migration.Job{}, false
	}
	return job, true
}
