package app

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/store"
)

// maxTasksPerList bounds one task list read; task lists are personal and
// small compared with mail folders.
const maxTasksPerList = 5000

// defaultTaskListName is the list created on first use of the Tasks workspace.
const defaultTaskListName = "Tasks"

// workspaceTask is one VTODO with its item identity.
type workspaceTask struct {
	calendarcore.Task
	ID       string `json:"id"`
	FolderID string `json:"folder_id"`
}

// workspaceTaskRequest creates or edits a task. Omitted fields keep the
// stored value on update.
type workspaceTaskRequest struct {
	FolderID    string    `json:"folder_id"`
	Summary     *string   `json:"summary,omitempty"`
	Description *string   `json:"description,omitempty"`
	Due         *string   `json:"due,omitempty"`
	Start       *string   `json:"start,omitempty"`
	Priority    *int      `json:"priority,omitempty"`
	Categories  *[]string `json:"categories,omitempty"`
	RelatedTo   *string   `json:"related_to,omitempty"`
	Recurrence  *string   `json:"recurrence,omitempty"`
	ReminderAt  *string   `json:"reminder_at,omitempty"`
	Status      *string   `json:"status,omitempty"`
	Timezone    string    `json:"timezone,omitempty"`
}

func (request workspaceTaskRequest) update() calendarcore.TaskUpdate {
	return calendarcore.TaskUpdate{
		Summary: request.Summary, Description: request.Description, Due: request.Due, Start: request.Start,
		Priority: request.Priority, Categories: request.Categories, RelatedTo: request.RelatedTo,
		Recurrence: request.Recurrence, ReminderAt: request.ReminderAt, Status: request.Status, Timezone: request.Timezone,
	}
}

func (h *Handler) registerTaskRoutes(api apiRouter) {
	api.handle("GET /api/v1/workspace/tasks/lists", h.apiWorkspaceTaskLists)
	api.handle("GET /api/v1/workspace/tasks", h.apiWorkspaceTasks)
	api.handle("POST /api/v1/workspace/tasks", h.apiWorkspaceCreateTask)
	api.handle("PUT /api/v1/workspace/tasks/{id}", h.apiWorkspaceUpdateTask)
	api.handle("DELETE /api/v1/workspace/tasks/{id}", h.apiWorkspaceDeleteTask)
	api.handle("POST /api/v1/workspace/tasks/{id}/complete", h.apiWorkspaceCompleteTask)
}

func taskView(item model.Item) (workspaceTask, error) {
	task, err := calendarcore.ProjectTask(item.Data)
	if err != nil {
		return workspaceTask{}, err
	}
	return workspaceTask{Task: task, ID: item.ID, FolderID: item.FolderID}, nil
}

// apiWorkspaceTaskLists lists the readable task lists and creates the
// signed-in user's default list on first use.
func (h *Handler) apiWorkspaceTaskLists(w http.ResponseWriter, r *http.Request) {
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	folders, err := h.workspace.ListFolders(r.Context(), actor, subject, mode)
	if err != nil {
		apiError(w, err)
		return
	}
	lists := make([]workspaceFolder, 0)
	owned := false
	for _, folder := range folders {
		if folder.Type != model.FolderTypeTasks {
			continue
		}
		owned = owned || strings.EqualFold(folder.UserID, subject.ID)
		capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
		if err != nil {
			apiError(w, err)
			return
		}
		lists = append(lists, workspaceFolder{Folder: folder, Capabilities: capabilities})
	}
	if !owned && strings.EqualFold(actor.ID, subject.ID) {
		folder, err := h.workspace.CreateFolder(r.Context(), actor, subject, mode, defaultTaskListName, model.FolderTypeTasks, "")
		if err != nil && !errors.Is(err, store.ErrExists) {
			apiError(w, err)
			return
		}
		if err == nil {
			capabilities, err := h.workspaceFolderCapabilities(r.Context(), r, folder)
			if err != nil {
				apiError(w, err)
				return
			}
			lists = append([]workspaceFolder{{Folder: folder, Capabilities: capabilities}}, lists...)
			h.workspaceChanged(r, "folder.created", folder.ID, nil)
		}
	}
	jsonResponse(w, http.StatusOK, lists)
}

// tasksIn reads every task of one readable task list.
func (h *Handler) tasksIn(r *http.Request, folderID string) ([]workspaceTask, error) {
	if _, err := h.workspaceFolder(r, folderID, model.FolderTypeTasks); err != nil {
		return nil, err
	}
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	summaries, err := h.workspace.ListItems(r.Context(), actor, subject, mode, folderID)
	if err != nil {
		return nil, err
	}
	if len(summaries) > maxTasksPerList {
		summaries = summaries[:maxTasksPerList]
	}
	tasks := make([]workspaceTask, 0, len(summaries))
	for _, summary := range summaries {
		item, err := h.workspace.GetItem(r.Context(), actor, subject, mode, summary.ID)
		if err != nil {
			continue
		}
		if task, err := taskView(item); err == nil {
			tasks = append(tasks, task)
		}
	}
	return tasks, nil
}

// apiWorkspaceTasks lists the tasks of up to 50 task lists, open tasks by
// due date first (undated last), then completed tasks newest first.
func (h *Handler) apiWorkspaceTasks(w http.ResponseWriter, r *http.Request) {
	folderIDs := r.URL.Query()["folder_id"]
	if len(folderIDs) == 0 || len(folderIDs) > 50 {
		jsonError(w, http.StatusBadRequest, "between 1 and 50 folder_id values are required")
		return
	}
	tasks := make([]workspaceTask, 0)
	for _, folderID := range folderIDs {
		listed, err := h.tasksIn(r, folderID)
		if err != nil {
			apiError(w, err)
			return
		}
		tasks = append(tasks, listed...)
	}
	sortTasks(tasks)
	jsonResponse(w, http.StatusOK, tasks)
}

func sortTasks(tasks []workspaceTask) {
	sort.SliceStable(tasks, func(i, j int) bool {
		a, b := tasks[i], tasks[j]
		if a.Completed != b.Completed {
			return !a.Completed
		}
		if a.Completed {
			return a.CompletedAt > b.CompletedAt
		}
		if (a.Due == "") != (b.Due == "") {
			return a.Due != ""
		}
		if a.Due != b.Due {
			return a.Due < b.Due
		}
		return strings.ToLower(a.Summary) < strings.ToLower(b.Summary)
	})
}

func (h *Handler) apiWorkspaceCreateTask(w http.ResponseWriter, r *http.Request) {
	var request workspaceTaskRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	folder, err := h.workspaceFolder(r, request.FolderID, model.FolderTypeTasks)
	if err != nil {
		apiError(w, err)
		return
	}
	if request.RelatedTo != nil && *request.RelatedTo != "" {
		if err := h.requireParentTask(r, folder.ID, *request.RelatedTo); err != nil {
			apiError(w, err)
			return
		}
	}
	now := time.Now()
	uid := fmt.Sprintf("web-task-%d@veksel", now.UTC().UnixNano())
	data, err := calendarcore.CreateTask(request.update(), uid, now)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	item, err := h.createTaskItem(r, folder.ID, uid, data)
	if err != nil {
		apiError(w, err)
		return
	}
	view, _ := taskView(item)
	h.workspaceChanged(r, "task.created", item.ID, map[string]any{"folder_id": folder.ID})
	jsonResponse(w, http.StatusCreated, view)
}

func (h *Handler) createTaskItem(r *http.Request, folderID, uid string, data []byte) (model.Item, error) {
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	summary := ""
	if task, err := calendarcore.ProjectTask(data); err == nil {
		summary = task.Summary
	}
	itemID, err := h.workspace.CreateItem(r.Context(), actor, subject, mode, folderID, data, map[string]string{"UID": uid, "SUMMARY": summary})
	if err != nil {
		return model.Item{}, err
	}
	return h.workspace.GetItem(r.Context(), actor, subject, mode, itemID)
}

// requireParentTask accepts a parent UID only when a task in the same list
// carries it, so subtasks never dangle across lists.
func (h *Handler) requireParentTask(r *http.Request, folderID, uid string) error {
	tasks, err := h.tasksIn(r, folderID)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if task.UID == uid {
			if task.RelatedTo != "" {
				return errors.New("subtasks cannot have subtasks of their own")
			}
			return nil
		}
	}
	return errors.New("the parent task is not in this list")
}

// taskItem loads a task item the caller can read in a task list.
func (h *Handler) taskItem(r *http.Request, id string) (model.Item, error) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), id)
	if err != nil {
		return model.Item{}, err
	}
	if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeTasks); err != nil {
		return model.Item{}, err
	}
	return item, nil
}

func (h *Handler) apiWorkspaceUpdateTask(w http.ResponseWriter, r *http.Request) {
	item, err := h.taskItem(r, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	var request workspaceTaskRequest
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.RelatedTo != nil && *request.RelatedTo != "" {
		if err := h.requireParentTask(r, item.FolderID, *request.RelatedTo); err != nil {
			apiError(w, err)
			return
		}
	}
	data, err := calendarcore.UpdateTask(item.Data, request.update(), time.Now())
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	if request.FolderID != "" && request.FolderID != item.FolderID {
		if _, err := h.workspaceFolder(r, request.FolderID, model.FolderTypeTasks); err != nil {
			apiError(w, err)
			return
		}
		if item, err = h.workspace.MoveItem(r.Context(), actor, subject, mode, item.ID, request.FolderID); err != nil {
			apiError(w, err)
			return
		}
	}
	headers := map[string]string{"UID": item.Headers["UID"]}
	if task, err := calendarcore.ProjectTask(data); err == nil {
		headers["UID"], headers["SUMMARY"] = task.UID, task.Summary
	}
	if item, err = h.workspace.UpdateItem(r.Context(), actor, subject, mode, item.ID, data, headers); err != nil {
		apiError(w, err)
		return
	}
	view, _ := taskView(item)
	h.workspaceChanged(r, "task.updated", item.ID, map[string]any{"folder_id": item.FolderID})
	jsonResponse(w, http.StatusOK, view)
}

// apiWorkspaceDeleteTask moves a task and its subtasks to Trash.
func (h *Handler) apiWorkspaceDeleteTask(w http.ResponseWriter, r *http.Request) {
	item, err := h.taskItem(r, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	actor, subject, mode := currentActor(r), currentSubject(r), currentActingMode(r)
	ids := []string{item.ID}
	if task, err := calendarcore.ProjectTask(item.Data); err == nil && task.UID != "" {
		siblings, err := h.tasksIn(r, item.FolderID)
		if err != nil {
			apiError(w, err)
			return
		}
		for _, sibling := range siblings {
			if sibling.RelatedTo == task.UID {
				ids = append(ids, sibling.ID)
			}
		}
	}
	for _, id := range ids {
		if _, err := h.workspace.TrashItem(r.Context(), actor, subject, mode, id); err != nil {
			apiError(w, err)
			return
		}
	}
	h.workspaceChanged(r, "task.trashed", item.ID, map[string]any{"folder_id": item.FolderID, "item_ids": ids})
	w.WriteHeader(http.StatusNoContent)
}

// apiWorkspaceCompleteTask completes or reopens a task. Completing a
// repeating task keeps the series open at its next occurrence and records
// the finished occurrence as its own completed task.
func (h *Handler) apiWorkspaceCompleteTask(w http.ResponseWriter, r *http.Request) {
	item, err := h.taskItem(r, r.PathValue("id"))
	if err != nil {
		apiError(w, err)
		return
	}
	var request struct {
		Completed *bool `json:"completed"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	completed := request.Completed == nil || *request.Completed
	now := time.Now()
	doneUID := fmt.Sprintf("web-task-%d@veksel", now.UTC().UnixNano())
	data, done, err := calendarcore.CompleteTask(item.Data, completed, doneUID, now)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	response := map[string]any{}
	if done != nil {
		record, err := h.createTaskItem(r, item.FolderID, doneUID, done)
		if err != nil {
			apiError(w, err)
			return
		}
		view, _ := taskView(record)
		response["completed_occurrence"] = view
	}
	if item, err = h.workspace.UpdateItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), item.ID, data, item.Headers); err != nil {
		apiError(w, err)
		return
	}
	view, _ := taskView(item)
	response["task"] = view
	h.workspaceChanged(r, "task.updated", item.ID, map[string]any{"folder_id": item.FolderID})
	jsonResponse(w, http.StatusOK, response)
}
