package rules

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/category"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

type Engine struct {
	repository *Repository
	space      service.FolderSpace
	ctx        context.Context
	cancel     context.CancelFunc
	lifecycle  sync.Mutex
	mu         sync.Mutex
	workers    map[string]context.CancelFunc
	wg         sync.WaitGroup
	closed     bool
}

func NewEngine(ctx context.Context, backend store.Store, space service.FolderSpace) (*Engine, error) {
	if space == nil {
		return nil, errors.New("automation engine requires FolderSpace")
	}
	repository, err := NewRepository(ctx, backend)
	if err != nil {
		return nil, err
	}
	workerContext, cancel := context.WithCancel(ctx)
	engine := &Engine{repository: repository, space: space, ctx: workerContext, cancel: cancel, workers: make(map[string]context.CancelFunc)}
	if err := engine.resumeRuns(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("resume automation runs: %w", err)
	}
	return engine, nil
}

func (e *Engine) Close() {
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		e.cancel()
	}
	e.mu.Unlock()
	e.wg.Wait()
}

func (e *Engine) Document(ctx context.Context, access service.AccessContext) (Document, error) {
	if err := e.authorizeOwner(ctx, access); err != nil {
		return Document{}, err
	}
	return e.repository.Load(ctx, access.Subject.ID)
}

func (e *Engine) authorizeOwner(ctx context.Context, access service.AccessContext) error {
	if err := validateOwnerAccess(access); err != nil {
		return err
	}
	if access.Actor != access.Subject {
		_, err := e.space.AccountUsage(ctx, access)
		return err
	}
	return nil
}

func (e *Engine) CreateRule(ctx context.Context, access service.AccessContext, expectedRevision string, rule Rule) (Document, error) {
	document, err := e.Document(ctx, access)
	if err != nil {
		return Document{}, err
	}
	if rule.ID == "" {
		rule.ID, err = newID("rule_")
		if err != nil {
			return Document{}, err
		}
	}
	if slices.ContainsFunc(document.Rules, func(existing Rule) bool { return existing.ID == rule.ID }) {
		return Document{}, fmt.Errorf("%w: rule already exists", store.ErrExists)
	}
	document.Rules = append(document.Rules, rule)
	return e.replace(ctx, access, expectedRevision, document)
}

func (e *Engine) UpdateRule(ctx context.Context, access service.AccessContext, expectedRevision, id string, rule Rule) (Document, error) {
	document, err := e.Document(ctx, access)
	if err != nil {
		return Document{}, err
	}
	index := slices.IndexFunc(document.Rules, func(existing Rule) bool { return existing.ID == id })
	if index < 0 {
		return Document{}, store.ErrNotFound
	}
	rule.ID, rule.CreatedAt = id, document.Rules[index].CreatedAt
	document.Rules[index] = rule
	return e.replace(ctx, access, expectedRevision, document)
}

func (e *Engine) DeleteRule(ctx context.Context, access service.AccessContext, expectedRevision, id string) (Document, error) {
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	document, err := e.Document(ctx, access)
	if err != nil {
		return Document{}, err
	}
	index := slices.IndexFunc(document.Rules, func(rule Rule) bool { return rule.ID == id })
	if index < 0 {
		return Document{}, store.ErrNotFound
	}
	runs, err := e.repository.ListRuns(ctx, access.Subject.ID)
	if err != nil {
		return Document{}, err
	}
	if slices.ContainsFunc(runs, func(run Run) bool {
		return run.RuleID == id && (run.Status == RunQueued || run.Status == RunRunning || run.Status == RunCancelling)
	}) {
		return Document{}, fmt.Errorf("%w: cancel the active run before deleting this rule", store.ErrPreconditionFailed)
	}
	document.Rules = slices.Delete(document.Rules, index, index+1)
	return e.replace(ctx, access, expectedRevision, document)
}

func (e *Engine) Reorder(ctx context.Context, access service.AccessContext, expectedRevision string, ids []string) (Document, error) {
	document, err := e.Document(ctx, access)
	if err != nil {
		return Document{}, err
	}
	if len(ids) != len(document.Rules) {
		return Document{}, errors.New("rule IDs must contain every rule exactly once")
	}
	byID := make(map[string]Rule, len(document.Rules))
	for _, rule := range document.Rules {
		byID[rule.ID] = rule
	}
	ordered := make([]Rule, 0, len(ids))
	for _, id := range ids {
		rule, found := byID[id]
		if !found {
			return Document{}, fmt.Errorf("unknown or duplicate rule %q", id)
		}
		delete(byID, id)
		ordered = append(ordered, rule)
	}
	document.Rules = ordered
	return e.replace(ctx, access, expectedRevision, document)
}

func (e *Engine) replace(ctx context.Context, access service.AccessContext, expectedRevision string, document Document) (Document, error) {
	if expectedRevision == "" || document.Revision != expectedRevision {
		return Document{}, ErrRevisionConflict
	}
	for _, rule := range document.Rules {
		if err := e.validateRuleFolders(ctx, access, rule); err != nil {
			return Document{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}
	return e.repository.Replace(ctx, access.Subject.ID, expectedRevision, document)
}

func (e *Engine) validateRuleFolders(ctx context.Context, access service.AccessContext, rule Rule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	sourceTypes := make(map[model.FolderType]struct{}, len(rule.FolderTypes)+len(rule.SourceFolderIDs))
	for _, kind := range rule.FolderTypes {
		sourceTypes[kind] = struct{}{}
	}
	for _, id := range append(slices.Clone(rule.SourceFolderIDs), destinationIDs(rule.Actions)...) {
		folder, err := e.space.GetFolder(ctx, access, id)
		if err != nil {
			return fmt.Errorf("folder %q is unavailable: %w", id, err)
		}
		if !folder.TrashedAt.IsZero() {
			return fmt.Errorf("folder %q is in trash", id)
		}
		if slices.Contains(rule.SourceFolderIDs, id) {
			sourceTypes[folder.Type] = struct{}{}
		}
	}
	for _, action := range rule.Actions {
		if action.Type != ActionMove && action.Type != ActionCopy {
			continue
		}
		destination, err := e.space.GetFolder(ctx, access, action.DestinationFolderID)
		if err != nil {
			return err
		}
		if len(sourceTypes) == 0 {
			return errors.New("move and copy rules must select source folders or folder types")
		}
		for sourceType := range sourceTypes {
			if sourceType != destination.Type {
				return fmt.Errorf("destination %q type %s differs from source type %s", destination.Path, destination.Type, sourceType)
			}
		}
	}
	return nil
}

func destinationIDs(actions []Action) []string {
	var result []string
	for _, action := range actions {
		if (action.Type == ActionMove || action.Type == ActionCopy) && !slices.Contains(result, action.DestinationFolderID) {
			result = append(result, action.DestinationFolderID)
		}
	}
	return result
}

func validateOwnerAccess(access service.AccessContext) error {
	if err := access.Validate(); err != nil {
		return err
	}
	if access.Subject.Kind != model.PrincipalUser {
		return errors.New("automation rules require a user account subject")
	}
	if access.Actor.ID != access.Subject.ID && access.Mode != authz.ActingDelegation && access.Mode != authz.ActingImpersonation {
		return service.ErrForbidden
	}
	return nil
}

// Apply evaluates the owner's complete ordered ruleset after one successful
// item creation. Action failures are retained as evidence and never turn the
// already durable ingestion into a retryable protocol error.
func (e *Engine) Apply(ctx context.Context, access service.AccessContext, item model.Item) model.Item {
	folder, err := e.space.GetFolder(ctx, access, item.FolderID)
	if err != nil {
		return item
	}
	document, err := e.repository.Load(ctx, folder.UserID)
	if err != nil {
		return item
	}
	ownerAccess := service.UserAccess(folder.UserID, "automation")
	ownerAccess.Correlation = access.Correlation
	for _, rule := range document.Rules {
		if !rule.Enabled {
			continue
		}
		currentFolder, folderErr := e.space.GetFolder(ctx, ownerAccess, item.FolderID)
		if folderErr != nil {
			break
		}
		result := Match(rule, currentFolder, item)
		if !result.Matched {
			continue
		}
		item, _ = e.executeRule(ctx, ownerAccess, folder.UserID, rule, currentFolder, item, false)
		// Recoverable trash removes the item from the active rule stream. It is
		// terminal even when the rule's ordinary stop switch is off: later rules
		// must never mutate an item after it has left its active folder.
		if rule.Stop || !item.TrashedAt.IsZero() {
			break
		}
	}
	return item
}

func (e *Engine) executeRule(ctx context.Context, access service.AccessContext, ownerID string, rule Rule, folder model.Folder, item model.Item, dryRun bool) (model.Item, Execution) {
	started := time.Now().UTC()
	executionID, err := newID("exec_")
	if err != nil {
		executionID = fmt.Sprintf("exec_unavailable_%d", started.UnixNano())
	}
	execution := Execution{ID: executionID, OwnerID: ownerID, RuleID: rule.ID, RuleName: rule.Name, ItemID: item.ID, SourceFolderID: folder.ID, FinalFolderID: item.FolderID, Matched: true, Succeeded: true, StartedAt: started}
	current := item
	for _, action := range rule.Actions {
		execution.Actions = append(execution.Actions, ActionEvidence{Type: action.Type, DestinationFolderID: action.DestinationFolderID, Succeeded: true})
	}
	if !dryRun {
		actionIndex := 0
		atomic := false
		_, atomic = e.space.(service.FolderSpaceBatcher)
		actionErr := service.Batch(ctx, e.space, func(batchCtx context.Context) error {
			for index, action := range rule.Actions {
				actionIndex = index
				var executeErr error
				current, executeErr = e.executeAction(batchCtx, access, current, rule.ID, action)
				if executeErr != nil {
					return executeErr
				}
			}
			return nil
		})
		if actionErr != nil {
			execution.Succeeded, execution.Error = false, boundedError(actionErr)
			execution.Actions[actionIndex].Succeeded = false
			execution.Actions[actionIndex].Error = execution.Error
			if atomic {
				for index := range actionIndex {
					execution.Actions[index].Succeeded = false
					execution.Actions[index].RolledBack = true
				}
			}
			if refreshed, refreshErr := e.space.GetItem(context.WithoutCancel(ctx), access, item.ID); refreshErr == nil {
				current = refreshed
			}
		}
	}
	execution.FinalFolderID, execution.FinalTrashed, execution.FinishedAt = current.FolderID, !current.TrashedAt.IsZero(), time.Now().UTC()
	_ = e.repository.SaveExecution(context.WithoutCancel(ctx), execution)
	return current, execution
}

func (e *Engine) executeAction(ctx context.Context, access service.AccessContext, item model.Item, ruleID string, action Action) (model.Item, error) {
	switch action.Type {
	case ActionMove:
		return e.space.MoveItem(ctx, access, item.ID, action.DestinationFolderID, item.Name)
	case ActionCopy:
		externalIDs := cloneHeaders(item.ExternalIDs)
		_, err := service.CreateItemIdempotent(ctx, e.space, access, action.DestinationFolderID, "automation-copy-"+ruleID, item.ID, service.ItemInput{
			Name: item.Name, Data: item.Data, Headers: cloneHeaders(item.Headers), ExternalIDs: externalIDs,
			Flags: slices.Clone(item.Flags), InternalDate: item.InternalDate,
		})
		if err != nil {
			return item, err
		}
		return item, nil
	case ActionAddFlag, ActionRemoveFlag:
		flags := slices.Clone(item.Flags)
		if action.Type == ActionAddFlag && !slices.Contains(flags, action.Value) {
			flags = append(flags, action.Value)
		}
		if action.Type == ActionRemoveFlag {
			flags = slices.DeleteFunc(flags, func(flag string) bool { return flag == action.Value })
		}
		return e.space.SetFlags(ctx, access, item.ID, flags)
	case ActionAddTag, ActionRemoveTag:
		headers := cloneHeaders(item.Headers)
		tags := splitTags(headers[tagHeader])
		if action.Type == ActionAddTag && !slices.Contains(tags, action.Value) {
			tags = append(tags, action.Value)
			sort.Strings(tags)
		}
		if action.Type == ActionRemoveTag {
			tags = slices.DeleteFunc(tags, func(tag string) bool { return tag == action.Value })
		}
		if len(tags) == 0 {
			delete(headers, tagHeader)
		} else {
			headers[tagHeader] = strings.Join(tags, ", ")
		}
		return e.space.UpdateItem(ctx, access, item.ID, item.Data, headers)
	case ActionAddCategory, ActionRemoveCategory:
		folder, err := e.space.GetFolder(ctx, access, item.FolderID)
		if err != nil {
			return item, err
		}
		change, err := category.Apply(folder.Type, item, action.Value, action.Type == ActionAddCategory)
		if err != nil || !change.Changed {
			return item, err
		}
		if folder.Type == model.FolderTypeMail {
			return e.space.SetFlags(ctx, access, item.ID, change.Flags)
		}
		return e.space.UpdateItem(ctx, access, item.ID, change.Data, item.Headers)
	case ActionTrash:
		recovery, ok := e.space.(service.RecoverableFolderSpace)
		if !ok {
			return item, errors.New("recoverable item trash is unavailable")
		}
		return recovery.TrashItem(ctx, access, item.ID)
	default:
		return item, fmt.Errorf("unsupported action %q", action.Type)
	}
}

func cloneHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers)+1)
	for key, value := range headers {
		result[key] = value
	}
	return result
}

func boundedError(err error) string {
	value := strings.Map(func(character rune) rune {
		if character < 0x20 && character != '\t' {
			return -1
		}
		return character
	}, err.Error())
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}

func (e *Engine) Preview(ctx context.Context, access service.AccessContext, ruleID string, limit int) (Preview, error) {
	document, err := e.Document(ctx, access)
	if err != nil {
		return Preview{}, err
	}
	rule, err := findRule(document, ruleID)
	if err != nil {
		return Preview{}, err
	}
	if limit < 1 || limit > MaxPreviewItems {
		limit = MaxPreviewItems
	}
	preview := Preview{RuleID: ruleID, Items: []PreviewItem{}}
	folders, err := e.ruleFolders(ctx, access, rule)
	if err != nil {
		return Preview{}, err
	}
	pager, ok := e.space.(service.FolderItemPager)
	if !ok {
		return Preview{}, errors.New("bounded item paging is unavailable")
	}
	for _, folder := range folders {
		beforeUID := uint32(0)
		for preview.Examined < MaxPreviewExamined {
			page, listErr := pager.ListItemPage(ctx, access, folder.ID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: 100, IncludeData: true})
			if listErr != nil {
				return Preview{}, listErr
			}
			for _, item := range page.Items {
				if preview.Examined >= MaxPreviewExamined {
					preview.Truncated = true
					break
				}
				preview.Examined++
				if Match(rule, folder, item).Matched {
					preview.Matched++
					if len(preview.Items) < limit {
						preview.Items = append(preview.Items, PreviewItem{ItemID: item.ID, FolderID: folder.ID, Name: item.Name, Date: item.InternalDate})
					} else {
						preview.Truncated = true
					}
				}
			}
			if page.NextBeforeUID == 0 || len(page.Items) == 0 || preview.Examined >= MaxPreviewExamined {
				break
			}
			beforeUID = page.NextBeforeUID
		}
		if preview.Examined >= MaxPreviewExamined {
			break
		}
	}
	return preview, nil
}

func (e *Engine) StartRun(ctx context.Context, access service.AccessContext, ruleID string, dryRun bool) (Run, error) {
	e.lifecycle.Lock()
	defer e.lifecycle.Unlock()
	document, err := e.Document(ctx, access)
	if err != nil {
		return Run{}, err
	}
	rule, err := findRule(document, ruleID)
	if err != nil {
		return Run{}, err
	}
	id, err := newID("run_")
	if err != nil {
		return Run{}, err
	}
	now := time.Now().UTC()
	runs, err := e.repository.ListRuns(ctx, access.Subject.ID)
	if err != nil {
		return Run{}, err
	}
	if slices.ContainsFunc(runs, func(existing Run) bool {
		return existing.RuleID == ruleID && (existing.Status == RunQueued || existing.Status == RunRunning || existing.Status == RunCancelling)
	}) {
		return Run{}, fmt.Errorf("%w: this rule already has an active run", store.ErrExists)
	}
	run := Run{ID: id, OwnerID: access.Subject.ID, RuleID: rule.ID, RuleName: rule.Name, Status: RunQueued, DryRun: dryRun, CreatedAt: now, UpdatedAt: now, Access: AccessSnapshot{ActorID: access.Actor.ID, SubjectID: access.Subject.ID, Mode: string(access.Mode)}, RuleSnapshot: rule}
	if err := e.repository.SaveRun(ctx, run); err != nil {
		return Run{}, err
	}
	e.startWorker(run)
	return run, nil
}

func (e *Engine) CancelRun(ctx context.Context, access service.AccessContext, id string) (Run, error) {
	if err := e.authorizeOwner(ctx, access); err != nil {
		return Run{}, err
	}
	run, err := e.repository.GetRun(ctx, access.Subject.ID, id)
	if err != nil {
		return Run{}, err
	}
	if run.Status != RunQueued && run.Status != RunRunning && run.Status != RunCancelling {
		return run, nil
	}
	run.CancelRequested, run.Status, run.UpdatedAt = true, RunCancelling, time.Now().UTC()
	if err := e.repository.SaveRun(ctx, run); err != nil {
		return Run{}, err
	}
	e.mu.Lock()
	cancel := e.workers[id]
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return run, nil
}

func (e *Engine) Runs(ctx context.Context, access service.AccessContext) ([]Run, error) {
	if err := e.authorizeOwner(ctx, access); err != nil {
		return nil, err
	}
	return e.repository.ListRuns(ctx, access.Subject.ID)
}

func (e *Engine) Evidence(ctx context.Context, access service.AccessContext, ruleID string, limit int) ([]Execution, error) {
	if err := e.authorizeOwner(ctx, access); err != nil {
		return nil, err
	}
	return e.repository.ListEvidence(ctx, access.Subject.ID, ruleID, limit)
}

func (e *Engine) resumeRuns(ctx context.Context) error {
	runs, err := e.repository.ActiveRuns(ctx)
	if err != nil {
		return err
	}
	for _, run := range runs {
		if run.CancelRequested || run.Status == RunCancelling {
			run.Status, run.FinishedAt, run.UpdatedAt = RunCancelled, time.Now().UTC(), time.Now().UTC()
			if err := e.repository.SaveRun(ctx, run); err != nil {
				return err
			}
			continue
		}
		e.startWorker(run)
	}
	return nil
}

func (e *Engine) startWorker(run Run) {
	workerContext, cancel := context.WithCancel(e.ctx)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		cancel()
		return
	}
	if _, exists := e.workers[run.ID]; exists {
		e.mu.Unlock()
		cancel()
		return
	}
	e.workers[run.ID] = cancel
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.workers, run.ID)
			e.mu.Unlock()
			cancel()
		}()
		e.run(workerContext, run)
	}()
}

func (e *Engine) run(ctx context.Context, run Run) {
	now := time.Now().UTC()
	if run.StartedAt.IsZero() {
		run.StartedAt = now
	}
	run.Status, run.UpdatedAt = RunRunning, now
	if err := e.repository.SaveRun(context.WithoutCancel(ctx), run); err != nil {
		return
	}
	access := service.AccessContext{Actor: model.PrincipalRef{Kind: model.PrincipalUser, ID: run.Access.ActorID}, Subject: model.PrincipalRef{Kind: model.PrincipalUser, ID: run.Access.SubjectID}, Mode: authz.ActingMode(run.Access.Mode), Protocol: "automation"}
	rule := run.RuleSnapshot
	if rule.ID == "" {
		document, err := e.repository.Load(ctx, run.OwnerID)
		if err != nil {
			e.failRun(ctx, &run, err)
			return
		}
		rule, err = findRule(document, run.RuleID)
		if err != nil {
			e.failRun(ctx, &run, err)
			return
		}
		run.RuleSnapshot = rule
	}
	folders := make([]model.Folder, 0, len(run.FolderIDs))
	if len(run.FolderIDs) == 0 {
		var err error
		folders, err = e.ruleFolders(ctx, access, rule)
		if err != nil {
			e.failRun(ctx, &run, err)
			return
		}
		for _, folder := range folders {
			run.FolderIDs = append(run.FolderIDs, folder.ID)
		}
	} else {
		for _, folderID := range run.FolderIDs {
			folder, err := e.space.GetFolder(ctx, access, folderID)
			if err != nil {
				e.failRun(ctx, &run, fmt.Errorf("resume source folder %q: %w", folderID, err))
				return
			}
			folders = append(folders, folder)
		}
	}
	run.FoldersTotal = len(folders)
	run.ItemsEstimated = 0
	for _, folder := range folders {
		run.ItemsEstimated += folder.ItemCount
	}
	if err := e.repository.SaveRun(context.WithoutCancel(ctx), run); err != nil {
		return
	}
	pager, ok := e.space.(service.FolderItemPager)
	if !ok {
		e.failRun(ctx, &run, errors.New("bounded item paging is unavailable"))
		return
	}
	for folderIndex := run.CheckpointFolder; folderIndex < len(folders); folderIndex++ {
		folder := folders[folderIndex]
		beforeUID := uint32(0)
		if folderIndex == run.CheckpointFolder {
			beforeUID = run.CheckpointBeforeUID
		}
		for {
			if ctx.Err() != nil || e.cancelRequested(ctx, run) {
				e.stopRun(ctx, &run)
				return
			}
			page, pageErr := pager.ListItemPage(ctx, access, folder.ID, service.ItemPageQuery{BeforeUID: beforeUID, Limit: 100, IncludeData: true})
			if pageErr != nil {
				if ctx.Err() != nil {
					e.stopRun(ctx, &run)
					return
				}
				run.ItemsFailed++
				run.LastError = boundedError(pageErr)
				break
			}
			for _, item := range page.Items {
				run.ItemsExamined++
				if Match(rule, folder, item).Matched {
					run.ItemsMatched++
					_, execution := e.executeRule(ctx, access, run.OwnerID, rule, folder, item, run.DryRun)
					if execution.Succeeded {
						run.ItemsSucceeded++
					} else {
						run.ItemsFailed++
						run.LastError = execution.Error
					}
				}
			}
			if page.NextBeforeUID == 0 || len(page.Items) == 0 {
				break
			}
			beforeUID = page.NextBeforeUID
			run.CheckpointFolder, run.CheckpointBeforeUID, run.UpdatedAt = folderIndex, page.NextBeforeUID, time.Now().UTC()
			if err := e.repository.SaveRun(context.WithoutCancel(ctx), run); err != nil {
				return
			}
		}
		run.FoldersDone, run.CheckpointFolder, run.CheckpointBeforeUID = folderIndex+1, folderIndex+1, 0
		if err := e.repository.SaveRun(context.WithoutCancel(ctx), run); err != nil {
			return
		}
	}
	run.Status = RunCompleted
	if run.ItemsFailed > 0 {
		run.Status = RunCompletedWithErrors
	}
	run.FinishedAt, run.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	_ = e.repository.SaveRun(context.WithoutCancel(ctx), run)
}

func (e *Engine) cancelRequested(ctx context.Context, run Run) bool {
	stored, err := e.repository.GetRun(context.WithoutCancel(ctx), run.OwnerID, run.ID)
	return err == nil && stored.CancelRequested
}

func (e *Engine) stopRun(ctx context.Context, run *Run) {
	stored, err := e.repository.GetRun(context.WithoutCancel(ctx), run.OwnerID, run.ID)
	if err == nil && stored.CancelRequested {
		run.CancelRequested = true
		e.cancelledRun(ctx, run)
		return
	}
	run.Status, run.UpdatedAt = RunRunning, time.Now().UTC()
	_ = e.repository.SaveRun(context.WithoutCancel(ctx), *run)
}

func (e *Engine) cancelledRun(ctx context.Context, run *Run) {
	run.Status, run.FinishedAt, run.UpdatedAt = RunCancelled, time.Now().UTC(), time.Now().UTC()
	_ = e.repository.SaveRun(context.WithoutCancel(ctx), *run)
}

func (e *Engine) failRun(ctx context.Context, run *Run, err error) {
	run.Status, run.LastError, run.FinishedAt, run.UpdatedAt = RunFailed, boundedError(err), time.Now().UTC(), time.Now().UTC()
	_ = e.repository.SaveRun(context.WithoutCancel(ctx), *run)
}

func (e *Engine) ruleFolders(ctx context.Context, access service.AccessContext, rule Rule) ([]model.Folder, error) {
	folders, err := e.space.ListFolders(ctx, access, service.FolderQuery{})
	if err != nil {
		return nil, err
	}
	result := folders[:0]
	for _, folder := range folders {
		if len(rule.SourceFolderIDs) > 0 && !slices.Contains(rule.SourceFolderIDs, folder.ID) {
			continue
		}
		if len(rule.FolderTypes) > 0 && !slices.Contains(rule.FolderTypes, folder.Type) {
			continue
		}
		result = append(result, folder)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func findRule(document Document, id string) (Rule, error) {
	for _, rule := range document.Rules {
		if rule.ID == id {
			return rule, nil
		}
	}
	return Rule{}, store.ErrNotFound
}
