package app

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lkarlslund/veksel/pkg/authz"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

const maxQuotaInventoryWorkers = 8

type accountUsageResponse struct {
	Usage  service.AccountUsage `json:"usage"`
	Status service.QuotaStatus  `json:"status"`
}

type adminAccountUsageEntry struct {
	AccountID   string               `json:"account_id"`
	DisplayName string               `json:"display_name"`
	Enabled     bool                 `json:"enabled"`
	Usage       service.AccountUsage `json:"usage"`
	Status      service.QuotaStatus  `json:"status"`
	Error       string               `json:"error,omitempty"`
}

type adminAccountUsagePage struct {
	Items       []adminAccountUsageEntry `json:"items"`
	Page        int                      `json:"page"`
	PageSize    int                      `json:"page_size"`
	Total       int                      `json:"total"`
	TotalPages  int                      `json:"total_pages"`
	StateCounts map[string]int           `json:"state_counts"`
	Policy      service.QuotaPolicy      `json:"policy"`
}

func (h *Handler) quotaPolicy() service.QuotaPolicy {
	policy := service.QuotaPolicy{WarningPercent: 80, CriticalPercent: 95}
	if h.cfg != nil {
		policy.WarningPercent = h.cfg.QuotaWarningPercent
		policy.CriticalPercent = h.cfg.QuotaCriticalPercent
	}
	if policy.Validate() != nil {
		return service.QuotaPolicy{WarningPercent: 80, CriticalPercent: 95}
	}
	return policy
}

func (h *Handler) apiAccountUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := h.folderSpace.AccountUsage(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, accountUsageResponse{Usage: usage, Status: h.quotaPolicy().Classify(usage)})
}

func (h *Handler) apiAdminAccountUsage(w http.ResponseWriter, r *http.Request) {
	actor := currentActor(r)
	scope, ok := h.requireAdminScope(w, r)
	if !ok {
		return
	}
	page, pageSize, err := quotaPageParameters(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if !validQuotaPressureFilter(state) {
		jsonError(w, http.StatusBadRequest, "invalid quota pressure state")
		return
	}
	sortBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort")))
	if sortBy == "" {
		sortBy = "percent"
	}
	if sortBy != "account" && sortBy != "percent" && sortBy != "bytes" && sortBy != "items" {
		jsonError(w, http.StatusBadRequest, "sort must be account, percent, bytes, or items")
		return
	}
	direction := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction")))
	if direction == "" {
		direction = "desc"
	}
	if direction != "asc" && direction != "desc" {
		jsonError(w, http.StatusBadRequest, "direction must be asc or desc")
		return
	}
	users, err := h.users.List(r.Context())
	if err != nil {
		apiError(w, err)
		return
	}
	users = h.filterUsersToScope(r.Context(), scope, users)
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	filteredUsers := users[:0]
	for _, user := range users {
		if query == "" || strings.Contains(strings.ToLower(user.ID), query) || strings.Contains(strings.ToLower(user.DisplayName), query) {
			filteredUsers = append(filteredUsers, user)
		}
	}
	policy := h.quotaPolicy()
	entries := h.loadQuotaInventory(r.Context(), actor, !scope.system, filteredUsers, policy)
	stateCounts := make(map[string]int)
	for _, entry := range entries {
		stateCounts[entry.Status.State]++
	}
	if state != "" {
		selected := entries[:0]
		for _, entry := range entries {
			if entry.Status.State == state {
				selected = append(selected, entry)
			}
		}
		entries = selected
	}
	sortQuotaEntries(entries, sortBy, direction == "asc")
	total := len(entries)
	totalPages := max(1, (total+pageSize-1)/pageSize)
	if page > totalPages {
		page = totalPages
	}
	start := min(total, (page-1)*pageSize)
	end := min(total, start+pageSize)
	jsonResponse(w, http.StatusOK, adminAccountUsagePage{
		Items: entries[start:end], Page: page, PageSize: pageSize, Total: total,
		TotalPages: totalPages, StateCounts: stateCounts, Policy: policy,
	})
}

func quotaPageParameters(r *http.Request) (int, int, error) {
	page, pageSize := 1, 25
	var err error
	if value := r.URL.Query().Get("page"); value != "" {
		page, err = strconv.Atoi(value)
		if err != nil || page < 1 {
			return 0, 0, errors.New("page must be a positive integer")
		}
	}
	if value := r.URL.Query().Get("page_size"); value != "" {
		pageSize, err = strconv.Atoi(value)
		if err != nil || pageSize < 1 || pageSize > 100 {
			return 0, 0, errors.New("page_size must be between 1 and 100")
		}
	}
	return page, pageSize, nil
}

func validQuotaPressureFilter(state string) bool {
	switch state {
	case "", service.QuotaPressureUnlimited, service.QuotaPressureNormal, service.QuotaPressureWarning,
		service.QuotaPressureCritical, service.QuotaPressureExceeded, service.QuotaPressureUnverified:
		return true
	default:
		return false
	}
}

// loadQuotaInventory reads each account's usage as an impersonating system
// administrator, or, for a domain administrator (delegated), in the
// account's own context, since the domain grant already covers the metadata.
func (h *Handler) loadQuotaInventory(ctx context.Context, actor model.PrincipalRef, delegated bool, users []model.User, policy service.QuotaPolicy) []adminAccountUsageEntry {
	entries := make([]adminAccountUsageEntry, len(users))
	workers := min(maxQuotaInventoryWorkers, len(users))
	if workers == 0 {
		return entries
	}
	jobs := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				user := users[index]
				subject := model.PrincipalRef{Kind: model.PrincipalUser, ID: user.ID}
				access := service.AccessContext{Actor: actor, Subject: subject, Mode: authz.ActingImpersonation, Protocol: "admin-quota"}
				if delegated {
					access.Actor, access.Mode = subject, authz.ActingNone
				}
				usage, err := h.folderSpace.AccountUsage(ctx, access)
				entry := adminAccountUsageEntry{AccountID: user.ID, DisplayName: user.DisplayName, Enabled: user.Enabled, Usage: usage}
				if err != nil {
					entry.Error = boundedQuotaError(err)
					entry.Usage = service.AccountUsage{AccountID: user.ID}
				}
				entry.Status = policy.Classify(entry.Usage)
				entries[index] = entry
			}
		}()
	}
	for index := range users {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	return entries
}

func boundedQuotaError(err error) string {
	message := strings.Join(strings.Fields(err.Error()), " ")
	const limit = 240
	runes := []rune(message)
	if len(runes) > limit {
		message = string(runes[:limit]) + "…"
	}
	return message
}

func sortQuotaEntries(entries []adminAccountUsageEntry, field string, ascending bool) {
	stateRank := map[string]int{
		service.QuotaPressureUnverified: 6, service.QuotaPressureExceeded: 5,
		service.QuotaPressureCritical: 4, service.QuotaPressureWarning: 3,
		service.QuotaPressureNormal: 2, service.QuotaPressureUnlimited: 1,
	}
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		comparison := 0
		switch field {
		case "account":
			comparison = cmp.Compare(left.AccountID, right.AccountID)
		case "bytes":
			comparison = cmp.Compare(left.Usage.LogicalBytes, right.Usage.LogicalBytes)
		case "items":
			comparison = cmp.Compare(left.Usage.Items, right.Usage.Items)
		default:
			comparison = cmp.Compare(stateRank[left.Status.State], stateRank[right.Status.State])
			if comparison == 0 {
				comparison = cmp.Compare(left.Status.Percent, right.Status.Percent)
			}
		}
		if comparison == 0 {
			comparison = cmp.Compare(left.AccountID, right.AccountID)
		}
		if ascending {
			return comparison < 0
		}
		return comparison > 0
	})
}
