package app

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/lkarlslund/veksel/pkg/config"
	logpkg "github.com/lkarlslund/veksel/pkg/log"
)

type loggingResponse struct {
	Revision     string              `json:"revision"`
	Directory    string              `json:"directory"`
	FilePattern  string              `json:"file_pattern"`
	Format       string              `json:"format"`
	ConsoleLevel string              `json:"console_level"`
	FileLevel    string              `json:"file_level"`
	Modules      []logpkg.ModuleInfo `json:"modules"`
}

func (h *Handler) apiAdminLogging(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	if r.Method == http.MethodGet {
		jsonResponse(w, http.StatusOK, h.loggingResponse())
		return
	}
	var request struct {
		Revision string            `json:"revision"`
		Levels   map[string]string `json:"levels"`
	}
	if err := decodeJSON(r, &request); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(request.Levels) == 0 {
		jsonError(w, http.StatusBadRequest, "at least one module level is required")
		return
	}
	current := h.configService.Current()
	levels := make(map[string]string, len(current.Config.LogModuleLevels)+len(request.Levels))
	for module, level := range current.Config.LogModuleLevels {
		levels[module] = level
	}
	for module, level := range request.Levels {
		levels[module] = level
	}
	if err := logpkg.ValidateModuleLevels(levels); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	after, _, err := h.configService.PatchWithPlan(request.Revision, map[string]any{"log_module_levels": levels}, config.MutationMetadata{Actor: currentActor(r).ID, Source: "logging-api"})
	if errors.Is(err, config.ErrRevisionConflict) {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.applyManagedConfiguration(after, map[string]any{"log_module_levels": levels})
	h.audit.Log(currentActor(r).ID, "logging.levels.update", "modules", map[string]string{"count": strconv.Itoa(len(request.Levels))})
	jsonResponse(w, http.StatusOK, h.loggingResponse())
}

func (h *Handler) apiAdminLogEntries(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if h.configService == nil {
		jsonError(w, http.StatusServiceUnavailable, "managed configuration is unavailable")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "limit must be a number")
			return
		}
		limit = parsed
	}
	module := r.URL.Query().Get("module")
	if module != "" {
		if err := logpkg.ValidateModuleLevels(map[string]string{module: "info"}); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	page, err := logpkg.QueryManagedLogs(h.configService.Current().Config.LogDir, logpkg.LogQuery{
		Cursor:   r.URL.Query().Get("cursor"),
		After:    r.URL.Query().Get("after"),
		Limit:    limit,
		Level:    r.URL.Query().Get("level"),
		MinLevel: r.URL.Query().Get("min_level"),
		Module:   module,
		Text:     r.URL.Query().Get("q"),
	})
	if errors.Is(err, logpkg.ErrLogCursor) || errors.Is(err, logpkg.ErrLogQuery) {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "read managed logs: "+err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, page)
}

func (h *Handler) loggingResponse() loggingResponse {
	snapshot := h.configService.Current()
	return loggingResponse{
		Revision: snapshot.Revision, Directory: snapshot.Config.LogDir,
		FilePattern: "veksel-YYYY-MM-DD.log", Format: snapshot.Config.LogFormat,
		ConsoleLevel: snapshot.Config.LogConsoleLevel, FileLevel: snapshot.Config.LogFileLevel,
		Modules: logpkg.Modules(),
	}
}
