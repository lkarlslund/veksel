package app

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/metrics"
	"github.com/lkarlslund/veksel/pkg/model"
)

// BuildInfo identifies the running binary and its listeners. It is served to
// API-key callers of GET /api/v1/health.
type BuildInfo struct {
	Version    string
	Commit     string
	BuildTime  string
	StoreType  string
	ListenAddr string
	IMAPPort   string
	SMTPPort   string
	StartTime  time.Time
}

// ConfigureBuildInfo installs the build and listener details of this process.
func (h *Handler) ConfigureBuildInfo(info BuildInfo) { h.build = info }

// ConfigureServerControl installs the callbacks that drain and exit the
// process: restart exits with the status the service manager restarts on,
// shutdown exits cleanly.
func (h *Handler) ConfigureServerControl(restart, shutdown func()) {
	h.restartServer, h.shutdownServer = restart, shutdown
}

func (h *Handler) apiAdminRestartServer(w http.ResponseWriter, r *http.Request) {
	h.controlServer(w, r, "server.restart", "restarting", h.restartServer)
}

func (h *Handler) apiAdminShutdownServer(w http.ResponseWriter, r *http.Request) {
	h.controlServer(w, r, "server.shutdown", "shutting_down", h.shutdownServer)
}

func (h *Handler) controlServer(w http.ResponseWriter, r *http.Request, action, status string, control func()) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	if control == nil {
		jsonError(w, http.StatusServiceUnavailable, "server control is unavailable")
		return
	}
	h.audit.Log(currentActor(r).ID, action, "server", nil)
	jsonResponse(w, http.StatusAccepted, map[string]string{"status": status})
	go control()
}

func (h *Handler) apiAdminHealth(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r.Context(), currentActor(r).ID) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	snapshot, ok := h.healthSnapshot(r.Context())
	if !ok {
		jsonError(w, http.StatusServiceUnavailable, "runtime health is unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, snapshot)
}

func (h *Handler) healthSnapshot(ctx context.Context) (health.Snapshot, bool) {
	if h.runtimeHealth == nil {
		return health.Snapshot{}, false
	}
	if h.refreshHealth != nil {
		h.refreshHealth(ctx)
	}
	return h.runtimeHealth.Snapshot(time.Now()), true
}

// healthResponse carries build and listener details only for API-key
// callers; anonymous probes see the status alone.
type healthResponse struct {
	Status        string  `json:"status"`
	Version       string  `json:"version,omitempty"`
	Commit        string  `json:"commit,omitempty"`
	BuildTime     string  `json:"build_time,omitempty"`
	UptimeSeconds float64 `json:"uptime_seconds,omitempty"`
	StoreType     string  `json:"store_type,omitempty"`
	ListenAddr    string  `json:"listen_addr,omitempty"`
	IMAPPort      string  `json:"imap_port,omitempty"`
	SMTPPort      string  `json:"smtp_port,omitempty"`
}

// apiHealth is public. A request presenting X-API-Key must present a valid
// administrator key and then also receives the build details.
func (h *Handler) apiHealth(w http.ResponseWriter, r *http.Request) {
	response := healthResponse{Status: "ok"}
	if secret := r.Header.Get(apiKeyHeader); secret != "" {
		credential, status, message := h.authenticateAPIKey(r.Context(), secret)
		if status != http.StatusOK {
			jsonError(w, status, message)
			return
		}
		if credential.permits(model.APIKeyScopeAPIRead) {
			build := h.build
			response.Version, response.Commit, response.BuildTime = build.Version, build.Commit, build.BuildTime
			response.StoreType, response.ListenAddr = build.StoreType, build.ListenAddr
			response.IMAPPort, response.SMTPPort = build.IMAPPort, build.SMTPPort
			if !build.StartTime.IsZero() {
				response.UptimeSeconds = time.Since(build.StartTime).Seconds()
			}
		}
	}
	jsonResponse(w, http.StatusOK, response)
}

type readinessComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type readinessResponse struct {
	Status     string               `json:"status"`
	Components []readinessComponent `json:"components"`
}

// apiHealthReady is the public per-component readiness probe: 200 while
// every desired component is available, 503 otherwise.
func (h *Handler) apiHealthReady(w http.ResponseWriter, r *http.Request) {
	snapshot, ok := h.healthSnapshot(r.Context())
	if !ok {
		jsonResponse(w, http.StatusServiceUnavailable, readinessResponse{Status: "unavailable", Components: []readinessComponent{}})
		return
	}
	response := readinessResponse{Status: "ready", Components: make([]readinessComponent, 0, len(snapshot.Components))}
	for _, component := range snapshot.Components {
		state := "ok"
		if component.Desired && component.State == health.StateUnavailable {
			state = "unavailable"
		}
		response.Components = append(response.Components, readinessComponent{Name: component.ID, Status: state, Reason: component.Reason})
	}
	status := http.StatusOK
	if snapshot.Status == health.StatusUnavailable {
		response.Status, status = "unavailable", http.StatusServiceUnavailable
	}
	jsonResponse(w, status, response)
}

func (h *Handler) apiHealthLive(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "alive"})
}

// metricsRangeResponse is the bounded, downsampled answer of
// GET /api/v1/admin/metrics.
type metricsRangeResponse struct {
	Start       time.Time             `json:"start"`
	End         time.Time             `json:"end"`
	StepSeconds int64                 `json:"step_seconds"`
	Series      []metrics.RangeSeries `json:"series"`
	Total       int                   `json:"total"`
}

// apiAdminMetrics returns stored metric series for a time window,
// downsampled server-side so each series carries at most a bounded number
// of points. Query parameters: window (default 24h, "15m", "6h", "7d", or
// seconds; capped at the retention period), end (RFC 3339 or Unix seconds,
// default now), points (default 288, capped at metrics.MaxRangePoints), and
// name (one metric name).
func (h *Handler) apiAdminMetrics(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	query := r.URL.Query()
	window := metrics.DefaultRangeWindow
	if value := query.Get("window"); value != "" {
		parsed, err := metrics.ParseRangeWindow(value)
		if err != nil || parsed < time.Second {
			jsonError(w, http.StatusBadRequest, "window must be a positive duration such as 1h, 24h, or 7d")
			return
		}
		window = parsed
	}
	end := time.Now().UTC()
	if value := query.Get("end"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			seconds, numErr := strconv.ParseInt(value, 10, 64)
			if numErr != nil {
				jsonError(w, http.StatusBadRequest, "end must be an RFC 3339 time or Unix seconds")
				return
			}
			parsed = time.Unix(seconds, 0)
		}
		end = parsed.UTC()
	}
	points := metrics.DefaultRangePoints
	if value := query.Get("points"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			jsonError(w, http.StatusBadRequest, "points must be a positive integer")
			return
		}
		points = min(parsed, metrics.MaxRangePoints)
	}
	response := metricsRangeResponse{End: end, Series: []metrics.RangeSeries{}}
	if h.metrics == nil {
		response.Start = end.Add(-window)
		jsonResponse(w, http.StatusOK, response)
		return
	}
	if retention := h.metrics.Retention(); retention > 0 {
		window = min(window, retention)
	}
	result, err := h.metrics.QueryRange(metrics.RangeQuery{Name: query.Get("name"), Start: end.Add(-window), End: end, Points: points})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "metrics query failed")
		return
	}
	response.Start, response.StepSeconds = result.Start, int64(result.Step/time.Second)
	response.Series, response.Total = result.Series, len(result.Series)
	jsonResponse(w, http.StatusOK, response)
}

// apiAdminMetricsPrometheus serves the /metrics exposition to administrators,
// whether or not a scrape token is configured.
func (h *Handler) apiAdminMetricsPrometheus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if h.metrics != nil {
		h.metrics.PrometheusFormat(w)
	}
}
