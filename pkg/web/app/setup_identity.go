package app

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/mailidentity"
)

// setupDefaultHostName is the host name first-run setup offers: the derived
// SMTP identity (machine host name unless configured).
func (h *Handler) setupDefaultHostName() string {
	if h.configService != nil {
		if cfg := h.configService.Current().Config; cfg != nil && strings.TrimSpace(cfg.SmtpServerName) != "" {
			return cfg.SmtpServerName
		}
	}
	if h.cfg != nil && strings.TrimSpace(h.cfg.SmtpServerName) != "" {
		return h.cfg.SmtpServerName
	}
	name, _ := os.Hostname()
	return name
}

// setupHostNameChange validates the optional public host name submitted at
// setup. It returns the normalized name to persist, or "" when nothing needs
// to change (blank, or equal to the already-derived name). A non-nil error is
// a validation message and must be returned before the owner is created.
func (h *Handler) setupHostNameChange(raw string) (string, error) {
	name := mailidentity.Normalize(raw)
	if name == "" || name == mailidentity.Normalize(h.setupDefaultHostName()) {
		return "", nil
	}
	if err := mailidentity.ValidateFQDN(name); err != nil {
		return "", err
	}
	return name, nil
}

// persistSetupHostName stores the public host name as smtp_server_name through
// the managed configuration patch mechanism. imap_server_name and
// pop3_server_name stay empty and keep deriving from the machine host name;
// administrators can set them separately. Failure never undoes owner
// creation: it is logged and the administrator can set the name later.
func (h *Handler) persistSetupHostName(_ context.Context, name string) {
	if name == "" || h.configService == nil {
		return
	}
	revision := h.configService.Current().Revision
	_, err := h.configService.PatchWithMetadata(revision, map[string]any{"smtp_server_name": name}, config.MutationMetadata{Actor: "setup", Reason: "first-run public host name", Source: "setup"})
	if err != nil {
		slog.Warn("setup: could not persist public host name", "error", err)
	}
}
