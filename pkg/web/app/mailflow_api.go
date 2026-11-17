package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

// Mail flow rules (sender routes, address rewriting, journaling, and
// always-BCC) are administrative objects that delivery reads from their
// stores for every message, so a change applies to the next message.

// mailFlowStore is the CRUD surface of one model.MailFlowStore.
type mailFlowStore[T any] interface {
	List(context.Context) ([]T, error)
	Get(context.Context, string) (T, error)
	Create(context.Context, T) (T, error)
	Set(context.Context, string, T) (T, error)
	Delete(context.Context, string) error
}

// mailFlowKind is one rule type's API: list, save (create when id is
// empty) returning the view and audit details, and delete.
type mailFlowKind struct {
	list   func(context.Context) (any, error)
	save   func(r *http.Request, id string) (view any, savedID string, details map[string]string, err error)
	remove func(context.Context, string) error
}

// plainMailFlowKind serves a rule type without secrets.
func plainMailFlowKind[T any](rules mailFlowStore[T], details func(T) (string, map[string]string)) mailFlowKind {
	return mailFlowKind{
		list: func(ctx context.Context) (any, error) { return rules.List(ctx) },
		save: func(r *http.Request, id string) (any, string, map[string]string, error) {
			var rule T
			if err := decodeJSON(r, &rule); err != nil {
				return nil, "", nil, err
			}
			var err error
			if id == "" {
				rule, err = rules.Create(r.Context(), rule)
			} else {
				rule, err = rules.Set(r.Context(), id, rule)
			}
			if err != nil {
				return nil, "", nil, err
			}
			savedID, audit := details(rule)
			return rule, savedID, audit, nil
		},
		remove: rules.Delete,
	}
}

// senderRouteView is a sender route without its sealed password.
type senderRouteView struct {
	model.SenderRoute
	HasPassword bool `json:"has_password"`
}

func viewSenderRoute(route model.SenderRoute) senderRouteView {
	view := senderRouteView{SenderRoute: route, HasPassword: len(route.SealedPassword) > 0}
	view.SealedPassword = nil
	return view
}

// senderRouteInput is a sender route as submitted. A nil Password keeps
// the stored one, an empty one removes it, and any other value replaces it.
type senderRouteInput struct {
	model.SenderRoute
	Password *string `json:"password,omitempty"`
}

func (h *Handler) senderRouteKind() mailFlowKind {
	routes := h.ts.SenderRouteStore()
	return mailFlowKind{
		list: func(ctx context.Context) (any, error) {
			stored, err := routes.List(ctx)
			views := make([]senderRouteView, 0, len(stored))
			for _, route := range stored {
				views = append(views, viewSenderRoute(route))
			}
			return views, err
		},
		save: func(r *http.Request, id string) (any, string, map[string]string, error) {
			var input senderRouteInput
			if err := decodeJSON(r, &input); err != nil {
				return nil, "", nil, err
			}
			ctx, route := r.Context(), input.SenderRoute
			route.SealedPassword = nil
			var err error
			if id == "" {
				route, err = routes.Create(ctx, route)
			} else {
				existing, getErr := routes.Get(ctx, id)
				if getErr != nil {
					return nil, "", nil, getErr
				}
				if input.Password == nil {
					route.SealedPassword = existing.SealedPassword
				}
				route, err = routes.Set(ctx, id, route)
			}
			if err != nil {
				return nil, "", nil, err
			}
			// The password is sealed to the route ID, which exists only now.
			if input.Password != nil && strings.TrimSpace(*input.Password) != "" && route.Transport == model.OutboundTransportRelay {
				if route.SealedPassword, err = h.migrationJobs.SealSecret(model.SenderRouteSecretPurpose, route.ID, []byte(*input.Password)); err != nil {
					return nil, "", nil, fmt.Errorf("protect relay credential: %w", err)
				}
				if route, err = routes.Set(ctx, route.ID, route); err != nil {
					return nil, "", nil, err
				}
			}
			return viewSenderRoute(route), route.ID, map[string]string{
				"sender": route.Sender, "account": route.Account, "destination": route.Destination, "transport": string(route.Transport),
				"relay_host": route.RelayHost, "enabled": fmt.Sprint(route.Enabled), "credential_changed": fmt.Sprint(input.Password != nil),
			}, nil
		},
		remove: routes.Delete,
	}
}

func (h *Handler) mailFlowKinds() map[string]mailFlowKind {
	return map[string]mailFlowKind{
		"sender-routes": h.senderRouteKind(),
		"rewrites": plainMailFlowKind(h.ts.AddressRewriteStore(), func(rule model.AddressRewrite) (string, map[string]string) {
			return rule.ID, map[string]string{"direction": string(rule.Direction), "pattern": rule.Pattern, "replacement": rule.Replacement,
				"envelope_sender": fmt.Sprint(rule.EnvelopeSender), "header_from": fmt.Sprint(rule.HeaderFrom), "enabled": fmt.Sprint(rule.Enabled)}
		}),
		"journal": plainMailFlowKind(h.ts.JournalRuleStore(), func(rule model.JournalRule) (string, map[string]string) {
			return rule.ID, map[string]string{"domain": rule.Domain, "inbound": fmt.Sprint(rule.Inbound), "outbound": fmt.Sprint(rule.Outbound),
				"address": rule.Address, "format": string(rule.Format), "enabled": fmt.Sprint(rule.Enabled)}
		}),
		"bcc": plainMailFlowKind(h.ts.BCCRuleStore(), func(rule model.BCCRule) (string, map[string]string) {
			return rule.ID, map[string]string{"match": string(rule.Match), "pattern": rule.Pattern, "address": rule.Address, "enabled": fmt.Sprint(rule.Enabled)}
		}),
	}
}

// apiAdminMailFlow lists every mail flow rule, keyed by kind.
func (h *Handler) apiAdminMailFlow(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	result := make(map[string]any)
	for name, kind := range h.mailFlowKinds() {
		rules, err := kind.list(r.Context())
		if err != nil {
			apiError(w, err)
			return
		}
		result[name] = rules
	}
	jsonResponse(w, http.StatusOK, result)
}

// apiAdminSaveMailFlow creates (POST) or replaces (PUT, with an id) a rule.
func (h *Handler) apiAdminSaveMailFlow(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	name := r.PathValue("kind")
	kind, ok := h.mailFlowKinds()[name]
	if !ok {
		jsonError(w, http.StatusNotFound, "unknown mail flow rule kind")
		return
	}
	id := r.PathValue("id")
	view, savedID, details, err := kind.save(r, id)
	if err != nil {
		apiError(w, err)
		return
	}
	action, status := "create", http.StatusCreated
	if id != "" {
		action, status = "update", http.StatusOK
	}
	h.audit.Log(currentActor(r).ID, "mail_flow."+name+"."+action, savedID, details)
	jsonResponse(w, status, view)
}

func (h *Handler) apiAdminDeleteMailFlow(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminAPI(w, r) {
		return
	}
	name := r.PathValue("kind")
	kind, ok := h.mailFlowKinds()[name]
	if !ok {
		jsonError(w, http.StatusNotFound, "unknown mail flow rule kind")
		return
	}
	id := r.PathValue("id")
	if err := kind.remove(r.Context(), id); err != nil {
		apiError(w, err)
		return
	}
	h.audit.Log(currentActor(r).ID, "mail_flow."+name+".delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}
