package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/veksel/pkg/config"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/webhook"
)

func TestOutboundHTTPPrivateNetworksApplyLive(t *testing.T) {
	s := &server{}
	t.Cleanup(func() {
		s.cleanup.run(true)
	})
	if err := s.openRuntime(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(internal.Close)
	hooks := model.NewWebhookStore(s.ts)
	if err := hooks.Create(t.Context(), model.Webhook{ID: "internal", URL: internal.URL, Events: []string{"*"}, Active: true, Secret: "s"}); err != nil {
		t.Fatal(err)
	}
	s.webhooks = webhook.New(hooks, model.NewWebhookDeliveryStore(s.ts), model.NewWebhookOutboxStore(s.ts), webhook.DefaultRetryPolicy())
	if err := s.registerOutboundHTTP(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.webhooks.Test(t.Context(), "internal"); err == nil {
		t.Fatal("a webhook on a loopback address was delivered by default")
	}
	patchAndApply(t, s, map[string]any{"outbound_http_allow_private_networks": true})
	if status := applyState(t, s, "outbound_http_allow_private_networks"); status.State != config.ApplyEffective || status.RestartRequired {
		t.Fatalf("apply state = %+v", status)
	}
	if delivery, err := s.webhooks.Test(t.Context(), "internal"); err != nil || delivery.Status != model.WebhookDeliverySent {
		t.Fatalf("allowed delivery = %+v, %v", delivery, err)
	}
}
