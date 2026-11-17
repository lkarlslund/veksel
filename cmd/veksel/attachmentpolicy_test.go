package main

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/attachment"
	"github.com/lkarlslund/veksel/pkg/config"
)

func TestAttachmentPolicyApplierSwapsPolicyLive(t *testing.T) {
	s := testDeliveryServer(t)
	apply := applierFor(t, s, "attachment_policy")
	cfg := config.Default()
	if err := apply(cfg); err != nil {
		t.Fatal(err)
	}
	if policy := s.delivery.attachments.Load(); policy == nil || policy.Mode() != attachment.ModeQuarantine || policy.Applies(true) {
		t.Fatalf("default policy = %+v", policy)
	}
	tuned := *cfg
	tuned.AttachmentPolicy, tuned.AttachmentCheckSubmissions = "reject", true
	if err := apply(&tuned); err != nil {
		t.Fatal(err)
	}
	if policy := s.delivery.attachments.Load(); policy.Mode() != attachment.ModeReject || !policy.Applies(true) {
		t.Fatalf("tuned policy = %+v", policy)
	}
	for name, mutate := range map[string]func(*config.Config){
		"unknown mode":  func(c *config.Config) { c.AttachmentPolicy = "block" },
		"bad extension": func(c *config.Config) { c.AttachmentBlockedExtensions = []string{"ex e"} },
	} {
		invalid := tuned
		mutate(&invalid)
		if err := apply(&invalid); err == nil {
			t.Fatalf("%s: invalid settings accepted", name)
		}
		if s.delivery.attachments.Load().Mode() != attachment.ModeReject {
			t.Fatalf("%s: policy changed after rejection", name)
		}
		if err := config.Validate(&invalid); err == nil {
			t.Fatalf("%s: configuration validation accepted it", name)
		}
	}
}
