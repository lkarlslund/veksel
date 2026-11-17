package service

import (
	"testing"

	"github.com/lkarlslund/veksel/pkg/model"
)

func TestQuotaPolicyClassifiesHighestLimitedResource(t *testing.T) {
	policy := QuotaPolicy{WarningPercent: 80, CriticalPercent: 95}
	tests := []struct {
		name  string
		usage AccountUsage
		state string
		want  float64
	}{
		{name: "unlimited", usage: AccountUsage{AccountingReady: true}, state: QuotaPressureUnlimited},
		{name: "normal", usage: AccountUsage{AccountingReady: true, Items: 4, Quota: model.QuotaInfo{MaxItems: 10}}, state: QuotaPressureNormal, want: 40},
		{name: "item warning", usage: AccountUsage{AccountingReady: true, Items: 8, LogicalBytes: 20, Quota: model.QuotaInfo{MaxItems: 10, MaxStorageBytes: 100}}, state: QuotaPressureWarning, want: 80},
		{name: "storage critical", usage: AccountUsage{AccountingReady: true, LogicalBytes: 96, Quota: model.QuotaInfo{MaxStorageBytes: 100}}, state: QuotaPressureCritical, want: 96},
		{name: "full", usage: AccountUsage{AccountingReady: true, Items: 10, Quota: model.QuotaInfo{MaxItems: 10}}, state: QuotaPressureExceeded, want: 100},
		{name: "over", usage: AccountUsage{AccountingReady: true, Items: 12, Quota: model.QuotaInfo{MaxItems: 10}}, state: QuotaPressureExceeded, want: 120},
		{name: "unverified wins", usage: AccountUsage{Items: 12, Quota: model.QuotaInfo{MaxItems: 10}}, state: QuotaPressureUnverified},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := policy.Classify(test.usage)
			if got.State != test.state || got.Percent != test.want {
				t.Fatalf("status = %+v, want state %q percent %v", got, test.state, test.want)
			}
		})
	}
}

func TestQuotaPolicyRejectsInvalidThresholds(t *testing.T) {
	for _, policy := range []QuotaPolicy{{}, {WarningPercent: 95, CriticalPercent: 95}, {WarningPercent: 100, CriticalPercent: 101}} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("policy %+v was accepted", policy)
		}
	}
	if err := (QuotaPolicy{WarningPercent: 80, CriticalPercent: 95}).Validate(); err != nil {
		t.Fatal(err)
	}
}
