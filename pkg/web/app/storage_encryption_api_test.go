package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lkarlslund/veksel/pkg/account"
)

func TestAdminStorageEncryptionConversionsAndKeyRotation(t *testing.T) {
	server, _, _, accounts, _ := managedTestApp(t)
	client := testClient(t)
	csrf := setupAndLogin(t, server, client, "owner")

	convert := func(body string, wantEncrypted bool) account.ConversionJob {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/account-storage/owner/conversions", csrf, body)
		var job account.ConversionJob
		if err := json.NewDecoder(response.Body).Decode(&job); err != nil || response.StatusCode != http.StatusAccepted {
			t.Fatalf("POST conversion %s status=%d job=%+v err=%v", body, response.StatusCode, job, err)
		}
		_ = response.Body.Close()
		deadline := time.Now().Add(5 * time.Second)
		for {
			jobs, err := accounts.Jobs("owner")
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) > 0 && jobs[0].ID == job.ID && jobs[0].Phase == account.ConversionCompleted {
				if entry, _ := accounts.ByLogin("owner"); entry.Manifest.Encrypted != wantEncrypted {
					t.Fatalf("after %s manifest encrypted=%t", body, entry.Manifest.Encrypted)
				}
				return jobs[0]
			}
			if time.Now().After(deadline) {
				t.Fatalf("conversion %s did not complete: %+v", body, jobs)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	status := func() account.EncryptionStatus {
		t.Helper()
		response := authenticatedJSON(t, client, http.MethodGet, server.URL+"/api/v1/admin/account-storage/encryption", "", "")
		var status account.EncryptionStatus
		if err := json.NewDecoder(response.Body).Decode(&status); err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("GET encryption status=%d err=%v", response.StatusCode, err)
		}
		_ = response.Body.Close()
		return status
	}

	encrypted := convert(`{"encrypted":true}`, true)
	if !encrypted.TargetEncrypted || encrypted.TargetEngine != encrypted.SourceEngine {
		t.Fatalf("encrypt job = %+v", encrypted)
	}
	before := status()
	if !before.Available || before.Encrypted != 1 || before.Accounts[0].KeyID != before.ActiveKeyID {
		t.Fatalf("status after encrypt = %+v", before)
	}

	response := authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/account-storage/encryption/rotate", csrf, `{}`)
	var rotation struct {
		Key struct {
			ActiveKeyID string `json:"active_key_id"`
		} `json:"key"`
		Accounts account.RewrapReport `json:"accounts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&rotation); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("POST rotate status=%d err=%v", response.StatusCode, err)
	}
	_ = response.Body.Close()
	if rotation.Key.ActiveKeyID == before.ActiveKeyID || rotation.Accounts.Rewrapped != 1 {
		t.Fatalf("rotation = %+v", rotation)
	}
	if after := status(); after.Stale != 0 || after.Accounts[0].KeyID != rotation.Key.ActiveKeyID {
		t.Fatalf("status after rotation = %+v", after)
	}

	if job := convert(`{"rotate_key":true}`, true); !job.RotateKey {
		t.Fatalf("rotate data key job = %+v", job)
	}
	convert(`{"encrypted":false}`, false)

	response = authenticatedJSON(t, client, http.MethodPost, server.URL+"/api/v1/admin/account-storage/owner/conversions", csrf, `{"rotate_key":true}`)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("key rotation of a plaintext account status = %d", response.StatusCode)
	}
}
