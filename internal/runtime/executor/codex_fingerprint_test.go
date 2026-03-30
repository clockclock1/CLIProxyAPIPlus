package executor

import (
	"fmt"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestCodexFingerprintGeneration(t *testing.T) {
	// Test that different accounts get different fingerprints
	auth1 := &cliproxyauth.Auth{
		ID: "test-account-1",
		Metadata: map[string]any{
			"account_id": "acc-123",
			"email":      "user1@example.com",
		},
	}
	
	auth2 := &cliproxyauth.Auth{
		ID: "test-account-2", 
		Metadata: map[string]any{
			"account_id": "acc-456",
			"email":      "user2@example.com",
		},
	}
	
	// Clear cache to ensure fresh generation
	ClearFingerprintCache()
	
	// Generate fingerprints
	fp1 := GetOrCreateFingerprint(auth1)
	fp2 := GetOrCreateFingerprint(auth2)
	
	if fp1 == nil || fp2 == nil {
		t.Fatal("Fingerprint generation failed")
	}
	
	// Verify fingerprints are different
	if fp1.PackageVersion == fp2.PackageVersion && 
	   fp1.RuntimeVersion == fp2.RuntimeVersion &&
	   fp1.OS == fp2.OS &&
	   fp1.Arch == fp2.Arch &&
	   fp1.AcceptLanguage == fp2.AcceptLanguage {
		t.Error("Different accounts generated identical fingerprints")
	}
	
	// Verify same account gets same fingerprint (consistency)
	fp1Again := GetOrCreateFingerprint(auth1)
	if fp1Again.PackageVersion != fp1.PackageVersion ||
	   fp1Again.RuntimeVersion != fp1.RuntimeVersion ||
	   fp1Again.OS != fp1.OS ||
	   fp1Again.Arch != fp1.Arch {
		t.Error("Same account generated different fingerprints")
	}
	
	t.Logf("Account 1 fingerprint: %s", GetFingerprintSummary(fp1))
	t.Logf("Account 2 fingerprint: %s", GetFingerprintSummary(fp2))
}

func TestCodexFingerprintRealism(t *testing.T) {
	ClearFingerprintCache()
	
	auth := &cliproxyauth.Auth{
		ID: "test-realism",
		Metadata: map[string]any{
			"account_id": "acc-realism-test",
		},
	}
	
	fp := GetOrCreateFingerprint(auth)
	if fp == nil {
		t.Fatal("Fingerprint generation failed")
	}
	
	// Verify realistic values
	if fp.UserAgent == "" {
		t.Error("User-Agent is empty")
	}
	
	if fp.PackageVersion == "" {
		t.Error("Package version is empty")
	}
	
	if fp.RuntimeVersion == "" {
		t.Error("Runtime version is empty")
	}
	
	if fp.OS == "" {
		t.Error("OS is empty")
	}
	
	if fp.Arch == "" {
		t.Error("Architecture is empty")
	}
	
	if fp.AcceptLanguage == "" {
		t.Error("Accept-Language is empty")
	}
	
	// Verify format
	if fp.Originator != "openai-node" {
		t.Errorf("Expected originator 'openai-node', got '%s'", fp.Originator)
	}
	
	t.Logf("Generated realistic fingerprint: %s", GetFingerprintSummary(fp))
	t.Logf("Full User-Agent: %s", fp.UserAgent)
	t.Logf("Accept-Language: %s", fp.AcceptLanguage)
}

func TestCodexFingerprintStats(t *testing.T) {
	ClearFingerprintCache()
	
	// Generate multiple fingerprints
	for i := 0; i < 10; i++ {
		auth := &cliproxyauth.Auth{
			ID: fmt.Sprintf("test-stats-%d", i),
			Metadata: map[string]any{
				"account_id": fmt.Sprintf("acc-stats-%d", i),
			},
		}
		GetOrCreateFingerprint(auth)
	}
	
	stats := ExportFingerprintStats()
	if stats["total_cached"].(int) != 10 {
		t.Errorf("Expected 10 cached fingerprints, got %d", stats["total_cached"])
	}
	
	t.Logf("Fingerprint statistics: %+v", stats)
}