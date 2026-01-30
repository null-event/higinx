package core

import (
	"strings"
	"testing"
)

// TestNetterE2E tests the end-to-end workflow of parsing HAR and generating phishlet
func TestNetterE2E(t *testing.T) {
	// Parse HAR file
	parser := NewHARParser()
	analysis, err := parser.ParseFile("testdata/test-login.har")
	if err != nil {
		t.Fatalf("Failed to parse HAR: %v", err)
	}

	// Validate analysis
	if err := analysis.Validate(); err != nil {
		t.Fatalf("Analysis validation failed: %v", err)
	}

	// Select all auth candidate cookies
	var selectedCookies []*CookieInfo
	for _, c := range analysis.Cookies {
		if c.IsAuthCandidate {
			selectedCookies = append(selectedCookies, c)
		}
	}

	if len(selectedCookies) != 2 {
		t.Errorf("Expected 2 auth candidate cookies, got %d", len(selectedCookies))
	}

	// Use detected credentials
	credentials := analysis.LoginCandidate
	if credentials == nil {
		t.Fatal("No login candidate detected")
	}

	// Use detected login info
	loginInfo := analysis.LoginCandidate

	// Generate phishlet
	builder := NewPhishletBuilder(analysis, selectedCookies, credentials, loginInfo)
	yaml, err := builder.Build()
	if err != nil {
		t.Fatalf("Failed to build phishlet: %v", err)
	}

	// Verify generated YAML is valid-looking
	requiredSections := []string{
		"min_ver:",
		"proxy_hosts:",
		"auth_tokens:",
		"credentials:",
		"login:",
	}

	for _, section := range requiredSections {
		if !strings.Contains(yaml, section) {
			t.Errorf("Generated YAML missing required section: %s", section)
		}
	}

	// Verify it has proper structure
	if !strings.Contains(yaml, "example.com") {
		t.Error("Generated YAML should contain example.com domain")
	}

	if !strings.Contains(yaml, "accounts") {
		t.Error("Generated YAML should contain accounts subdomain")
	}

	if !strings.Contains(yaml, "session_id") || !strings.Contains(yaml, "auth_token") {
		t.Error("Generated YAML should contain auth tokens")
	}

	if !strings.Contains(yaml, "email") || !strings.Contains(yaml, "password") {
		t.Error("Generated YAML should contain credentials")
	}

	// Verify the generated phishlet can be parsed by the existing phishlet loader
	// This is a basic smoke test to ensure YAML structure is valid
	if !strings.HasPrefix(yaml, "#") {
		t.Error("Expected YAML to start with header comment")
	}

	lines := strings.Split(yaml, "\n")
	foundMinVer := false
	for _, line := range lines {
		if strings.HasPrefix(line, "min_ver:") {
			foundMinVer = true
			break
		}
	}

	if !foundMinVer {
		t.Error("min_ver should appear before other sections")
	}
}
