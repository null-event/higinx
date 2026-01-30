package core

import (
	"testing"
)

func TestHARParser_ParseFile(t *testing.T) {
	parser := NewHARParser()

	analysis, err := parser.ParseFile("testdata/test-login.har")
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Check domains
	if len(analysis.Domains) == 0 {
		t.Error("Expected at least one domain")
	}

	domain, exists := analysis.Domains["accounts.example.com"]
	if !exists {
		t.Error("Expected accounts.example.com domain")
	}

	if domain.BaseDomain != "example.com" {
		t.Errorf("Expected base domain 'example.com', got '%s'", domain.BaseDomain)
	}

	if domain.OrigSubdomain != "accounts" {
		t.Errorf("Expected subdomain 'accounts', got '%s'", domain.OrigSubdomain)
	}

	// Check cookies
	if len(analysis.Cookies) != 3 {
		t.Errorf("Expected 3 cookies, got %d", len(analysis.Cookies))
	}

	// Find session cookie
	var sessionCookie *CookieInfo
	for _, c := range analysis.Cookies {
		if c.Name == "session_id" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Error("Expected to find session_id cookie")
	}

	if !sessionCookie.HttpOnly {
		t.Error("Expected session_id to be HttpOnly")
	}

	if !sessionCookie.Secure {
		t.Error("Expected session_id to be Secure")
	}

	if !sessionCookie.IsAuthCandidate {
		t.Error("Expected session_id to be marked as auth candidate")
	}

	// Check POST requests
	if len(analysis.PostRequests) != 1 {
		t.Errorf("Expected 1 POST request, got %d", len(analysis.PostRequests))
	}

	post := analysis.PostRequests[0]
	if post.Domain != "accounts.example.com" {
		t.Errorf("Expected POST domain 'accounts.example.com', got '%s'", post.Domain)
	}

	if post.PostType != "json" {
		t.Errorf("Expected POST type 'json', got '%s'", post.PostType)
	}

	if post.UsernameKey != "email" {
		t.Errorf("Expected username key 'email', got '%s'", post.UsernameKey)
	}

	if post.PasswordKey != "password" {
		t.Errorf("Expected password key 'password', got '%s'", post.PasswordKey)
	}

	if !post.IsLoginCandidate {
		t.Error("Expected POST to be marked as login candidate")
	}

	if !post.SetsAuthCookies {
		t.Error("Expected POST to set auth cookies")
	}

	if post.AuthCookiesSet != 2 {
		t.Errorf("Expected 2 auth cookies set, got %d", post.AuthCookiesSet)
	}

	// Check login candidate
	if analysis.LoginCandidate == nil {
		t.Error("Expected login candidate to be detected")
	}

	if analysis.LoginCandidate.Path != "/api/auth/login" {
		t.Errorf("Expected login path '/api/auth/login', got '%s'", analysis.LoginCandidate.Path)
	}
}

func TestHARParser_Validate(t *testing.T) {
	parser := NewHARParser()

	analysis, err := parser.ParseFile("testdata/test-login.har")
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	err = analysis.Validate()
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}
}

func TestHARParser_InvalidFile(t *testing.T) {
	parser := NewHARParser()

	_, err := parser.ParseFile("nonexistent.har")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}
