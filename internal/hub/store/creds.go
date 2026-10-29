package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xiongyumail/tunx/internal/hub/model"
)

// Admin is an administrator account.
type Admin struct {
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPLast     int64 // last accepted TOTP step
}

// CreateAdmin adds an administrator; the username must be new.
func (s *Store) CreateAdmin(ctx context.Context, a Admin) error {
	if err := model.CheckName("username", a.Username); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO admins (username, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?)`,
			a.Username, a.PasswordHash, a.TOTPSecret, s.stamp()); err != nil {
			return fmt.Errorf("create admin %q: %w", a.Username, err)
		}
		return s.audit(ctx, tx, "cli", "create", "admin", a.Username, map[string]any{})
	})
}

// AdminCount returns the number of administrators.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

// Admin returns an administrator by name.
func (s *Store) Admin(ctx context.Context, username string) (*Admin, error) {
	a := &Admin{Username: username}
	err := s.db.QueryRowContext(ctx, `SELECT password_hash, totp_secret, totp_last FROM admins WHERE username = ?`, username).
		Scan(&a.PasswordHash, &a.TOTPSecret, &a.TOTPLast)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// UseTOTPStep records step as the last accepted TOTP step. It fails when
// the step is not newer than the stored one (a replayed code).
func (s *Store) UseTOTPStep(ctx context.Context, username string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET totp_last = ? WHERE username = ? AND totp_last < ?`, step, username, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// CreateSession stores a session by token hash.
func (s *Store) CreateSession(ctx context.Context, hash, username string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, s.now().Unix())
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)`, hash, username, expires.Unix())
	return err
}

// Session returns the user of an unexpired session.
func (s *Store) Session(ctx context.Context, hash string) (string, error) {
	var u string
	err := s.db.QueryRowContext(ctx, `SELECT username FROM sessions WHERE token_hash = ? AND expires_at > ?`, hash, s.now().Unix()).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return u, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash)
	return err
}

// APIToken describes an automation token (the token itself is not stored).
type APIToken struct {
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

// CreateAPIToken stores a token hash under a unique name.
func (s *Store) CreateAPIToken(ctx context.Context, actor, name, hash string) error {
	if err := model.CheckName("token name", name); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens (name, token_hash, created_by, created_at) VALUES (?, ?, ?, ?)`,
			name, hash, actor, s.stamp()); err != nil {
			return fmt.Errorf("token %q: %w", name, err)
		}
		return s.audit(ctx, tx, actor, "create", "token", name, map[string]any{})
	})
}

// APITokenByHash returns the name of a token.
func (s *Store) APITokenByHash(ctx context.Context, hash string) (string, error) {
	var n string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM api_tokens WHERE token_hash = ?`, hash).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return n, err
}

// APITokens lists the tokens.
func (s *Store) APITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, created_by, created_at FROM api_tokens ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.Name, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, actor, name string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE name = ?`, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.audit(ctx, tx, actor, "delete", "token", name, map[string]any{})
	})
}

// NodeByToken returns the node a config token belongs to.
func (s *Store) NodeByToken(ctx context.Context, hash string) (string, error) {
	var n string
	err := s.db.QueryRowContext(ctx, `SELECT node FROM node_tokens WHERE token_hash = ?`, hash).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return n, err
}

// CreateEnrollToken stores a one-time enrolment token for a node.
func (s *Store) CreateEnrollToken(ctx context.Context, actor, node, hash string, expires time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var x int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE name = ?`, node).Scan(&x); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("node %q: %w", node, ErrNotFound)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO enroll_tokens (token_hash, node, expires_at) VALUES (?, ?, ?)`, hash, node, expires.Unix()); err != nil {
			return err
		}
		return s.audit(ctx, tx, actor, "create", "enroll-token", node, map[string]any{"expires_at": expires.UTC().Format(time.RFC3339)})
	})
}

// ErrBadEnrollToken means the token is unknown, used or expired.
var ErrBadEnrollToken = errors.New("enrolment token is invalid, used or expired")

// Enroll consumes a one-time token: it sets the node's public key and
// replaces its config token, in one transaction. It returns the node name.
func (s *Store) Enroll(ctx context.Context, tokenHash, publicKey, nodeTokenHash string) (string, error) {
	var node string
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var expires int64
		var used sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT node, expires_at, used_at FROM enroll_tokens WHERE token_hash = ?`, tokenHash).Scan(&node, &expires, &used)
		if errors.Is(err, sql.ErrNoRows) || used.Valid || expires <= s.now().Unix() {
			return ErrBadEnrollToken
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enroll_tokens SET used_at = ? WHERE token_hash = ?`, s.stamp(), tokenHash); err != nil {
			return err
		}
		old, err := loadSpec(ctx, tx)
		if err != nil {
			return err
		}
		next := old.Clone()
		next.Node(node).PublicKey = publicKey
		if err := next.Validate(); err != nil {
			return &ValidationError{err}
		}
		if _, err := s.write(ctx, tx, "enroll:"+node, old, next); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO node_tokens (node, token_hash, created_at) VALUES (?, ?, ?)
			ON CONFLICT (node) DO UPDATE SET token_hash = excluded.token_hash, created_at = excluded.created_at`, node, nodeTokenHash, s.stamp())
		return err
	})
	return node, err
}
