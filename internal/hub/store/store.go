// Package store keeps the tunx-hub state in SQLite: the network objects
// (one table per kind, each row the object's JSON), credentials and the
// audit log. Every change of a network object is applied to the whole
// network in one transaction, validated, and recorded in the audit log.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xiongyumail/tunx/internal/hub/model"
)

// ErrNotFound is returned for a missing row.
var ErrNotFound = model.ErrNotFound

// ValidationError wraps an invalid network change.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return "invalid network: " + e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// tables maps object kinds to their tables.
var tables = map[string]string{
	"groups":  "groups",
	"nodes":   "nodes",
	"links":   "links",
	"routes":  "routes",
	"access":  "access_policies",
	"egress":  "egress_policies",
	"clients": "clients",
}

// Store is the hub database.
type Store struct {
	db  *sql.DB
	mu  sync.Mutex // serializes network updates
	now func() time.Time
	// Rand supplies generated secrets; nil means crypto/rand.
	Rand io.Reader
}

// Open opens or creates the database at path and applies migrations.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite has a single writer, and this keeps
	// transactions and plain queries strictly ordered.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetClock replaces the clock (tests).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Now returns the store's current time.
func (s *Store) Now() time.Time { return s.now() }

func objectTable(name string) string {
	return fmt.Sprintf(`CREATE TABLE %s (
	name TEXT PRIMARY KEY,
	spec TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`, name)
}

// migrations are applied in order; each runs once, in its own transaction.
var migrations = [][]string{
	{
		`CREATE TABLE network (id INTEGER PRIMARY KEY CHECK (id = 1), spec TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		objectTable("groups"), objectTable("nodes"), objectTable("links"), objectTable("routes"),
		objectTable("access_policies"), objectTable("egress_policies"), objectTable("clients"),
		`CREATE TABLE audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at TEXT NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			kind TEXT NOT NULL,
			name TEXT NOT NULL,
			diff TEXT NOT NULL
		)`,
		`CREATE TABLE admins (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			totp_secret TEXT NOT NULL,
			totp_last INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE sessions (
			token_hash TEXT PRIMARY KEY,
			username TEXT NOT NULL REFERENCES admins(username) ON DELETE CASCADE,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE api_tokens (
			name TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			created_by TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE node_tokens (
			node TEXT PRIMARY KEY REFERENCES nodes(name) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE enroll_tokens (
			token_hash TEXT PRIMARY KEY,
			node TEXT NOT NULL REFERENCES nodes(name) ON DELETE CASCADE,
			expires_at INTEGER NOT NULL,
			used_at TEXT
		)`,
	},
}

// SchemaVersion is the number of migrations this binary knows.
var SchemaVersion = len(migrations)

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	v, err := s.Version(ctx)
	if err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("database schema %d is newer than this binary (%d)", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		err := s.tx(ctx, func(tx *sql.Tx) error {
			for _, stmt := range migrations[i] {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("migration %d: %w", i+1, err)
				}
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, i+1, s.stamp())
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Version returns the applied schema version.
func (s *Store) Version(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (s *Store) stamp() string { return s.now().UTC().Format(time.RFC3339) }

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

// Spec loads the whole network.
func (s *Store) Spec(ctx context.Context) (*model.Spec, error) { return loadSpec(ctx, s.db) }

func loadSpec(ctx context.Context, q querier) (*model.Spec, error) {
	spec := &model.Spec{}
	var raw string
	switch err := q.QueryRowContext(ctx, `SELECT spec FROM network WHERE id = 1`).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal([]byte(raw), &spec.Network); err != nil {
			return nil, fmt.Errorf("network row: %w", err)
		}
	}
	for _, kind := range model.Kinds {
		rows, err := q.QueryContext(ctx, `SELECT spec FROM `+tables[kind]+` ORDER BY name`)
		if err != nil {
			return nil, err
		}
		var items [][]byte
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				rows.Close()
				return nil, err
			}
			items = append(items, b)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if err := spec.SetItems(kind, items); err != nil {
			return nil, fmt.Errorf("%s row: %w", kind, err)
		}
	}
	spec.Canonicalize()
	return spec, nil
}

// Change is one object created, updated or deleted by an update.
type Change struct {
	Action string `json:"action"` // create, update, delete
	Kind   string `json:"kind"`
	Name   string `json:"name"`
}

// Update applies fn to a copy of the network and stores the result when it
// is valid, all in one transaction. Secrets left empty keep their stored
// value or are generated. Every changed object is written to the audit log
// under actor. With no change nothing is written.
func (s *Store) Update(ctx context.Context, actor string, fn func(*model.Spec) error) ([]Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var changes []Change
	err := s.tx(ctx, func(tx *sql.Tx) error {
		old, err := loadSpec(ctx, tx)
		if err != nil {
			return err
		}
		next := old.Clone()
		if err := fn(next); err != nil {
			return err
		}
		next.Canonicalize()
		next.KeepGenerated(old)
		if err := next.FillGenerated(s.Rand); err != nil {
			return err
		}
		if err := next.Validate(); err != nil {
			return &ValidationError{err}
		}
		changes, err = s.write(ctx, tx, actor, old, next)
		return err
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}

// Import replaces the whole network with spec (declarative, idempotent):
// objects missing from spec are deleted, secrets missing from spec keep
// their stored values.
func (s *Store) Import(ctx context.Context, actor string, spec *model.Spec) ([]Change, error) {
	return s.Update(ctx, actor, func(cur *model.Spec) error {
		*cur = *spec.Clone()
		return nil
	})
}

func (s *Store) write(ctx context.Context, tx *sql.Tx, actor string, old, next *model.Spec) ([]Change, error) {
	var changes []Change
	now := s.stamp()
	if !reflect.DeepEqual(jsonValue(old.Network), jsonValue(next.Network)) {
		b, _ := json.Marshal(next.Network)
		if _, err := tx.ExecContext(ctx, `INSERT INTO network (id, spec, updated_at) VALUES (1, ?, ?)
			ON CONFLICT (id) DO UPDATE SET spec = excluded.spec, updated_at = excluded.updated_at`, string(b), now); err != nil {
			return nil, err
		}
		changes = append(changes, Change{"update", "network", next.Network.Name})
		if err := s.audit(ctx, tx, actor, "update", "network", next.Network.Name, diff(old.Network, next.Network)); err != nil {
			return nil, err
		}
	}
	// Deletes run in reverse dependency order, writes in dependency order,
	// so foreign keys of credential rows see a consistent state.
	kinds := slices.Clone(model.Kinds)
	slices.Reverse(kinds)
	for _, kind := range kinds {
		nextNames := map[string]bool{}
		for _, it := range next.Items(kind) {
			nextNames[it.Name] = true
		}
		for _, it := range old.Items(kind) {
			if nextNames[it.Name] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+tables[kind]+` WHERE name = ?`, it.Name); err != nil {
				return nil, err
			}
			changes = append(changes, Change{"delete", kind, it.Name})
			if err := s.audit(ctx, tx, actor, "delete", kind, it.Name, diff(it.Obj, nil)); err != nil {
				return nil, err
			}
		}
	}
	for _, kind := range model.Kinds {
		oldObjs := map[string]any{}
		for _, it := range old.Items(kind) {
			oldObjs[it.Name] = it.Obj
		}
		for _, it := range next.Items(kind) {
			prev, existed := oldObjs[it.Name]
			if existed && reflect.DeepEqual(jsonValue(prev), jsonValue(it.Obj)) {
				continue
			}
			b, _ := json.Marshal(it.Obj)
			if _, err := tx.ExecContext(ctx, `INSERT INTO `+tables[kind]+` (name, spec, created_at, updated_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (name) DO UPDATE SET spec = excluded.spec, updated_at = excluded.updated_at`, it.Name, string(b), now, now); err != nil {
				return nil, err
			}
			action := "create"
			if existed {
				action = "update"
			} else {
				prev = nil
			}
			changes = append(changes, Change{action, kind, it.Name})
			if err := s.audit(ctx, tx, actor, action, kind, it.Name, diff(prev, it.Obj)); err != nil {
				return nil, err
			}
		}
	}
	return changes, nil
}

// jsonValue decodes v's JSON encoding into generic values for comparison.
func jsonValue(v any) any {
	if v == nil || reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil() {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	json.Unmarshal(b, &out)
	return out
}

// diff describes a change with secrets redacted: the whole object for a
// create or delete, the changed top-level fields for an update.
func diff(old, new any) any {
	o, n := model.Redact(jsonValue(old)), model.Redact(jsonValue(new))
	om, ok1 := o.(map[string]any)
	nm, ok2 := n.(map[string]any)
	if !ok1 || !ok2 {
		return map[string]any{"old": o, "new": n}
	}
	out := map[string]any{}
	for k := range om {
		if _, ok := nm[k]; !ok {
			out[k] = map[string]any{"old": om[k], "new": nil}
		}
	}
	for k, v := range nm {
		if !reflect.DeepEqual(om[k], v) {
			out[k] = map[string]any{"old": om[k], "new": v}
		}
	}
	// A changed secret shows as "<redacted>" on both sides; compare the
	// raw values to still record that it changed.
	ro, _ := jsonValue(old).(map[string]any)
	rn, _ := jsonValue(new).(map[string]any)
	for k := range rn {
		if _, done := out[k]; !done && !reflect.DeepEqual(ro[k], rn[k]) {
			out[k] = map[string]any{"old": om[k], "new": nm[k], "changed": true}
		}
	}
	return out
}

func (s *Store) audit(ctx context.Context, tx *sql.Tx, actor, action, kind, name string, d any) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit (at, actor, action, kind, name, diff) VALUES (?, ?, ?, ?, ?, ?)`,
		s.stamp(), actor, action, kind, name, string(b))
	return err
}

// LogEvent records a non-object event (login, token issued) in the audit
// log. detail must not contain secrets.
func (s *Store) LogEvent(ctx context.Context, actor, action, kind, name string, detail any) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return s.audit(ctx, tx, actor, action, kind, name, detail) })
}

// AuditEntry is one audit log row.
type AuditEntry struct {
	ID     int64           `json:"id"`
	At     string          `json:"at"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Diff   json.RawMessage `json:"diff"`
}

// Audit returns the newest entries first.
func (s *Store) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, actor, action, kind, name, diff FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var d string
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Kind, &e.Name, &d); err != nil {
			return nil, err
		}
		e.Diff = json.RawMessage(d)
		out = append(out, e)
	}
	return out, rows.Err()
}
