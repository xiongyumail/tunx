package model

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Kinds lists the object kinds of a Spec as used in API paths and store
// tables, in dependency order.
var Kinds = []string{"groups", "nodes", "links", "routes", "access", "egress", "clients"}

// ErrNotFound is returned for a missing object.
var ErrNotFound = errors.New("not found")

// Item is one object with its kind and name.
type Item struct {
	Kind string
	Name string
	Obj  any
}

type kindOps struct {
	items  func(s *Spec) []Item
	put    func(s *Spec, b []byte) (string, error)
	delete func(s *Spec, name string) bool
	set    func(s *Spec, items [][]byte) error
}

func ops[T any](kind string, list func(*Spec) *[]T, name func(*T) string) kindOps {
	return kindOps{
		items: func(s *Spec) []Item {
			l := *list(s)
			out := make([]Item, len(l))
			for i := range l {
				out[i] = Item{Kind: kind, Name: name(&l[i]), Obj: &l[i]}
			}
			return out
		},
		put: func(s *Spec, b []byte) (string, error) {
			var v T
			if err := DecodeJSON(b, &v); err != nil {
				return "", err
			}
			n := name(&v)
			l := list(s)
			if i := slices.IndexFunc(*l, func(x T) bool { return name(&x) == n }); i >= 0 {
				(*l)[i] = v
			} else {
				*l = append(*l, v)
			}
			return n, nil
		},
		delete: func(s *Spec, n string) bool {
			l := list(s)
			i := slices.IndexFunc(*l, func(x T) bool { return name(&x) == n })
			if i < 0 {
				return false
			}
			*l = slices.Delete(*l, i, i+1)
			return true
		},
		set: func(s *Spec, items [][]byte) error {
			l := list(s)
			*l = nil
			for _, b := range items {
				var v T
				if err := json.Unmarshal(b, &v); err != nil {
					return err
				}
				*l = append(*l, v)
			}
			return nil
		},
	}
}

var kindTable = map[string]kindOps{
	"groups":  ops("groups", func(s *Spec) *[]Group { return &s.Groups }, func(x *Group) string { return x.Name }),
	"nodes":   ops("nodes", func(s *Spec) *[]Node { return &s.Nodes }, func(x *Node) string { return x.Name }),
	"links":   ops("links", func(s *Spec) *[]Link { return &s.Links }, func(x *Link) string { return x.Name }),
	"routes":  ops("routes", func(s *Spec) *[]Route { return &s.Routes }, func(x *Route) string { return x.Name }),
	"access":  ops("access", func(s *Spec) *[]AccessPolicy { return &s.Access }, func(x *AccessPolicy) string { return x.Name }),
	"egress":  ops("egress", func(s *Spec) *[]EgressPolicy { return &s.Egress }, func(x *EgressPolicy) string { return x.Name }),
	"clients": ops("clients", func(s *Spec) *[]Client { return &s.Clients }, func(x *Client) string { return x.Name }),
}

// ValidKind reports whether kind names an object list.
func ValidKind(kind string) bool { _, ok := kindTable[kind]; return ok }

// Items returns the objects of one kind.
func (s *Spec) Items(kind string) []Item { return kindTable[kind].items(s) }

// Get returns one object.
func (s *Spec) Get(kind, name string) (any, error) {
	for _, it := range s.Items(kind) {
		if it.Name == name {
			return it.Obj, nil
		}
	}
	return nil, ErrNotFound
}

// Put decodes a JSON object of the given kind and creates or replaces it.
func (s *Spec) Put(kind string, b []byte) (string, error) {
	o, ok := kindTable[kind]
	if !ok {
		return "", fmt.Errorf("unknown kind %q", kind)
	}
	return o.put(s, b)
}

// Delete removes one object.
func (s *Spec) Delete(kind, name string) error {
	o, ok := kindTable[kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", kind)
	}
	if !o.delete(s, name) {
		return ErrNotFound
	}
	return nil
}

// SetItems replaces all objects of a kind from their JSON encodings.
func (s *Spec) SetItems(kind string, items [][]byte) error { return kindTable[kind].set(s, items) }

// DecodeJSON decodes strictly: unknown fields and trailing data are errors.
func DecodeJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON object")
	}
	return nil
}

// Clone returns a deep copy.
func (s *Spec) Clone() *Spec {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var c Spec
	if err := json.Unmarshal(b, &c); err != nil {
		panic(err)
	}
	return &c
}

// KeepGenerated copies generated secrets from old into objects of s that
// have the same name and leave them empty, so that a declarative import
// without secrets does not rotate them.
func (s *Spec) KeepGenerated(old *Spec) {
	for i := range s.Nodes {
		n := &s.Nodes[i]
		o := old.Node(n.Name)
		if o == nil {
			continue
		}
		if n.PublicKey == "" {
			n.PublicKey = o.PublicKey
		}
		for j := range n.Endpoints {
			e := &n.Endpoints[j]
			oe := o.Endpoint(e.Name)
			if e.Reality != nil && e.Reality.PrivateKey == "" && oe != nil && oe.Reality != nil {
				e.Reality.PrivateKey = oe.Reality.PrivateKey
			}
		}
	}
	for i := range s.Links {
		l := &s.Links[i]
		j := slices.IndexFunc(old.Links, func(x Link) bool { return x.Name == l.Name })
		if j < 0 {
			continue
		}
		if l.UUID == "" {
			l.UUID = old.Links[j].UUID
		}
		if l.ShortID == "" {
			l.ShortID = old.Links[j].ShortID
		}
	}
	for i := range s.Clients {
		c := &s.Clients[i]
		o := old.Client(c.Name)
		if o == nil {
			continue
		}
		if c.UUID == "" {
			c.UUID = o.UUID
		}
		if c.ShortID == "" {
			c.ShortID = o.ShortID
		}
		if c.Password == "" {
			c.Password = o.Password
		}
	}
}

// FillGenerated generates every missing secret: REALITY keys of endpoints,
// link and client UUIDs and short IDs, client SOCKS passwords.
func (s *Spec) FillGenerated(r io.Reader) error {
	if r == nil {
		r = rand.Reader
	}
	for i := range s.Nodes {
		for j := range s.Nodes[i].Endpoints {
			e := &s.Nodes[i].Endpoints[j]
			if e.Reality != nil && e.Reality.PrivateKey == "" {
				k, err := ecdh.X25519().GenerateKey(r)
				if err != nil {
					return err
				}
				e.Reality.PrivateKey = base64.RawURLEncoding.EncodeToString(k.Bytes())
			}
		}
	}
	var err error
	gen := func(dst *string, f func(io.Reader) (string, error)) {
		if *dst == "" && err == nil {
			*dst, err = f(r)
		}
	}
	for i := range s.Links {
		l := &s.Links[i]
		gen(&l.UUID, NewUUID)
		gen(&l.ShortID, newShortID)
	}
	for i := range s.Clients {
		c := &s.Clients[i]
		gen(&c.UUID, NewUUID)
		gen(&c.ShortID, newShortID)
		gen(&c.Password, newPassword)
	}
	return err
}

// NewUUID returns a random version 4 UUID.
func NewUUID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func newShortID(r io.Reader) (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func newPassword(r io.Reader) (string, error) {
	var b [18]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// RealityPublicKey derives the public key (Xray's "password") from an
// endpoint's private key.
func RealityPublicKey(priv string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		return "", errors.New("reality private key: not base64url")
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// secretFields are JSON keys whose values are redacted in the audit log.
var secretFields = []string{"uuid", "short_id", "password", "private_key"}

// Redact replaces non-empty secret values anywhere in a decoded JSON value.
func Redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if s, ok := e.(string); ok && s != "" && slices.Contains(secretFields, k) {
				out[k] = "<redacted>"
				continue
			}
			out[k] = Redact(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = Redact(e)
		}
		return out
	}
	return v
}
