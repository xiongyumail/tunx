package model

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadExample(t *testing.T) (*Spec, []byte) {
	t.Helper()
	b, err := os.ReadFile("../../../examples/network.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s, b
}

func TestYAMLRoundTrip(t *testing.T) {
	s, _ := loadExample(t)
	out, err := MarshalYAML(s)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ParseYAML(out)
	if err != nil {
		t.Fatalf("export does not parse: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(s, s2) {
		t.Fatalf("round trip changed the network:\n%s", out)
	}
	out2, _ := MarshalYAML(s2)
	if !bytes.Equal(out, out2) {
		t.Fatal("export is not stable")
	}
	// The JSON form used by the store round-trips too.
	if !reflect.DeepEqual(s.Clone(), s) {
		t.Fatal("JSON clone differs")
	}
}

func TestParseYAMLStrict(t *testing.T) {
	for _, doc := range []string{"", "network: {name: x}\nextra: 1\n", "network: {name: x, bogus: 1}\n", "network: {name: x}\n---\nnetwork: {name: y}\n"} {
		if _, err := ParseYAML([]byte(doc)); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(s *Spec){
		"duplicate node":      func(s *Spec) { s.Nodes = append(s.Nodes, s.Nodes[0]) },
		"client named a node": func(s *Spec) { s.Clients[0].Name = "hub" },
		"bad node name":       func(s *Spec) { s.Nodes[0].Name = "a b" },
		"address outside":     func(s *Spec) { s.Nodes[0].Addresses = []string{"192.0.2.1"} },
		"address reused":      func(s *Spec) { s.Nodes[1].Addresses = s.Nodes[0].Addresses },
		"unknown capability":  func(s *Spec) { s.Nodes[0].Capabilities = append(s.Nodes[0].Capabilities, "fly") },
		"endpoint no listen":  func(s *Spec) { s.Node("hub").Capabilities = []string{"relay"} },
		"link same node":      func(s *Spec) { s.Links[0].Listener = s.Links[0].Dialer },
		"link bad endpoint":   func(s *Spec) { s.Links[0].Endpoint = "nope" },
		"link bad proxy":      func(s *Spec) { s.Links[0].DialerProxy = "nope" },
		"route host bits":     func(s *Spec) { s.Routes[0].Prefix = "10.0.1.1/24" },
		"route no advertise":  func(s *Spec) { s.Routes[0].Advertisers[0].Node = "hub" },
		"default needs exit":  func(s *Spec) { s.Routes[0].Prefix = "0.0.0.0/0" },
		"route dup prefix":    func(s *Spec) { s.Routes[1].Prefix = s.Routes[0].Prefix },
		"bad source mode":     func(s *Spec) { s.Routes[0].Advertisers[0].Source = "nat" },
		"access bad action":   func(s *Spec) { s.Access[0].Action = "maybe" },
		"access bad node":     func(s *Spec) { s.Access[0].Sources = []string{"node:nope"} },
		"access bad group":    func(s *Spec) { s.Access[0].Sources = []string{"group:nope"} },
		"access bad port":     func(s *Spec) { s.Access[1].Ports = Ports{"99999"} },
		"access icmp ports":   func(s *Spec) { s.Access[1].Proto = []string{"icmp"}; s.Access[1].Ports = Ports{"22"} },
		"nested group":        func(s *Spec) { s.Groups[0].Members = []string{"group:sites"} },
		"egress not exit":     func(s *Spec) { s.Egress[0].Exit = "hub" },
		"egress rule no tag":  func(s *Spec) { s.Egress[0].XrayRules = []map[string]any{{"domain": []any{"x"}}} },
		"client endpoint":     func(s *Spec) { s.Node("hub").Endpoints[0].Clients = false },
		"plain vless public":  func(s *Spec) { e := &s.Node("exit").Endpoints[0]; e.Transport, e.Reality = "vless", nil },
		"reality no target":   func(s *Spec) { s.Node("hub").Endpoints[0].Reality.Target = "" },
		"bad uuid":            func(s *Spec) { s.Links[0].UUID = "nope" },
		"link_listen public":  func(s *Spec) { s.Nodes[0].LinkListen = "0.0.0.0:7700" },
		"hop limit":           func(s *Spec) { s.Network.HopLimit = 300 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := loadExample(t)
			mutate(s)
			err := s.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
}

func TestPlainVLESSPrivate(t *testing.T) {
	for addr, ok := range map[string]bool{"10.1.2.3": true, "100.64.0.9": true, "fd00::1": true, "exit.lan": true, "x.home.arpa": true, "exit.example.net": false, "8.8.8.8": false} {
		if privateAddress(addr) != ok {
			t.Errorf("%s: want %v", addr, ok)
		}
	}
}

func TestGeneratedSecrets(t *testing.T) {
	s, _ := loadExample(t)
	old := s.Clone()
	for i := range s.Links {
		s.Links[i].UUID, s.Links[i].ShortID = "", ""
	}
	s.Node("hub").Endpoints[0].Reality.PrivateKey = ""
	s.KeepGenerated(old)
	if !reflect.DeepEqual(s, old) {
		t.Fatal("KeepGenerated did not restore secrets")
	}
	s.Links[0].UUID = ""
	s.Clients[0].Password = ""
	s.Node("hub").Endpoints[0].Reality.PrivateKey = ""
	if err := s.FillGenerated(nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Links[0].UUID == "" || s.Links[0].UUID == old.Links[0].UUID || s.Clients[0].Password == "" {
		t.Fatal("secrets not generated")
	}
	if _, err := RealityPublicKey(s.Node("hub").Endpoints[0].Reality.PrivateKey); err != nil {
		t.Fatal(err)
	}
	r := Redact(map[string]any{"uuid": "x", "nested": []any{map[string]any{"private_key": "k", "name": "n"}}})
	if s := strings.Join([]string{r.(map[string]any)["uuid"].(string), r.(map[string]any)["nested"].([]any)[0].(map[string]any)["private_key"].(string)}, ","); s != "<redacted>,<redacted>" {
		t.Fatal(s)
	}
}
