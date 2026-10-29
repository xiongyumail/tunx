// Package model holds the declarative network description managed by
// tunx-hub: the network, nodes, links, routes, policies, clients and groups.
// The same structs are used for the YAML import/export, the REST API and the
// rows stored in SQLite.
package model

// Capabilities a node may have.
const (
	CapListen    = "listen"    // accepts links and clients on Xray endpoints
	CapRelay     = "relay"     // forwards flows between other nodes
	CapAdvertise = "advertise" // delivers route prefixes
	CapExit      = "exit"      // delivers the default route (internet)
)

// Endpoint transports.
const (
	TransportReality = "reality" // VLESS + REALITY
	TransportTLS     = "tls"     // VLESS + TLS
	TransportVLESS   = "vless"   // plain VLESS
	TransportSOCKS   = "socks"   // SOCKS5 with a password per link
)

// Defaults filled in by the renderer when a field is empty.
const (
	DefaultLinkListen   = "127.0.0.1:7700"
	DefaultClientListen = "127.0.0.1:7701"
	DefaultDialPortBase = 10800
	DefaultLinkCost     = 10
)

// Spec is a whole network. Lists are kept in canonical order (see
// Canonicalize): by name, except access policies by priority then name.
type Spec struct {
	Network Network        `yaml:"network" json:"network"`
	Groups  []Group        `yaml:"groups,omitempty" json:"groups"`
	Nodes   []Node         `yaml:"nodes,omitempty" json:"nodes"`
	Links   []Link         `yaml:"links,omitempty" json:"links"`
	Routes  []Route        `yaml:"routes,omitempty" json:"routes"`
	Access  []AccessPolicy `yaml:"access,omitempty" json:"access"`
	Egress  []EgressPolicy `yaml:"egress,omitempty" json:"egress"`
	Clients []Client       `yaml:"clients,omitempty" json:"clients"`
}

// Network holds the settings shared by all nodes.
type Network struct {
	// Name is the network ID that both ends of a link must agree on.
	Name string `yaml:"name" json:"name"`
	// Prefixes are the overlay prefixes (IPv4 and IPv6 ULA).
	Prefixes  []string `yaml:"prefixes,omitempty" json:"prefixes,omitempty"`
	DNSSuffix string   `yaml:"dns_suffix,omitempty" json:"dns_suffix,omitempty"`
	// HopLimit is rendered into every node; 0 keeps the tunxd default.
	HopLimit int `yaml:"hop_limit,omitempty" json:"hop_limit,omitempty"`
}

// Group names a list of identity selectors ("node:x", "client:x", "tag:t"
// or a glob pattern such as "site-*").
type Group struct {
	Name    string   `yaml:"name" json:"name"`
	Members []string `yaml:"members" json:"members"`
}

// Node is a host running tunxd and Xray.
type Node struct {
	Name string `yaml:"name" json:"name"`
	// PublicKey is the node's ed25519 key (base64). It is set at enrolment;
	// a node without it is not rendered into other nodes' configs.
	PublicKey    string     `yaml:"public_key,omitempty" json:"public_key,omitempty"`
	Addresses    []string   `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	Tags         []string   `yaml:"tags,omitempty" json:"tags,omitempty"`
	Capabilities []string   `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Endpoints    []Endpoint `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	// Proxies are extra Xray outbounds (opaque JSON objects) that links of
	// this node can dial through with dialer_proxy.
	Proxies []Proxy `yaml:"proxies,omitempty" json:"proxies,omitempty"`
	TUN     *TUN    `yaml:"tun,omitempty" json:"tun,omitempty"`
	// LinkListen is where tunxd accepts link connections from the local
	// Xray; ClientListen is the local SOCKS server for standard clients.
	LinkListen   string `yaml:"link_listen,omitempty" json:"link_listen,omitempty"`
	ClientListen string `yaml:"client_listen,omitempty" json:"client_listen,omitempty"`
	// DialPortBase is the first loopback port of the Xray inbounds that
	// tunxd dials, one per link this node dials.
	DialPortBase int    `yaml:"dial_port_base,omitempty" json:"dial_port_base,omitempty"`
	Status       string `yaml:"status,omitempty" json:"status,omitempty"`
	LogLevel     string `yaml:"log_level,omitempty" json:"log_level,omitempty"`
}

// TUN is the capture device of a node.
type TUN struct {
	Name string `yaml:"name" json:"name"`
	MTU  int    `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

// Endpoint is an Xray inbound of a listening node that links and clients
// connect to.
type Endpoint struct {
	Name      string `yaml:"name" json:"name"`
	Transport string `yaml:"transport" json:"transport"`
	// Address is the host other nodes and clients dial; Listen the local
	// bind address (default 0.0.0.0).
	Address string `yaml:"address" json:"address"`
	Port    int    `yaml:"port" json:"port"`
	Listen  string `yaml:"listen,omitempty" json:"listen,omitempty"`
	// Network is the Xray stream network: raw (default) or xhttp.
	Network string   `yaml:"network,omitempty" json:"network,omitempty"`
	Path    string   `yaml:"path,omitempty" json:"path,omitempty"`
	Reality *Reality `yaml:"reality,omitempty" json:"reality,omitempty"`
	TLS     *TLS     `yaml:"tls,omitempty" json:"tls,omitempty"`
	// Clients allows standard clients on this endpoint.
	Clients bool `yaml:"clients,omitempty" json:"clients,omitempty"`
}

// Reality configures a REALITY endpoint. PrivateKey is generated by the hub
// when empty (X25519, base64url without padding).
type Reality struct {
	Target      string   `yaml:"target" json:"target"`
	ServerNames []string `yaml:"server_names" json:"server_names"`
	Fingerprint string   `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	PrivateKey  string   `yaml:"private_key,omitempty" json:"private_key,omitempty"`
}

// TLS configures a TLS endpoint; the files are paths on the listening node.
type TLS struct {
	ServerName  string `yaml:"server_name" json:"server_name"`
	CertFile    string `yaml:"cert_file" json:"cert_file"`
	KeyFile     string `yaml:"key_file" json:"key_file"`
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
}

// Proxy is an Xray outbound object used as a dialer proxy. Its tag is set
// by the renderer.
type Proxy struct {
	Name     string         `yaml:"name" json:"name"`
	Outbound map[string]any `yaml:"outbound" json:"outbound"`
}

// Link is a transport connection between two nodes: Dialer connects to
// Listener's Endpoint.
type Link struct {
	Name     string `yaml:"name" json:"name"`
	Dialer   string `yaml:"dialer" json:"dialer"`
	Listener string `yaml:"listener" json:"listener"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	// Cost weighs the link in path computation (default 10); Priority
	// orders the peers of a node and the links between one pair of nodes.
	Cost     int `yaml:"cost,omitempty" json:"cost,omitempty"`
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`
	// Interface and Mark bind the dialer's Xray outbound socket.
	Interface string `yaml:"interface,omitempty" json:"interface,omitempty"`
	Mark      uint32 `yaml:"mark,omitempty" json:"mark,omitempty"`
	// DialerProxy names a proxy of the dialer node to chain through.
	DialerProxy string `yaml:"dialer_proxy,omitempty" json:"dialer_proxy,omitempty"`
	Disabled    bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// Generated by the hub when empty: the VLESS user ID (also the SOCKS
	// password) and the REALITY short ID.
	UUID    string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	ShortID string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
}

// Route maps a prefix to the nodes that deliver it.
type Route struct {
	Name        string            `yaml:"name" json:"name"`
	Prefix      string            `yaml:"prefix" json:"prefix"`
	Advertisers []RouteAdvertiser `yaml:"advertisers" json:"advertisers"`
}

// RouteAdvertiser is one node delivering a route.
type RouteAdvertiser struct {
	Node     string `yaml:"node" json:"node"`
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty"`
	// Source is snat (default) or preserve; Interface and Mark apply to
	// the delivering socket.
	Source    string `yaml:"source,omitempty" json:"source,omitempty"`
	Interface string `yaml:"interface,omitempty" json:"interface,omitempty"`
	Mark      uint32 `yaml:"mark,omitempty" json:"mark,omitempty"`
}

// AccessPolicy is an ordered allow or deny rule. Rules are evaluated by
// priority (lower first, then name); no match denies.
type AccessPolicy struct {
	Name        string `yaml:"name" json:"name"`
	Priority    int    `yaml:"priority" json:"priority"`
	Action      string `yaml:"action" json:"action"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Sources are identity selectors: "node:x", "client:x", "tag:t",
	// "group:g" or a glob pattern. Empty matches any identity.
	Sources        []string `yaml:"sources,omitempty" json:"sources,omitempty"`
	SourcePrefixes []string `yaml:"source_prefixes,omitempty" json:"source_prefixes,omitempty"`
	// Destinations are prefixes, addresses, "node:x" or "tag:t" (the
	// nodes' overlay addresses). Empty matches any destination.
	Destinations []string `yaml:"destinations,omitempty" json:"destinations,omitempty"`
	Proto        []string `yaml:"proto,omitempty" json:"proto,omitempty"`
	Ports        Ports    `yaml:"ports,omitempty" json:"ports,omitempty"`
}

// EgressPolicy sends the internet traffic of its sources to an exit node.
type EgressPolicy struct {
	Name     string   `yaml:"name" json:"name"`
	Priority int      `yaml:"priority" json:"priority"`
	Sources  []string `yaml:"sources" json:"sources"`
	Exit     string   `yaml:"exit" json:"exit"`
	// XrayRules are Xray routing rule objects applied to the traffic of
	// matching standard clients before it is handed to tunxd; they may
	// use the outbound tags "direct" and "block".
	XrayRules []map[string]any `yaml:"xray_rules,omitempty" json:"xray_rules,omitempty"`
}

// Client is a device without tunxd (a phone) attached to a listening node.
type Client struct {
	Name     string   `yaml:"name" json:"name"`
	Node     string   `yaml:"node" json:"node"`
	Endpoint string   `yaml:"endpoint" json:"endpoint"`
	Tags     []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Disabled bool     `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// Generated by the hub when empty: the VLESS user ID, the REALITY
	// short ID and the password of the client's account on the node's
	// local SOCKS server.
	UUID     string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	ShortID  string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
}

// HasCap reports whether the node has capability c.
func (n *Node) HasCap(c string) bool {
	for _, x := range n.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// HasTag reports whether the node has tag t.
func (n *Node) HasTag(t string) bool {
	for _, x := range n.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// Endpoint returns the node's endpoint by name.
func (n *Node) Endpoint(name string) *Endpoint {
	for i := range n.Endpoints {
		if n.Endpoints[i].Name == name {
			return &n.Endpoints[i]
		}
	}
	return nil
}

// Proxy returns the node's proxy by name.
func (n *Node) Proxy(name string) *Proxy {
	for i := range n.Proxies {
		if n.Proxies[i].Name == name {
			return &n.Proxies[i]
		}
	}
	return nil
}

// Node returns a node by name.
func (s *Spec) Node(name string) *Node {
	return find(s.Nodes, name, func(n *Node) string { return n.Name })
}

// Client returns a client by name.
func (s *Spec) Client(name string) *Client {
	return find(s.Clients, name, func(c *Client) string { return c.Name })
}

// Group returns a group by name.
func (s *Spec) Group(name string) *Group {
	return find(s.Groups, name, func(g *Group) string { return g.Name })
}

func find[T any](list []T, name string, key func(*T) string) *T {
	for i := range list {
		if key(&list[i]) == name {
			return &list[i]
		}
	}
	return nil
}
