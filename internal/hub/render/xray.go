package render

import (
	"cmp"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"

	"github.com/xiongyumail/tunx/internal/hub/model"
)

type obj = map[string]any

// Xray outbound tags used by the rendered routing and available to egress
// rule fragments.
const (
	TagBlock  = "block"
	TagDirect = "direct"
	TagTunxd  = "tunxd"
)

const visionFlow = "xtls-rprx-vision"

func linkEmail(l *model.Link) string     { return "link:" + l.Name }
func clientEmail(c *model.Client) string { return "client:" + c.Name }
func inboundTag(e *model.Endpoint) string {
	return "in-" + e.Name
}

// flow returns the VLESS flow for an endpoint: Vision on raw TLS and
// REALITY, none otherwise.
func flow(e *model.Endpoint) string {
	if cmp.Or(e.Network, "raw") == "raw" && (e.Transport == model.TransportReality || e.Transport == model.TransportTLS) {
		return visionFlow
	}
	return ""
}

func vlessUser(id, email, flow string, client bool) obj {
	u := obj{"id": id}
	if client {
		u["encryption"] = "none"
	} else {
		u["email"] = email
	}
	if flow != "" {
		u["flow"] = flow
	}
	return u
}

// xray renders the node's Xray config:
//   - each endpoint is an inbound; link users go to the "tunxd" outbound
//     (freedom redirected to tunxd's link listener), each client user to its
//     own SOCKS outbound into tunxd's client server, the rest is blocked;
//   - each link this node dials is a loopback tunnel inbound that tunxd
//     dials, routed to an outbound wired to the peer's endpoint.
func (r *renderer) xray() map[string]any {
	n := r.self
	var inbounds, outbounds, rules []any
	outbounds = append(outbounds,
		obj{"tag": TagBlock, "protocol": "blackhole"},
		obj{"tag": TagDirect, "protocol": "freedom"},
	)

	// Users of each endpoint.
	linksAt := map[string][]*model.Link{}
	for i := range r.spec.Links {
		l := &r.spec.Links[i]
		if l.Listener == n.Name && r.g.active(l) {
			linksAt[l.Endpoint] = append(linksAt[l.Endpoint], l)
		}
	}
	clientsAt := map[string][]*model.Client{}
	for _, c := range r.clientsOf(n.Name) {
		clientsAt[c.Endpoint] = append(clientsAt[c.Endpoint], c)
	}
	eps := slices.Clone(n.Endpoints)
	slices.SortFunc(eps, func(a, b model.Endpoint) int { return cmp.Compare(a.Name, b.Name) })

	var endpointTags, linkRules, clientRules []any
	for i := range eps {
		e := &eps[i]
		links, clients := linksAt[e.Name], clientsAt[e.Name]
		if len(links) == 0 && len(clients) == 0 {
			continue
		}
		tag := inboundTag(e)
		endpointTags = append(endpointTags, tag)
		inbounds = append(inbounds, r.endpointInbound(e, links, clients))
		if len(links) > 0 {
			rule := obj{"inboundTag": []any{tag}, "outboundTag": TagTunxd}
			if e.Transport != model.TransportSOCKS {
				var users []any
				for _, l := range links {
					users = append(users, linkEmail(l))
				}
				rule["user"] = users
			}
			linkRules = append(linkRules, rule)
		}
		for _, c := range clients {
			clientRules = append(clientRules, obj{"inboundTag": []any{tag}, "user": []any{clientEmail(c)}, "outboundTag": "client-" + c.Name})
		}
	}
	if len(linkRules) > 0 {
		outbounds = append(outbounds, obj{"tag": TagTunxd, "protocol": "freedom", "settings": obj{"redirect": linkListen(n)}})
	}

	dial, ports := r.dialLinks()
	for _, l := range dial {
		peer := r.spec.Node(l.Listener)
		host, port, _ := net.SplitHostPort(linkListen(peer))
		p, _ := strconv.Atoi(port)
		inbounds = append(inbounds, obj{
			"tag": "dial-" + l.Name, "listen": "127.0.0.1", "port": ports[l.Name], "protocol": "tunnel",
			"settings": obj{"address": host, "port": p, "network": "tcp"},
		})
		outbounds = append(outbounds, r.linkOutbound(l, peer.Endpoint(l.Endpoint)))
		rules = append(rules, obj{"inboundTag": []any{"dial-" + l.Name}, "outboundTag": "link-" + l.Name})
	}
	rules = append(rules, linkRules...)
	rules = append(rules, r.egressRules(clientsAt)...)
	rules = append(rules, clientRules...)
	if len(endpointTags) > 0 {
		rules = append(rules, obj{"inboundTag": endpointTags, "outboundTag": TagBlock})
	}

	if cs := r.clientSOCKS(); cs != nil {
		host, port, _ := net.SplitHostPort(cs.Listen)
		p, _ := strconv.Atoi(port)
		for _, u := range cs.Users {
			outbounds = append(outbounds, obj{
				"tag": "client-" + u.Name, "protocol": "socks",
				"settings": obj{"servers": []any{obj{"address": host, "port": p, "users": []any{obj{"user": u.Name, "pass": u.Password}}}}},
			})
		}
	}
	proxies := slices.Clone(n.Proxies)
	slices.SortFunc(proxies, func(a, b model.Proxy) int { return cmp.Compare(a.Name, b.Name) })
	for _, p := range proxies {
		o := maps.Clone(p.Outbound)
		o["tag"] = "proxy-" + p.Name
		outbounds = append(outbounds, o)
	}

	if inbounds == nil {
		inbounds = []any{}
	}
	if rules == nil {
		rules = []any{}
	}
	return obj{
		"log":       obj{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   obj{"domainStrategy": "AsIs", "rules": rules},
	}
}

func (r *renderer) endpointInbound(e *model.Endpoint, links []*model.Link, clients []*model.Client) obj {
	in := obj{"tag": inboundTag(e), "listen": cmp.Or(e.Listen, "0.0.0.0"), "port": e.Port}
	if e.Transport == model.TransportSOCKS {
		var accounts []any
		for _, l := range links {
			accounts = append(accounts, obj{"user": "link-" + l.Name, "pass": l.UUID})
		}
		in["protocol"] = "socks"
		in["settings"] = obj{"auth": "password", "accounts": accounts, "udp": false}
		return in
	}
	f := flow(e)
	var users []any
	var shortIDs []string
	for _, l := range links {
		users = append(users, vlessUser(l.UUID, linkEmail(l), f, false))
		shortIDs = append(shortIDs, l.ShortID)
	}
	for _, c := range clients {
		users = append(users, vlessUser(c.UUID, clientEmail(c), f, false))
		shortIDs = append(shortIDs, c.ShortID)
	}
	in["protocol"] = "vless"
	in["settings"] = obj{"decryption": "none", "clients": users}
	ss := streamBase(e)
	switch e.Transport {
	case model.TransportReality:
		slices.Sort(shortIDs)
		ids := []any{}
		for _, s := range slices.Compact(shortIDs) {
			ids = append(ids, s)
		}
		names := []any{}
		for _, s := range e.Reality.ServerNames {
			names = append(names, s)
		}
		ss["security"] = "reality"
		ss["realitySettings"] = obj{
			"target": e.Reality.Target, "serverNames": names,
			"privateKey": e.Reality.PrivateKey, "shortIds": ids,
		}
	case model.TransportTLS:
		ss["security"] = "tls"
		ss["tlsSettings"] = obj{
			"serverName":   e.TLS.ServerName,
			"certificates": []any{obj{"certificateFile": e.TLS.CertFile, "keyFile": e.TLS.KeyFile}},
		}
	}
	in["streamSettings"] = ss
	return in
}

func streamBase(e *model.Endpoint) obj {
	ss := obj{"network": cmp.Or(e.Network, "raw")}
	if e.Network == "xhttp" {
		ss["xhttpSettings"] = obj{"path": cmp.Or(e.Path, "/")}
	}
	return ss
}

func (r *renderer) linkOutbound(l *model.Link, e *model.Endpoint) obj {
	out := obj{"tag": "link-" + l.Name}
	var ss obj
	if e.Transport == model.TransportSOCKS {
		out["protocol"] = "socks"
		out["settings"] = obj{"servers": []any{obj{
			"address": e.Address, "port": e.Port,
			"users": []any{obj{"user": "link-" + l.Name, "pass": l.UUID}},
		}}}
		ss = obj{}
	} else {
		out["protocol"] = "vless"
		out["settings"] = obj{"vnext": []any{obj{
			"address": e.Address, "port": e.Port,
			"users": []any{vlessUser(l.UUID, "", flow(e), true)},
		}}}
		ss = streamBase(e)
		switch e.Transport {
		case model.TransportReality:
			pub, _ := model.RealityPublicKey(e.Reality.PrivateKey)
			ss["security"] = "reality"
			ss["realitySettings"] = obj{
				"serverName": e.Reality.ServerNames[0], "fingerprint": cmp.Or(e.Reality.Fingerprint, "chrome"),
				"password": pub, "shortId": l.ShortID,
			}
		case model.TransportTLS:
			ss["security"] = "tls"
			ss["tlsSettings"] = obj{"serverName": e.TLS.ServerName, "fingerprint": cmp.Or(e.TLS.Fingerprint, "chrome")}
		}
	}
	so := obj{}
	if l.Interface != "" {
		so["interface"] = l.Interface
	}
	if l.Mark != 0 {
		so["mark"] = l.Mark
	}
	if l.DialerProxy != "" {
		so["dialerProxy"] = "proxy-" + l.DialerProxy
	}
	if len(so) > 0 {
		ss["sockopt"] = so
	}
	if len(ss) > 0 {
		out["streamSettings"] = ss
	}
	return out
}

// egressRules renders the Xray rule fragments of egress policies for the
// clients they match, restricted to those clients unless the fragment sets
// inboundTag or user itself.
func (r *renderer) egressRules(clientsAt map[string][]*model.Client) []any {
	var out []any
	for _, e := range r.spec.Egress {
		if len(e.XrayRules) == 0 {
			continue
		}
		var users, tags []any
		for _, ep := range slices.Sorted(maps.Keys(clientsAt)) {
			matched := false
			for _, c := range clientsAt[ep] {
				if r.matchesAny(e.Sources, c.Name) {
					users = append(users, clientEmail(c))
					matched = true
				}
			}
			if matched {
				tags = append(tags, "in-"+ep)
			}
		}
		if len(users) == 0 {
			continue
		}
		for _, frag := range e.XrayRules {
			rule := maps.Clone(frag)
			if _, ok := rule["inboundTag"]; !ok {
				rule["inboundTag"] = tags
			}
			if _, ok := rule["user"]; !ok {
				rule["user"] = users
			}
			out = append(out, rule)
		}
	}
	return out
}

// ShareLink returns the vless:// URI a standard client imports.
func ShareLink(s *model.Spec, client string) (string, error) {
	c := s.Client(client)
	if c == nil {
		return "", model.ErrNotFound
	}
	e := s.Node(c.Node).Endpoint(c.Endpoint)
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", map[string]string{"raw": "tcp", "": "tcp", "xhttp": "xhttp"}[e.Network])
	if e.Network == "xhttp" {
		q.Set("path", cmp.Or(e.Path, "/"))
	}
	if f := flow(e); f != "" {
		q.Set("flow", f)
	}
	switch e.Transport {
	case model.TransportReality:
		pub, err := model.RealityPublicKey(e.Reality.PrivateKey)
		if err != nil {
			return "", err
		}
		q.Set("security", "reality")
		q.Set("sni", e.Reality.ServerNames[0])
		q.Set("fp", cmp.Or(e.Reality.Fingerprint, "chrome"))
		q.Set("pbk", pub)
		q.Set("sid", c.ShortID)
	case model.TransportTLS:
		q.Set("security", "tls")
		q.Set("sni", e.TLS.ServerName)
		q.Set("fp", cmp.Or(e.TLS.Fingerprint, "chrome"))
	default:
		q.Set("security", "none")
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(c.UUID),
		Host:     net.JoinHostPort(e.Address, strconv.Itoa(e.Port)),
		RawQuery: q.Encode(),
		Fragment: c.Name,
	}
	return u.String(), nil
}
