package link

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ Link = (*TrojanQt5)(nil)

func init() {
	common.Must(RegisterParser(&Parser{
		Name:   "Trojan-Qt5",
		Scheme: []string{"trojan"},
		Parse: func(u *url.URL) (Link, error) {
			return ParseTrojanQt5(u)
		},
	}))
}

// TrojanQt5 represents a parsed Trojan-Qt5 link
type TrojanQt5 struct {
	Remarks       string
	Address       string
	Port          uint16
	Password      string
	AllowInsecure bool
	TFO           bool

	Type string
	Host string
	Path string

	TLS bool
	SNI string
}

// Outbound implements Link
func (l *TrojanQt5) Outbound() (*option.Outbound, error) {
	out := &option.Outbound{
		Type: C.TypeTrojan,
		Tag:  l.Remarks,
		TrojanOptions: option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     l.Address,
				ServerPort: l.Port,
			},
			Password: l.Password,
			DialerOptions: option.DialerOptions{
				TCPFastOpen: l.TFO,
			},
		},
	}
	if l.TLS {
		out.TrojanOptions.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: l.SNI,
			Insecure:   l.AllowInsecure,
		}
	}
	opt := &option.V2RayTransportOptions{
		Type: l.Type,
	}
	switch l.Type {
	case "":
		opt = nil
	case C.V2RayTransportTypeHTTP:
		opt.HTTPOptions.Path = l.Path
		if l.Host != "" {
			opt.HTTPOptions.Host = []string{l.Host}
			opt.HTTPOptions.Headers["Host"] = []string{l.Host}
		}
	case C.V2RayTransportTypeWebsocket:
		opt.WebsocketOptions.Path = l.Path
		opt.WebsocketOptions.Headers = map[string]option.Listable[string]{
			"Host": {l.Host},
		}
	case C.V2RayTransportTypeGRPC:
		opt.GRPCOptions.ServiceName = l.Path
	}
	out.TrojanOptions.Transport = opt
	return out, nil
}

// ParseTrojanQt5 parses a Trojan-Qt5 link
//
// trojan://password@domain:port?allowinsecure=value&tfo=value#remarks
func ParseTrojanQt5(u *url.URL) (*TrojanQt5, error) {
	if u.Scheme != "trojan" {
		return nil, E.New("not a trojan-qt5 link")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		return nil, E.Cause(err, "invalid port")
	}
	link := &TrojanQt5{}
	link.Address = u.Hostname()
	link.Port = uint16(port)
	link.Remarks = u.Fragment
	if uname := u.User.Username(); uname != "" {
		password, err := url.QueryUnescape(uname)
		if err != nil {
			return nil, err
		}
		link.Password = password
	}
	queries := u.Query()
	for key, values := range queries {
		switch strings.ToLower(key) {
		case "allowinsecure":
			switch values[0] {
			case "0":
				link.AllowInsecure = false
			default:
				link.AllowInsecure = true
			}
		case "tfo":
			switch values[0] {
			case "0":
				link.TFO = false
			default:
				link.TFO = true
			}
		case "type":
			link.Type = values[0]
		case "host":
			link.Host = values[0]
		case "path":
			link.Path = values[0]
		case "servicename":
			link.Path = values[0]
		case "security":
			link.TLS = values[0] == "tls"
		case "sni":
			link.SNI = values[0]
		}
	}
	return link, nil
}

// URL implements Link
func (l *TrojanQt5) URL() (string, error) {
	var uri url.URL
	uri.Scheme = "trojan"
	uri.Host = fmt.Sprintf("%s:%d", l.Address, l.Port)
	uri.User = url.User(url.QueryEscape(l.Password))
	uri.Fragment = l.Remarks
	query := uri.Query()
	if l.AllowInsecure {
		query.Set("allowInsecure", "1")
	}
	if l.TFO {
		query.Set("tfo", "1")
	}
	query.Set("type", l.Type)
	query.Set("host", l.Host)
	switch l.Type {
	case C.V2RayTransportTypeHTTP:
		query.Set("path", l.Path)
	case C.V2RayTransportTypeWebsocket:
		query.Set("path", l.Path)
	case C.V2RayTransportTypeGRPC:
		query.Set("serviceName", l.Path)
	}
	if l.TLS {
		query.Set("security", "tls")
		query.Set("sni", l.SNI)
	}
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}
