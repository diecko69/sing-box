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

var _ Link = (*Vless)(nil)

func init() {
	common.Must(RegisterParser(&Parser{
		Name:   "Vless",
		Scheme: []string{"vless"},
		Parse: func(u *url.URL) (Link, error) {
			return ParseVless(u)
		},
	}))
}

// vless://UUID@SERVER:PORT/?type=TYPE&encryption=none&host=HOST-CDN&path=PATH&security=tls&sni=SNI#REMARK
// vless://UUID@SERVER:PORT/?type=TYPE&encryption=none&host=HOST-CDN&serviceName=SERVICE_NAME&security=tls&sni=SNI#REMARK
type Vless struct {
	Tag        string
	Server     string
	ServerPort uint16
	UUID       string

	Transport     string
	TransportHost string
	TransportPath string

	TLS bool
	SNI string
}

func (vl *Vless) Outbound() (*option.Outbound, error) {
	out := &option.Outbound{
		Type: C.TypeVLESS,
		Tag:  vl.Tag,
		VLESSOptions: option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     vl.Server,
				ServerPort: vl.ServerPort,
			},
			UUID: vl.UUID,
		},
	}
	if vl.TLS {
		out.VLESSOptions.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: vl.SNI,
		}
	}
	opt := &option.V2RayTransportOptions{
		Type: vl.Transport,
	}
	switch vl.Transport {
	case "":
		opt = nil
	case C.V2RayTransportTypeHTTP:
		opt.HTTPOptions.Path = vl.TransportPath
		if vl.TransportHost != "" {
			opt.HTTPOptions.Host = []string{vl.TransportHost}
			opt.HTTPOptions.Headers["Host"] = []string{vl.TransportHost}
		}
	case C.V2RayTransportTypeWebsocket:
		opt.WebsocketOptions.Path = vl.TransportPath
		opt.WebsocketOptions.Headers = map[string]option.Listable[string]{
			"Host": {vl.TransportHost},
		}
	case C.V2RayTransportTypeGRPC:
		opt.GRPCOptions.ServiceName = vl.TransportPath
	}
	out.VLESSOptions.Transport = opt
	return out, nil
}
func (vl *Vless) URL() (string, error) {
	var uri url.URL
	uri.Scheme = "vless"
	uri.Host = fmt.Sprintf("%s:%d", vl.Server, vl.ServerPort)
	uri.User = url.User(url.QueryEscape(vl.UUID))
	uri.Fragment = vl.Tag
	queries := uri.Query()
	queries.Set("type", vl.Transport)
	queries.Set("host", vl.TransportHost)
	switch vl.Transport {
	case C.V2RayTransportTypeHTTP:
		queries.Set("path", vl.TransportPath)
	case C.V2RayTransportTypeWebsocket:
		queries.Set("path", vl.TransportPath)
	case C.V2RayTransportTypeGRPC:
		queries.Set("serviceName", vl.TransportPath)
	}
	if vl.TLS {
		queries.Set("security", "tls")
		queries.Set("sni", vl.SNI)
	}
	uri.RawQuery = queries.Encode()
	return uri.String(), nil
}

func ParseVless(u *url.URL) (*Vless, error) {
	if u.Scheme != "vless" {
		return nil, E.New("not Vless link")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		return nil, E.Cause(err, "invalid port")
	}
	link := &Vless{}
	link.Server = u.Hostname()
	link.ServerPort = uint16(port)
	link.Tag = u.Fragment
	if uname := u.User.Username(); uname != "" {
		uuid, err := url.QueryUnescape(uname)
		if err != nil {
			return nil, err
		}
		link.UUID = uuid
	}
	queries := u.Query()
	for key, value := range queries {
		switch strings.ToLower(key) {
		case "type":
			link.Transport = value[0]
		case "host":
			link.TransportHost = value[0]
		case "path":
			link.TransportPath = value[0]
		case "serviceName":
			link.TransportPath = value[0]
		case "sni":
			link.SNI = value[0]
		case "security":
			link.TLS = value[0] == "tls"
		}
	}
	return link, nil
}
