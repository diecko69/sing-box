package link_test

import (
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/common/link"
)

func TestVless(t *testing.T) {
	t.Parallel()
	testCases := []*link.Vless{
		{
			Tag:           "tag WS TLS",
			Server:        "192.168.1.1",
			ServerPort:    443,
			UUID:          "0d39b1fe-a459-4f9d-bcea-e9129b567ce0",
			Transport:     "ws",
			TransportHost: "www.example.com",
			TransportPath: "/path",
			TLS:           true,
			SNI:           "www.example.com",
		},
		{
			Tag:           "tag WS NTLS",
			Server:        "192.168.1.1",
			ServerPort:    80,
			UUID:          "0d39b1fe-a459-4f9d-bcea-e9129b567ce0",
			Transport:     "ws",
			TransportHost: "www.example.com",
			TransportPath: "/path",
			TLS:           false,
		},
		{
			Tag:           "tag gRPC TLS",
			Server:        "192.168.1.1",
			ServerPort:    443,
			UUID:          "0d39b1fe-a459-4f9d-bcea-e9129b567ce0",
			Transport:     "grpc",
			TransportHost: "www.example.com",
			TransportPath: "service-Name",
			TLS:           true,
			SNI:           "www.example.com",
		},
	}
	for i, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprint("#", i), func(t *testing.T) {
			t.Parallel()
			uri, err := tc.URL()
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			link, err := link.ParseVless(u)
			if err != nil {
				t.Fatal(err)
				return
			}
			if !reflect.DeepEqual(link, tc) {
				t.Errorf("want %#v, got %#v", tc, link)
			}
		})
	}
}
