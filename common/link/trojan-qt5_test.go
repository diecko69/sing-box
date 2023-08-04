package link_test

import (
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/common/link"
)

func TestTrojanQt5(t *testing.T) {
	t.Parallel()
	testCases := []*link.TrojanQt5{
		{
			Remarks:       "remarks WS TLS",
			Address:       "192.168.1.1",
			Port:          443,
			Password:      "password-密码",
			AllowInsecure: true,
			TFO:           true,
			Type:          "ws",
			Host:          "www.example.com",
			Path:          "/path",
			TLS:           true,
			SNI:           "www.example.com",
		},
		{
			Remarks:       "remarks gRPC",
			Address:       "192.168.1.1",
			Port:          443,
			Password:      "33ef9206-117a-48d5-b6e9-e778807a5afb",
			AllowInsecure: false,
			TFO:           false,
			Type:          "grpc",
			Host:          "www.example.com",
			Path:          "grpc-service",
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
			link, err := link.ParseTrojanQt5(u)
			if err != nil {
				t.Error(err)
				return
			}
			if !reflect.DeepEqual(link, tc) {
				t.Errorf("want %#v, got %#v", tc, link)
			}
		})
	}
}
