package dialer

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	N "github.com/sagernet/sing/common/network"
)

func New(router adapter.Router, options option.DialerOptions) N.Dialer {
	var dialer N.Dialer
	if options.Detour == "" {
		dialer = NewDefault(router, options)
	} else {
		dialer = NewDetour(router, options.Detour)
	}
	domainStrategy := dns.DomainStrategy(options.DomainStrategy)
	if domainStrategy != dns.DomainStrategyAsIS || options.Detour == "" {
		dialer = NewResolveDialer(router, dialer, domainStrategy, time.Duration(options.FallbackDelay))
	}
	return dialer
}

func NewRedirectable(router adapter.Router, tag string, options option.DialerOptions) N.Dialer {
	var dialer N.Dialer
	if options.Detour == "" {
		dialer = NewDefault(router, options)
		dialer = NewChainRedirectDialer(tag, dialer, dialer)
	} else {
		dialer = NewDetour(router, options.Detour)
		dialer = NewChainRedirectDialer(tag, dialer, NewDefault(router, options))
	}
	domainStrategy := dns.DomainStrategy(options.DomainStrategy)
	if domainStrategy != dns.DomainStrategyAsIS || options.Detour == "" {
		dialer = NewResolveDialer(router, dialer, domainStrategy, time.Duration(options.FallbackDelay))
	}
	return dialer
}
