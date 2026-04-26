package config

import (
	"net"
	"net/netip"

	"github.com/hiddify/hiddify-core/v2/hutils"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin {
		return true
	}
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}

func setInbound(options *option.Options, hopt *HiddifyOptions) {
	ipv6Enable := isIPv6Supported()
	if hopt.EnableTun {
		opts := option.TunInboundOptions{
			Stack:       hopt.TUNStack,
			MTU:         hopt.MTU,
			AutoRoute:   true,
			StrictRoute: hopt.StrictRoute,
		}
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,
			Options: &opts,
		}

		opts.Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/28")}
		if ipv6Enable {
			opts.Address = append(opts.Address, netip.MustParsePrefix("fdfe:dcba:9876::1/126"))
		}

		options.Inbounds = append(options.Inbounds, tunInbound)
	}

	binds := []string{}

	if hopt.AllowConnectionFromLAN {
		if ipv6Enable {
			binds = append(binds, "::")
		} else {
			binds = append(binds, "0.0.0.0")
		}
	} else {
		if ipv6Enable {
			binds = append(binds, "::1")
		}
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))

		options.Inbounds = append(
			options.Inbounds,
			option.Inbound{
				Type: C.TypeMixed,
				Tag:  InboundMixedTag + bind,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     &addr,
						ListenPort: hopt.MixedPort,
					},
					SetSystemProxy: hopt.SetSystemProxy,
				},
			},
		)
		if C.IsLinux && !C.IsAndroid && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeTProxy,
					Tag:  InboundTProxy + bind,
					Options: &option.TProxyInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.TProxyPort,
						},
					},
				},
			)
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.RedirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeRedirect,
					Tag:  InboundRedirect + bind,
					Options: &option.RedirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.RedirectPort,
						},
					},
				},
			)
		}
		if hopt.DirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeDirect,
					Tag:  InboundDirectTag + bind,
					Options: &option.DirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.DirectPort,
						},
					},
				},
			)
		}
	}
}

