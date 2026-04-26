package config

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/wireguard-go/hiddify"
)

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	var overseasTags []string
	var ruRbTags []string
	var bridgeTags []string

	OutboundMainDetour = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	hasPsiphon := false
	for _, out := range input.Outbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
		case C.TypeCustom:
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if out.Type == C.TypePsiphon {
				if hasPsiphon {
					continue
				}
				hasPsiphon = true
			}
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
				class := classifyNode(out.Tag)
				switch class {
				case OutboundOverseasAutoTag:
					overseasTags = append(overseasTags, out.Tag)
				case OutboundRuRbAutoTag:
					ruRbTags = append(ruRbTags, out.Tag)
				case OutboundRuRbBridgeTag:
					bridgeTags = append(bridgeTags, out.Tag)
				}
			}
			out = *patchHiddifyWarpFromConfig(&out, *opt)
			outbounds = append(outbounds, out)
		}
	}

	if opt.Warp.EnableWarp {
		out, err := GenerateWarpSingboxNew("p1", &hiddify.NoiseOptions{})
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		out.Tag = WARPConfigTag
		if opts, ok := out.Options.(*option.WireGuardWARPEndpointOptions); ok {
			if opt.Warp.Mode == "warp_over_proxy" {
				opts.Detour = OutboundSelectTag
				opts.MTU = 1280
			} else {
				opts.Detour = OutboundDirectTag
				opt.MTU = max(opt.MTU, 1340)
			}
		}

		OutboundMainDetour = WARPConfigTag
		out, err = patchEndpoint(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, *out)
	}
	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}
		if opt.Warp.EnableWarp {
			if end.Type == C.TypeWARP {
				if opts, ok := end.Options.(*option.WireGuardWARPEndpointOptions); ok {
					if opts.UniqueIdentifier == "p1" {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
			if end.Type == C.TypeWireGuard {
				if opts, ok := end.Options.(*option.WireGuardEndpointOptions); ok {
					if opts.PrivateKey == opt.Warp.WireguardConfig.PrivateKey {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
		}

		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}

		if !strings.Contains(out.Tag, "§hide§") {
			tags = append(tags, out.Tag)
			class := classifyNode(out.Tag)
			switch class {
			case OutboundOverseasAutoTag:
				overseasTags = append(overseasTags, out.Tag)
			case OutboundRuRbAutoTag:
				ruRbTags = append(ruRbTags, out.Tag)
			case OutboundRuRbBridgeTag:
				bridgeTags = append(bridgeTags, out.Tag)
			}
		}

		endpoints = append(endpoints, *out)
	}
	if len(opt.ConnectionTestUrls) == 0 {
		opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl, "https://www.google.com/generate_204", "http://captive.apple.com/generate_204", "https://cp.cloudflare.com"}
		if isBlockedConnectionTestUrl(opt.ConnectionTestUrl) {
			opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl}
		}
	}

	if len(tags) == 0 {
		tags = append(tags, OutboundDirectTag)
	}

	var activeBalancers []string

	if len(overseasTags) > 0 {
		overseasBalancer := option.Outbound{
			Type: C.TypeBalancer,
			Tag:  OutboundOverseasAutoTag,
			Options: &option.BalancerOutboundOptions{
				Outbounds:                 overseasTags,
				Strategy:                  "lowest-delay",
				DelayAcceptableRatio:      2,
				Tolerance:                 1,
				InterruptExistConnections: true,
			},
		}
		outbounds = append([]option.Outbound{overseasBalancer}, outbounds...)
		activeBalancers = append(activeBalancers, OutboundOverseasAutoTag)
	}

	if len(ruRbTags) > 0 {
		ruRbBalancer := option.Outbound{
			Type: C.TypeBalancer,
			Tag:  OutboundRuRbAutoTag,
			Options: &option.BalancerOutboundOptions{
				Outbounds:                 ruRbTags,
				Strategy:                  "lowest-delay",
				DelayAcceptableRatio:      2,
				Tolerance:                 1,
				InterruptExistConnections: true,
			},
		}
		outbounds = append([]option.Outbound{ruRbBalancer}, outbounds...)
		activeBalancers = append(activeBalancers, OutboundRuRbAutoTag)
	}

	if len(bridgeTags) > 0 {
		bridgeBalancer := option.Outbound{
			Type: C.TypeBalancer,
			Tag:  OutboundRuRbBridgeTag,
			Options: &option.BalancerOutboundOptions{
				Outbounds:                 bridgeTags,
				Strategy:                  "lowest-delay",
				DelayAcceptableRatio:      2,
				Tolerance:                 1,
				InterruptExistConnections: true,
			},
		}
		outbounds = append([]option.Outbound{bridgeBalancer}, outbounds...)
		activeBalancers = append(activeBalancers, OutboundRuRbBridgeTag)
	}

	urlTest := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundURLTestTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:                 tags,
			Strategy:                  "lowest-delay",
			DelayAcceptableRatio:      2,
			Tolerance:                 1,
			InterruptExistConnections: true,
		},
	}

	balancer := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundRoundRobinTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:                 tags,
			Strategy:                  opt.BalancerStrategy,
			DelayAcceptableRatio:      2,
			Tolerance:                 1,
			InterruptExistConnections: true,
		},
	}

	defaultSelect := tags[0]
	manualDefault := ""
	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			manualDefault = tag
			break
		}
	}

	selectorTags := append([]string{}, activeBalancers...)
	if len(tags) > 1 {
		if OutboundMainDetour == WARPConfigTag {
			outbounds = append([]option.Outbound{urlTest}, outbounds...)
			selectorTags = append(selectorTags, urlTest.Tag)
			defaultSelect = urlTest.Tag
		} else {
			outbounds = append([]option.Outbound{balancer, urlTest}, outbounds...)
			selectorTags = append(selectorTags, balancer.Tag, urlTest.Tag)
			defaultSelect = balancer.Tag // Default to Round-Robin to avoid DNS bootstrap deadlock
		}
	} else if len(activeBalancers) > 0 {
		defaultSelect = activeBalancers[0]
	}

	if manualDefault != "" {
		defaultSelect = manualDefault
	}

	selectorTags = append(selectorTags, tags...)

	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector}, outbounds...)

	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:     OutboundDirectTag,
				Type:    C.TypeDirect,
				Options: &option.DirectOutboundOptions{},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						TCPFastOpen: false,

						TLSFragment: option.TLSFragmentOptions{
							Enabled: true,
							Size:    opt.TLSTricks.FragmentSize,
							Sleep:   opt.TLSTricks.FragmentSleep,
						},
					},
				},
			},
		}...,
	)

	return nil
}

func patchHiddifyWarpFromConfig(out *option.Outbound, opt HiddifyOptions) *option.Outbound {
	if out.Type == C.TypePsiphon {
		return out
	}
	if opt.Warp.EnableWarp && opt.Warp.Mode == "proxy_over_warp" {
		if opts, ok := out.Options.(option.DialerOptionsWrapper); ok {
			dialer := opts.TakeDialerOptions()
			dialer.Detour = WARPConfigTag
			opts.ReplaceDialerOptions(dialer)
		}
	}
	return out
}

