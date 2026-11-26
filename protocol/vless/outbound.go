package vless

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/finalmask"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless/encryption"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.VLESSOutboundOptions](registry, C.TypeVLESS, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	client          *vless.Client
	serverAddr      M.Socksaddr
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	tlsDialer       tls.Dialer
	transport       adapter.V2RayClientTransport
	packetAddr      bool
	xudp            bool
	// encryption is the VLESS post-quantum layer, nil unless `encryption` is
	// configured. It wraps the dialed conn beneath the vless client (lx: SPEC 032).
	encryption *encryption.ClientInstance
	ipWarmup *urltest.IPWarmupCoordinator
	ipWarmupEligible bool
	finalMaskTCP *finalmask.TCPFragment
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSOutboundOptions) (adapter.Outbound, error) {
	mask, err := prepareTCPFragment(options)
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeVLESS, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		finalMaskTCP: mask,
		ipWarmup: service.PtrFromContext[urltest.IPWarmupCoordinator](ctx),
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:        ctx,
			Logger:         logger,
			ServerAddress:  options.Server,
			Options:        common.PtrValueOrDefault(options.TLS),
			DomainResolver: options.DomainResolver,
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled &&
				options.Flow == "",
		})
		if err != nil {
			return nil, err
		}
		// lx:begin tls-disabled-dialer
		// NewClientWithOptions returns (nil, nil) for `"tls": {"enabled": false}`;
		// an unconditional NewDialer here wraps that nil config and SIGSEGVs on the
		// first handshake (SPEC 045). Same guard as vmess.
		if outbound.tlsConfig != nil {
			// lx: iOS adaptive verified race, native direct VLESS+REALITY only.
			if options.Transport == nil && options.TLS.Reality != nil && options.TLS.Reality.Enabled && options.Detour == "" && options.TCPConcurrent && options.ServerIsDomain() {
				if adaptive, ok := outboundDialer.(interface{ EnableAdaptiveVerifiedTCP() }); ok {
					adaptive.EnableAdaptiveVerifiedTCP()
					outbound.ipWarmupEligible = outbound.ipWarmup != nil && !common.PtrValueOrDefault(options.Multiplex).Enabled
				}
			}
			outbound.tlsDialer = tls.NewDialer(outboundDialer, outbound.tlsConfig)
			if outbound.ipWarmup != nil && options.Transport == nil && options.TLS.Reality != nil && options.TLS.Reality.Enabled && !tls.DialedThroughDetour(options.DialerOptions) && options.TCPConcurrent && options.ServerIsDomain() {
				outbound.tlsDialer = tls.NewAdaptiveRealityDialerLx(outboundDialer, outbound.tlsConfig, *options.TLS)
			}
		}
		// lx:end tls-disabled-dialer
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outbound.dialer, outbound.serverAddr, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	if options.PacketEncoding == nil {
		outbound.xudp = true
	} else {
		switch *options.PacketEncoding {
		case "":
		case "packetaddr":
			outbound.packetAddr = true
		case "xudp":
			outbound.xudp = true
		default:
			return nil, E.New("unknown packet encoding: ", *options.PacketEncoding)
		}
	}
	// lx: SPEC 032 — set up the post-quantum encryption layer before the vless
	// client, which is unaware of it.
	if options.Encryption != "" && options.Encryption != "none" {
		encryptionConfig, err := parseClientEncryption(options.Encryption)
		if err != nil {
			return nil, E.Cause(err, "parse encryption")
		}
		outbound.encryption = &encryption.ClientInstance{}
		if err := outbound.encryption.Init(encryptionConfig.keys, encryptionConfig.xorMode, encryptionConfig.seconds, encryptionConfig.padding); err != nil {
			return nil, E.Cause(err, "initialize encryption")
		}
	}
	outbound.client, err = vless.NewClient(options.UUID, options.Flow, logger)
	if err != nil {
		return nil, err
	}
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*vlessDialer)(outbound), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	finish := h.beginIPWarmupUse(ctx)
	defer finish()
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*vlessDialer)(h).DialContext(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	finish := h.beginIPWarmupUse(ctx)
	defer finish()
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*vlessDialer)(h).ListenPacket(ctx, destination)
	} else {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *Outbound) MultiplexEnabled() bool {
	if h.multiplexDialer != nil {
		return true
	}
	multiplexTransport, isMultiplexTransport := h.transport.(adapter.V2RayMultiplexClientTransport)
	return isMultiplexTransport && multiplexTransport.MultiplexEnabled()
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	// The cached winning address is valid only for the previous network.
	// Keep the opt-in race isolated from ordinary VLESS connections.
	if resetter, ok := h.dialer.(interface{ ResetTCPConcurrentHistory() }); ok {
		resetter.ResetTCPConcurrentHistory()
	}
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper)
	if isTransportKeeper {
		transportKeeper.SetKeepIdleConnections(keep)
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper)
	if isTransportKeeper {
		transportKeeper.CloseIdleConnections()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.CloseIdleConnections()
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.transport != nil {
		scope.Add(h.transport.Close)
	}
	if h.multiplexDialer != nil {
		scope.Add(h.multiplexDialer.Close)
	}
	return nil
}

type vlessDialer Outbound

func (h *vlessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		return nil, err
	}
	if h.finalMaskTCP != nil {
		conn = h.finalMaskTCP.Wrap(conn)
	}
	conn, err = h.wrapEncryption(ctx, conn)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		if h.xudp {
			return h.client.DialEarlyXUDPPacketConn(conn, destination)
		} else if h.packetAddr {
			if destination.IsDomain() {
				return nil, E.New("packetaddr: domain destination is not supported")
			}
			packetConn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(packetaddr.NewConn(packetConn, destination), destination), nil
		} else {
			return h.client.DialEarlyPacketConn(conn, destination)
		}
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vlessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	if h.finalMaskTCP != nil {
		conn = h.finalMaskTCP.Wrap(conn)
	}
	conn, err = h.wrapEncryption(ctx, conn)
	if err != nil {
		return nil, err
	}
	if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	} else if h.packetAddr {
		if destination.IsDomain() {
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		conn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination)
	}
}

// Keep the first transport-layer integration deliberately limited to plain
// VLESS. Do not shadow the dialer's adaptive verified-race interfaces or stack
// it with a TLS/REALITY mask or an HTTP transport.
func prepareTCPFragment(options option.VLESSOutboundOptions) (*finalmask.TCPFragment, error) {
	if options.FinalMaskTCPFragment == nil {
		return nil, nil
	}
	if options.TLS != nil && (options.TLS.Enabled || options.TLS.FinalMaskFragment != nil) {
		return nil, E.New("finalmask_tcp_fragment: TLS/REALITY is not supported yet")
	}
	if options.Transport != nil || options.Flow != "" {
		return nil, E.New("finalmask_tcp_fragment: only plain VLESS transport without flow is supported")
	}
	return finalmask.NewTCPFragment(options.FinalMaskTCPFragment)
}
