package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ ResolveDialer               = (*resolveDialer)(nil)
	_ ResolveDialer               = (*resolveParallelNetworkDialer)(nil)
	_ ParallelNetworkDialer       = (*resolveParallelNetworkDialer)(nil)
	_ PacketDialerWithDestination = (*resolveParallelNetworkDialer)(nil)
)

type ResolveDialer interface {
	N.Dialer
	QueryOptions() adapter.DNSQueryOptions
}

type resolveDialer struct {
	transport     adapter.DNSTransportManager
	router        adapter.DNSRouter
	dialer        N.Dialer
	parallel      bool
	server        string
	initOnce      sync.Once
	initErr       error
	queryOptions  adapter.DNSQueryOptions
	fallbackDelay time.Duration
	ipRace *lxIPRace
	adaptiveVerifiedTCP bool // native direct VLESS REALITY only
}

func NewResolveDialer(ctx context.Context, dialer N.Dialer, parallel bool, server string, queryOptions adapter.DNSQueryOptions, fallbackDelay time.Duration) ResolveDialer {
	if parallelDialer, isParallel := dialer.(ParallelNetworkDialer); isParallel {
		return &resolveParallelNetworkDialer{
			resolveDialer{
				transport:     service.FromContext[adapter.DNSTransportManager](ctx),
				router:        service.FromContext[adapter.DNSRouter](ctx),
				dialer:        dialer,
				parallel:      parallel,
				server:        server,
				queryOptions:  queryOptions,
				fallbackDelay: fallbackDelay,
			},
			parallelDialer,
		}
	}
	return &resolveDialer{
		transport:     service.FromContext[adapter.DNSTransportManager](ctx),
		router:        service.FromContext[adapter.DNSRouter](ctx),
		dialer:        dialer,
		parallel:      parallel,
		server:        server,
		queryOptions:  queryOptions,
		fallbackDelay: fallbackDelay,
	}
}

type resolveParallelNetworkDialer struct {
	resolveDialer
	dialer ParallelNetworkDialer
}

func (d *resolveDialer) initialize() error {
	d.initOnce.Do(d.initServer)
	return d.initErr
}

func (d *resolveDialer) initServer() {
	if d.server == "" {
		return
	}
	transport, loaded := d.transport.Transport(d.server)
	if !loaded {
		d.initErr = E.New("domain resolver not found: " + d.server)
		return
	}
	d.queryOptions.Transport = transport
}

func (d *resolveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	generation := d.ipRace.currentGeneration()
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.lookupLx(ctx, destination.Fqdn) // lx: SPEC 139 — d.router.Lookup inside a `lookup` stage
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, E.New("DNS returned no IP addresses for ", destination.Fqdn)
	}
	if d.ipRace != nil && N.NetworkName(network) == N.NetworkTCP && len(addresses) > 1 {
		return d.ipRace.dialAtGeneration(ctx, destination, addresses, addresses[0].Is6(), generation, false,
			func(raceCtx context.Context, address netip.Addr) (net.Conn, error) {
				return d.dialer.DialContext(raceCtx, network, M.SocksaddrFrom(address, destination.Port))
			})
	}
	if d.parallel {
		return N.DialParallel(ctx, d.dialer, network, destination, addresses, addresses[0].Is6(), d.fallbackDelay)
	} else {
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
}

func (d *resolveDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, destinationAddress, err := d.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if !destinationAddress.IsValid() {
		return conn, nil
	}
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *resolveDialer) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	err := d.initialize()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if !destination.IsDomain() {
		conn, err := d.dialer.ListenPacket(ctx, destination)
		return conn, netip.Addr{}, err
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.lookupLx(ctx, destination.Fqdn) // lx: SPEC 139 — d.router.Lookup inside a `lookup` stage
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return N.ListenSerial(ctx, d.dialer, destination, addresses)
}

func (d *resolveDialer) QueryOptions() adapter.DNSQueryOptions {
	return d.queryOptions
}

// ResetTCPConcurrentHistory clears transient IP preferences after a Wi-Fi,
// cellular or routing-interface change. The embedded parallel resolve dialer
// inherits this method.
func (d *resolveDialer) ResetTCPConcurrentHistory() {
	if d.ipRace != nil {
		d.ipRace.resetHistory()
	}
}

func (d *resolveDialer) Upstream() any {
	return d.dialer
}

func (d *resolveParallelNetworkDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.IsDomain() {
		return d.DialParallelNetwork(ctx, network, destination, nil, nil, nil, nil, 0)
	}
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	return d.dialer.DialContext(ctx, network, destination)
}

func (d *resolveParallelNetworkDialer) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	// A caller-provided list has no DNS-generation provenance. Keep the
	// upstream path for it rather than populating the authenticated race cache.
	resolvedHere := len(destinationAddresses) == 0 && destination.IsDomain()
	generation := d.ipRace.currentGeneration()
	if resolvedHere {
		ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
		destinationAddresses, err = d.lookupLx(ctx, destination.Fqdn) // lx: SPEC 139 — d.router.Lookup inside a `lookup` stage
		if err != nil {
			return nil, err
		}
		if len(destinationAddresses) == 0 {
			return nil, E.New("DNS returned no IP addresses for ", destination.Fqdn)
		}
	}
	if fallbackDelay == 0 {
		fallbackDelay = d.fallbackDelay
	}
	if resolvedHere && d.ipRace != nil && N.NetworkName(network) == N.NetworkTCP && len(destinationAddresses) > 1 {
		return d.ipRace.dialAtGeneration(ctx, destination, destinationAddresses, destinationAddresses[0].Is6(), generation, false,
			func(raceCtx context.Context, address netip.Addr) (net.Conn, error) {
				return d.dialer.DialParallelNetwork(raceCtx, network, destination, []netip.Addr{address}, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
			})
	}
	if d.parallel || len(destinationAddresses) <= 1 {
		return d.dialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	var errors []error
	for _, address := range destinationAddresses {
		conn, err := d.dialer.DialParallelNetwork(ctx, network, destination, []netip.Addr{address}, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
		if err == nil {
			return conn, nil
		}
		errors = append(errors, err)
	}
	return nil, E.Errors(errors...)
}

func (d *resolveParallelNetworkDialer) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	err := d.initialize()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if len(destinationAddresses) == 0 && destination.IsDomain() {
		ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
		destinationAddresses, err = d.lookupLx(ctx, destination.Fqdn) // lx: SPEC 139 — d.router.Lookup inside a `lookup` stage
		if err != nil {
			return nil, netip.Addr{}, err
		}
	}
	if fallbackDelay == 0 {
		fallbackDelay = d.fallbackDelay
	}
	return d.dialer.ListenSerialNetworkPacket(ctx, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
}

// Only forward the explicit ICMP socket capability. Never unwrap a
// detour into a direct connection, and never invoke a DNS fallback.
func(d *resolveDialer)ListenXICMP(ctx context.Context,destination netip.Addr,dgram bool)(net.PacketConn,error){
	if upstream,ok:=d.dialer.(interface{ListenXICMP(context.Context,netip.Addr,bool)(net.PacketConn,error)});ok{
		return upstream.ListenXICMP(ctx,destination,dgram)
	}
	return nil,E.New("XICMP requires a direct ICMP-capable dialer")
}
