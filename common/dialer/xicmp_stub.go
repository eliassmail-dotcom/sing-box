//go:build !unix

package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func(d *DefaultDialer)ListenXICMP(context.Context,netip.Addr,bool)(net.PacketConn,error){
	return nil,errors.New("XICMP socket carrier unsupported on this platform")
}
