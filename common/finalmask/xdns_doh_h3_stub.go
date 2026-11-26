//go:build !with_quic

package finalmask

import (
	"crypto/tls"
	"net/http"

	N "github.com/sagernet/sing/common/network"
)

const xdnsDoH3Available=false

func newXDNSDoH3Transport(N.Dialer,*xdnsConfig,*tls.Config)(http.RoundTripper,func()){
	panic("XDNS DoH HTTP/3 requires with_quic")
}
