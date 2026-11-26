//go:build !with_quic

package finalmask

import (
	"crypto/tls"
	"errors"
	"github.com/sagernet/sing-box/option"
	"net/http"

	N "github.com/sagernet/sing/common/network"
)

const xdnsDoH3Available=false

func newXDNSDoH3Transport(N.Dialer,*xdnsConfig,*tls.Config)(http.RoundTripper,func()){
	panic("XDNS DoH HTTP/3 requires with_quic")
}

type xdnsH3Settings struct{}
func compileXDNSH3Params(*option.LXFinalMaskQUICParams)(*xdnsH3Settings,error){
	return nil,errors.New("XDNS HTTP/3 requires with_quic")
}
