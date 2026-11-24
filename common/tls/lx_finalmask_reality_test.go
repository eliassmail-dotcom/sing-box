//go:build with_utls

package tls

import (
	"context"
	"encoding/binary"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLxRealityFinalMaskFirefoxHybrid(t *testing.T) {
	opts := lxRealityOptions("firefox", "hybrid", false, false)
	opts.FinalMaskFragment = &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "10-20", Delay: "0"}
	config, err := NewClientWithOptions(ClientOptions{Context: context.Background(), Logger: logger.NOP(), ServerAddress: "www.example.com", Options: opts})
	require.NoError(t, err)
	c := config.(*RealityClientConfig)
	for _, client := range []*RealityClientConfig{c, c.Clone().(*RealityClientConfig)} {
		wire := lxRealityFirstFlight(t, client)
		records := 0
		for len(wire) > 0 {
			require.GreaterOrEqual(t, len(wire), 5)
			require.Equal(t, byte(22), wire[0])
			n := int(binary.BigEndian.Uint16(wire[3:5]))
			require.Greater(t, n, 0)
			require.LessOrEqual(t, n, 20)
			require.GreaterOrEqual(t, len(wire), 5+n)
			wire = wire[5+n:]
			if len(wire) > 0 {
				require.GreaterOrEqual(t, n, 10)
			}
			records++
		}
		require.Greater(t, records, 60)
	}
}
