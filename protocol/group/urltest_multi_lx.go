package group

// LX redundant URLTest probes: a node is healthy if any configured endpoint
// responds. All endpoints are bounded by the same per-node timeout; the first
// success cancels the remaining probes. Unconfigured groups use the unchanged
// single URLTest path.

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

type endpointResult struct {
	delay uint16
	err   error
}

func probeAnyURL(ctx context.Context, links []string, node adapter.Outbound) (uint16, error) {
	if len(links) == 0 {
		return urltest.URLTest(ctx, "", node)
	}
	if len(links) == 1 {
		return urltest.URLTest(ctx, links[0], node)
	}
	return probeURLs(ctx, links, func(runCtx context.Context, link string) (uint16, error) {
		return urltest.URLTest(runCtx, link, node)
	})
}

// probeURLs is split from the outbound implementation to test the cancellation
// and any-success policy without network traffic.
func probeURLs(ctx context.Context, links []string, probe func(context.Context, string) (uint16, error)) (uint16, error) {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan endpointResult, len(links))
	for _, link := range links {
		link := link
		go func() {
			delay, err := probe(probeCtx, link)
			results <- endpointResult{delay: delay, err: err}
		}()
	}
	var failures []error
	for i := 0; i < len(links); i++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case result := <-results:
			if result.err == nil {
				return result.delay, nil
			}
			failures = append(failures, result.err)
		}
	}
	return 0, errors.Join(failures...)
}
