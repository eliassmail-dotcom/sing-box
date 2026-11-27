package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	Outbounds                 []string `json:"outbounds" reference:"outbound"`
	Default                   string   `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds                 []string           `json:"outbounds" reference:"outbound"`
	URL                       string             `json:"url,omitempty"`
	URLs                      []string           `json:"urls,omitempty"`              // LX: any successful endpoint proves node health (max 3)
	TolerancePercent          uint8              `json:"tolerance_percent,omitempty"` // LX: 0=legacy absolute tolerance, 1..100=adaptive relative threshold
	MinHold                   badoption.Duration `json:"min_hold,omitempty"`          // LX: least_test minimum hold for healthy nodes; outages bypass
	Interval                  badoption.Duration `json:"interval,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
	// lx: SPEC 019 v2 — load-balancing.
	Mode     string                  `json:"mode,omitempty"` // least_test (default) | round_robin | failover
	Balancer *URLTestBalancerOptions `json:"balancer,omitempty"`
	// LX: Prefer the listed outbound tags whenever they have successful URL-test history.
	// With least_test this defines a preferred tier; with failover it enables ordered
	// first-healthy fallback in configured order, with recovery to higher tiers.
	// Valid with least_test or failover; tags must also be present in outbounds.
	PriorityOutbounds []string `json:"priority_outbounds,omitempty" reference:"outbound"`
	// Optional middle tier: used after all primary members fail, before other outbounds.
	SecondaryPriorityOutbounds []string `json:"secondary_priority_outbounds,omitempty" reference:"outbound"`
	// LX: opt-in passive stall diagnostics, short node quarantine and suspect dial pacing.
	// Disabled by default; only least_test/failover (not round_robin).
	PassiveGuard bool `json:"passive_guard,omitempty"`
}

// URLTestBalancerOptions configures round_robin: a fixed-size pool of live nodes, lazily
// health-checked, with optional per-flow stickiness. lx: SPEC 019 v2. Required only for
// round_robin (defaults {pool:3, pool_tolerance:0} apply when omitted); set with any other
// mode is an error.
type URLTestBalancerOptions struct {
	Pool          int    `json:"pool,omitempty"`           // rotation pool size, default 3, < 1 is an error
	PoolTolerance uint16 `json:"pool_tolerance,omitempty"` // ms; 0 = first-live-fill, > 0 = top-N-by-delay with eviction threshold
	// StickyHash key components: process|domain|source_ip|dest_ip|dest_port.
	// Omitted → default ["process","domain"]. To DISABLE stickiness use ["none"] — a bare [] is
	// NOT honoured because the config decoder (badjson.UnmarshallExcludedContext) re-marshals
	// the struct and collapses an empty array to nil, indistinguishable from "omitted".
	StickyHash []string `json:"sticky_hash,omitempty"`
}
