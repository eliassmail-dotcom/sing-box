package option

// LXFinalMaskQUICParams follows Xray's field names inside the opt-in
// quic_params block. Zero values leave the transport defaults unchanged.
type LXFinalMaskQUICParams struct {
	Congestion string `json:"congestion,omitempty"`
	BrutalUp string `json:"brutalUp,omitempty"`
	BrutalDown string `json:"brutalDown,omitempty"`
	BrutalDisableLossCompensation bool `json:"brutalDisableLossCompensation,omitempty"`
	BBRProfile string `json:"bbrProfile,omitempty"`
	InitStreamReceiveWindow uint64 `json:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow uint64 `json:"maxStreamReceiveWindow,omitempty"`
	InitConnectionReceiveWindow uint64 `json:"initConnectionReceiveWindow,omitempty"`
	MaxConnectionReceiveWindow uint64 `json:"maxConnectionReceiveWindow,omitempty"`
	MaxIdleTimeout int64 `json:"maxIdleTimeout,omitempty"`
	KeepAlivePeriod int64 `json:"keepAlivePeriod,omitempty"`
	DisablePathMTUDiscovery bool `json:"disablePathMTUDiscovery,omitempty"`
	DisableChromeParrot bool `json:"disableChromeParrot,omitempty"`
	// DisableGSO selects basic UDP I/O, including disabled ECN/batching/PMTU.
	DisableGSO bool `json:"disableGSO,omitempty"`
	// Client sending of stateless resets is already disabled by default.
	DisableStatelessReset bool `json:"disableStatelessReset,omitempty"`
	MaxIncomingStreams int64 `json:"maxIncomingStreams,omitempty"`
}
