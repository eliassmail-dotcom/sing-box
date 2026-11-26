package option

import "encoding/json"

// LXFinalMaskTCPHeaderOptions is the static/random and capture/reuse client subset of Xray
// header-custom. Transform expressions and server error sequences are rejected.
type LXFinalMaskTCPHeaderOptions struct {
	Clients [][]LXFinalMaskTCPHeaderItem `json:"clients"`
	Servers [][]LXFinalMaskTCPHeaderItem `json:"servers"`
	Errors [][]LXFinalMaskTCPHeaderItem `json:"errors,omitempty"`
}

type LXFinalMaskTCPHeaderItem struct {
	Delay json.RawMessage `json:"delay,omitempty"`
	Rand int `json:"rand,omitempty"`
	RandRange json.RawMessage `json:"randRange,omitempty"`
	Type string `json:"type,omitempty"`
	Packet json.RawMessage `json:"packet,omitempty"`
	Capture string `json:"capture,omitempty"`
	Reuse string `json:"reuse,omitempty"`
	Transform json.RawMessage `json:"transform,omitempty"`
}
