package option

import "encoding/json"

// LXFinalMaskUDPMaskOptions mirrors the Xray type/settings list.
type LXFinalMaskUDPMaskOptions struct {
	Type string `json:"type"`
	Settings json.RawMessage `json:"settings"`
}
