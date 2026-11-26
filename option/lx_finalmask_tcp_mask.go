package option

import "encoding/json"

// LXFinalMaskTCPMaskOptions is an ordered Xray-style TCP mask entry.
// Settings are decoded strictly by the selected mask compiler.
type LXFinalMaskTCPMaskOptions struct {
	Type string `json:"type"`
	Settings json.RawMessage `json:"settings"`
}
