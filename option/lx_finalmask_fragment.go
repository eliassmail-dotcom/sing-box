package option

import (
	"fmt"
	"strconv"
	"strings"
)

// LXFinalMaskFragmentOptions is the supported Xray FinalMask tlshello subset.
// Length is a TLS record payload length (bytes), not a TCP segment size.
// Zero delay merges the records into a single underlying write.
type LXFinalMaskFragmentOptions struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Delay    string `json:"delay"`
	MaxSplit string `json:"max_split,omitempty"`
}

func (o *LXFinalMaskFragmentOptions) Bounds() (int, int, error) {
	if o == nil {
		return 0, 0, nil
	}
	if o.Packets != "tlshello" || o.Delay != "0" {
		return 0, 0, fmt.Errorf("finalmask_fragment supports packets=tlshello and delay=0 only")
	}
	parts := strings.Split(o.Length, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid finalmask_fragment length")
	}
	lo, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid finalmask_fragment length")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.Atoi(parts[1])
	}
	if err != nil || lo < 1 || hi < lo || hi > 16384 {
		return 0, 0, fmt.Errorf("invalid finalmask_fragment length bounds")
	}
	return lo, hi, nil
}
// MaxSplitBounds returns the optional cap on the number of TLS records.
// Zero means unlimited, preserving the original behavior.
func (o *LXFinalMaskFragmentOptions) MaxSplitBounds() (int, int, error) {
	if o == nil || o.MaxSplit == "" {
		return 0, 0, nil
	}
	parts := strings.Split(o.MaxSplit, "-")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid finalmask_fragment max_split")
	}
	lo, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid finalmask_fragment max_split")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.Atoi(parts[1])
	}
	if err != nil || lo < 0 || hi < lo || hi > 16384 {
		return 0, 0, fmt.Errorf("invalid finalmask_fragment max_split bounds")
	}
	return lo, hi, nil
}

func (o *LXFinalMaskFragmentOptions) Validate() error {
	if _, _, err := o.Bounds(); err != nil {
		return err
	}
	_, _, err := o.MaxSplitBounds()
	return err
}
