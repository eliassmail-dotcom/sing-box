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
	Length   string   `json:"length,omitempty"`
	Lengths  []string `json:"lengths,omitempty"`
	Delay    string `json:"delay"`
	MaxSplit string `json:"max_split,omitempty"`
}

// LXFinalMaskLengthRange describes a TLS record payload length in bytes.
type LXFinalMaskLengthRange struct {
	Min, Max int
}

func (o *LXFinalMaskFragmentOptions) LengthRanges() ([]LXFinalMaskLengthRange, error) {
	if o == nil {
		return nil, nil
	}
	if o.Packets != "tlshello" || o.Delay != "0" {
		return nil, fmt.Errorf("finalmask_fragment supports packets=tlshello and delay=0 only")
	}
	values := o.Lengths
	if len(values) == 0 {
		values = []string{o.Length}
	}
	if len(values) > 256 {
		return nil, fmt.Errorf("finalmask_fragment supports at most 256 length ranges")
	}
	ranges := make([]LXFinalMaskLengthRange, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid finalmask_fragment length")
		}
		lo, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid finalmask_fragment length")
		}
		hi := lo
		if len(parts) == 2 {
			hi, err = strconv.Atoi(parts[1])
		}
		if err != nil || lo < 1 || hi < lo || hi > 16384 {
			return nil, fmt.Errorf("invalid finalmask_fragment length bounds")
		}
		ranges = append(ranges, LXFinalMaskLengthRange{Min: lo, Max: hi})
	}
	return ranges, nil
}

// Bounds retains the existing single-range API. The connection uses LengthRanges.
func (o *LXFinalMaskFragmentOptions) Bounds() (int, int, error) {
	ranges, err := o.LengthRanges()
	if err != nil || len(ranges) == 0 {
		return 0, 0, err
	}
	return ranges[0].Min, ranges[0].Max, nil
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
