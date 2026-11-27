package option

import (
	"fmt"
	"strconv"
	"strings"
)

// LXFinalMaskFragmentOptions is the supported Xray FinalMask tlshello subset.
// Length is a TLS record payload length (bytes), not a TCP segment size.
// A single zero delay merges the records into one underlying write.
type LXFinalMaskFragmentOptions struct {
	Packets  string   `json:"packets"`
	Length   string   `json:"length,omitempty"`
	Lengths  []string `json:"lengths,omitempty"`
	Delay    string   `json:"delay,omitempty"`
	Delays   []string `json:"delays,omitempty"`
	MaxSplit string   `json:"max_split,omitempty"`
}

// LXFinalMaskLengthRange describes a TLS record payload length in bytes.
type LXFinalMaskLengthRange struct {
	Min, Max int
}

func (o *LXFinalMaskFragmentOptions) LengthRanges() ([]LXFinalMaskLengthRange, error) {
	if o == nil {
		return nil, nil
	}
	if o.Packets != "tlshello" {
		return nil, fmt.Errorf("finalmask_fragment supports packets=tlshello only")
	}
	return o.TCPFragmentLengthRanges()
}

// TCPFragmentLengthRanges parses payload lengths shared by TLS and raw TCP masks.
func (o *LXFinalMaskFragmentOptions) TCPFragmentLengthRanges() ([]LXFinalMaskLengthRange, error) {
	if o == nil {
		return nil, nil
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

// DelayRanges returns ordered delay ranges in milliseconds. The last range
// repeats. An omitted delay is equivalent to a single zero.
func (o *LXFinalMaskFragmentOptions) DelayRanges() ([]LXFinalMaskLengthRange, error) {
	if o == nil {
		return nil, nil
	}
	values := o.Delays
	if len(values) == 0 {
		value := o.Delay
		if value == "" {
			value = "0"
		}
		values = []string{value}
	}
	if len(values) > 256 {
		return nil, fmt.Errorf("finalmask_fragment supports at most 256 delay ranges")
	}
	ranges := make([]LXFinalMaskLengthRange, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid finalmask_fragment delay")
		}
		lo, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid finalmask_fragment delay")
		}
		hi := lo
		if len(parts) == 2 {
			hi, err = strconv.Atoi(parts[1])
		}
		if err != nil || lo < 0 || hi < lo || hi > 5000 {
			return nil, fmt.Errorf("invalid finalmask_fragment delay bounds (0-5000 ms)")
		}
		ranges = append(ranges, LXFinalMaskLengthRange{Min: lo, Max: hi})
	}
	return ranges, nil
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
	if _, err := o.DelayRanges(); err != nil {
		return err
	}
	_, _, err := o.MaxSplitBounds()
	return err
}

// TCPPacketRange parses Xray's raw write-index selection. Empty means every
// nonempty Write; indices are one-based. tlshello is a separate TLS mode.
func (o *LXFinalMaskFragmentOptions) TCPPacketRange() (uint64, uint64, error) {
	if o == nil || o.Packets == "" {
		return 0, 0, nil
	}
	parts := strings.Split(o.Packets, "-")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid finalmask TCP packet range")
	}
	lo, err := strconv.ParseUint(parts[0], 10, 31)
	if err != nil || lo == 0 {
		return 0, 0, fmt.Errorf("invalid finalmask TCP packet range")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(parts[1], 10, 31)
	}
	if err != nil || hi < lo {
		return 0, 0, fmt.Errorf("invalid finalmask TCP packet range")
	}
	return lo, hi, nil
}
