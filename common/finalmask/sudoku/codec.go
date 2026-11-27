// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Adapted from XTLS/Xray-core, 676eaf66f8f05d4d558ee7a74b4736623d3feeb9,
// transport/internet/finalmask/sudoku/codec.go. See UPSTREAM.md.

package sudoku

import (
	"fmt"
	"math/rand/v2"
)

var perm4 = [24][4]byte{
	{0, 1, 2, 3},
	{0, 1, 3, 2},
	{0, 2, 1, 3},
	{0, 2, 3, 1},
	{0, 3, 1, 2},
	{0, 3, 2, 1},
	{1, 0, 2, 3},
	{1, 0, 3, 2},
	{1, 2, 0, 3},
	{1, 2, 3, 0},
	{1, 3, 0, 2},
	{1, 3, 2, 0},
	{2, 0, 1, 3},
	{2, 0, 3, 1},
	{2, 1, 0, 3},
	{2, 1, 3, 0},
	{2, 3, 0, 1},
	{2, 3, 1, 0},
	{3, 0, 1, 2},
	{3, 0, 2, 1},
	{3, 1, 0, 2},
	{3, 1, 2, 0},
	{3, 2, 0, 1},
	{3, 2, 1, 0},
}

type codec struct {
	tables        []*table
	rng           *rand.Rand
	paddingChance int
	tableIndex    int
}

func newCodec(tables []*table, pMin, pMax int) *codec {
	if len(tables) == 0 {
		tables = nil
	}
	rng := newSeededRand()
	return &codec{
		tables:        tables,
		rng:           rng,
		paddingChance: pickPaddingChance(rng, pMin, pMax),
	}
}

func pickPaddingChance(rng *rand.Rand, pMin, pMax int) int {
	if pMin < 0 {
		pMin = 0
	}
	if pMax < pMin {
		pMax = pMin
	}
	if pMin > 100 {
		pMin = 100
	}
	if pMax > 100 {
		pMax = 100
	}
	if pMax == pMin {
		return pMin
	}
	return pMin + rng.IntN(pMax-pMin+1)
}

func (c *codec) shouldPad() bool {
	if c.paddingChance <= 0 {
		return false
	}
	if c.paddingChance >= 100 {
		return true
	}
	return c.rng.IntN(100) < c.paddingChance
}

func (c *codec) currentTable() *table {
	if len(c.tables) == 0 {
		return nil
	}
	return c.tables[c.tableIndex%len(c.tables)]
}

func (c *codec) randomPadding(t *table) byte {
	pool := t.layout.paddingPool
	return pool[c.rng.IntN(len(pool))]
}

func (c *codec) encode(in []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := make([]byte, 0, len(in)*6+8)
	for _, b := range in {
		t := c.currentTable()
		if t == nil {
			return nil, fmt.Errorf("sudoku table set missing")
		}
		if c.shouldPad() {
			out = append(out, c.randomPadding(t))
		}

		enc := t.encode[b]
		if len(enc) == 0 {
			return nil, fmt.Errorf("sudoku encode table missing for byte %d", b)
		}

		hints := enc[c.rng.IntN(len(enc))]
		perm := perm4[c.rng.IntN(len(perm4))]
		for _, idx := range perm {
			if c.shouldPad() {
				out = append(out, c.randomPadding(t))
			}
			out = append(out, t.layout.encodeHint(hints[idx]))
		}
		c.tableIndex++
	}

	if c.shouldPad() {
		if t := c.currentTable(); t != nil {
			out = append(out, c.randomPadding(t))
		}
	}

	return out, nil
}

func decodeBytes(tables []*table, tableIndex *int, in []byte, hintBuf []byte, out []byte) ([]byte, []byte, error) {
	if len(tables) == 0 {
		return hintBuf, out, fmt.Errorf("sudoku table set missing")
	}
	for _, b := range in {
		t := tables[*tableIndex%len(tables)]
		if !t.layout.isHint(b) {
			continue
		}

		group, ok := t.layout.decodeGroup(b)
		if !ok {
			return hintBuf[:0], out, fmt.Errorf("invalid sudoku hint byte")
		}
		hintBuf = append(hintBuf, group)
		if len(hintBuf) < 4 {
			continue
		}

		keyBytes := sort4([4]byte{hintBuf[0], hintBuf[1], hintBuf[2], hintBuf[3]})
		key := packKey(keyBytes)
		gridIndex, ok := baseDecode[key]
		if !ok || t.decode[gridIndex] < 0 {
			return hintBuf[:0], out, fmt.Errorf("invalid sudoku hint tuple")
		}

		out = append(out, byte(t.decode[gridIndex]))
		hintBuf = hintBuf[:0]
		*tableIndex++
	}

	return hintBuf, out, nil
}
