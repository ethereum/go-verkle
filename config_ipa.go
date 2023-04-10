// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

package verkle

import (
	"encoding/hex"
	"os"

	"github.com/crate-crypto/go-ipa/ipa"
)

// emptyCodeHashPoint is a cached point that is used to represent an empty code hash.
// This value is initialized once in GetConfig().
var (
	emptyCodeHashPoint           *Point
	emptyCodeHashFirstHalfValue  Fr
	emptyCodeHashSecondHalfValue Fr
)

const (
	codeHashVectorPosition     = 3 // Defined by the spec.
	emptyCodeHashFirstHalfIdx  = codeHashVectorPosition * 2
	emptyCodeHashSecondHalfIdx = emptyCodeHashFirstHalfIdx + 1
)

type IPAConfig struct {
	conf *ipa.IPAConfig
}

type Config = IPAConfig

func (ipac *IPAConfig) CommitToPoly(poly []Fr, _ int) *Point {
	containsEmptyCodeHash := len(poly) >= emptyCodeHashSecondHalfIdx &&
		poly[emptyCodeHashFirstHalfIdx].Equal(&emptyCodeHashFirstHalfValue) &&
		poly[emptyCodeHashSecondHalfIdx].Equal(&emptyCodeHashSecondHalfValue)

	if containsEmptyCodeHash {
		poly[emptyCodeHashFirstHalfIdx] = FrZero
		poly[emptyCodeHashSecondHalfIdx] = FrZero
	}

	ret := ipac.conf.Commit(poly)

	if containsEmptyCodeHash {
		ret.Add(&ret, emptyCodeHashPoint)
		poly[emptyCodeHashFirstHalfIdx] = emptyCodeHashFirstHalfValue
		poly[emptyCodeHashSecondHalfIdx] = emptyCodeHashSecondHalfValue
	}

	return &ret
}

var cfg *Config

const precompFileName = "precomp"

func GetConfig() *Config {
	if cfg == nil {
		var ipacfg *ipa.IPAConfig
		if precompSer, err := os.ReadFile(precompFileName); err != nil {
			ipacfg = ipa.NewIPASettings()
			serialized, err := ipacfg.SRSPrecompPoints.SerializeSRSPrecomp()
			if err != nil {
				panic("error writing serialized precomputed Lagrange points:" + err.Error())
			} else if err = os.WriteFile(precompFileName, serialized, 0666); err != nil {
				panic("error saving the precomp: " + err.Error())
			}
		} else {
			srs, err := ipa.DeserializeSRSPrecomp(precompSer)
			if err != nil {
				panic("error deserializing precomputed Lagrange points:" + err.Error())
			}
			ipacfg = ipa.NewIPASettingsWithSRSPrecomp(srs)
		}
		cfg = &IPAConfig{conf: ipacfg}

		emptyHashCode, _ := hex.DecodeString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
		values := make([][]byte, 256)
		values[codeHashVectorPosition] = emptyHashCode[:]
		var c1poly [256]Fr
		fillSuffixTreePoly(c1poly[:], values[:128])
		emptyCodeHashPoint = cfg.CommitToPoly(c1poly[:], 0)
		emptyCodeHashFirstHalfValue = c1poly[emptyCodeHashFirstHalfIdx]
		emptyCodeHashSecondHalfValue = c1poly[emptyCodeHashSecondHalfIdx]

	}
	return cfg
}

var (
	FrZero Fr
	FrOne  Fr
)

func init() {
	FrZero.SetZero()
	FrOne.SetOne()
}
