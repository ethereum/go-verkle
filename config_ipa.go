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
	"fmt"
	"io/ioutil"

	"github.com/crate-crypto/go-ipa/bandersnatch"
	"github.com/crate-crypto/go-ipa/ipa"
)

type IPAConfig struct {
	conf *ipa.IPAConfig
}

type Config = IPAConfig

func (ipac *IPAConfig) CommitToPoly(poly []Fr, _ int) *Point {
	ret := ipac.conf.Commit(poly)
	return &ret
}

var cfg *Config

const precompFileName = "precomp"

func GetConfig() (*Config, error) {
	if cfg == nil {
		var ipacfg *ipa.IPAConfig
		if precompSer, err := ioutil.ReadFile(precompFileName); err != nil {
			ipacfg = ipa.NewIPASettings()
			serialized, err := ipacfg.PrecompLag.SerializePrecomputedLagrange()
			if err != nil {
				return nil, fmt.Errorf("error writing serialized precomputed Lagrange points: %w", err)
			} else {
				if err = ioutil.WriteFile(precompFileName, serialized, 0555); err != nil {
					return nil, fmt.Errorf("error saving the precomp: %w", err)
				}
			}
		} else {
			pcl, err := bandersnatch.DeserializePrecomputedLagrange(precompSer)
			if err != nil {
				return nil, fmt.Errorf("error deserializing precomputed Lagrange points, regenerating")
			}
			ipacfg = ipa.NewIPASettingsWithPrecomputedLagrange(pcl)

		}
		cfg = &IPAConfig{conf: ipacfg}
	}
	return cfg, nil
}

var FrZero Fr
var FrOne Fr

func init() {
	FrZero.SetZero()
	FrOne.SetOne()
}
