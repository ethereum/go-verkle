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
	"math/big"

	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

const multiExpThreshold8 = 25

type TreeConfig struct {
	width             int      // number of key bits spanned by a node
	nodeWidth         int      // Number of children in an internal node
	modulus           *big.Int // Field's modulus
	omegaIs           []bls.Fr // List of the root of unity
	inverses          []bls.Fr // List of all 1 / (1 - ωⁱ)
	nodeWidthInversed bls.Fr   // Inverse of node witdh in prime field
	lg1               []bls.G1Point
	// Threshold for using multi exponentiation when
	// computing commitment. Number refers to non-zero
	// children in a node.
	multiExpThreshold int
}

var configs map[int]*TreeConfig

func init() {
	configs = make(map[int]*TreeConfig)
}

func GetTreeConfig(width int) *TreeConfig {
	if cfg, ok := configs[width]; ok {
		return cfg
	}

	// Hardcode the secret to simplify the API for the
	// moment.
	var s bls.Fr
	bls.SetFr(&s, "1927409816240961209460912649124")

	var sPow bls.Fr
	bls.CopyFr(&sPow, &bls.ONE)

	nChildren := 1 << width
	s1Out := make([]bls.G1Point, nChildren, nChildren)
	s2Out := make([]bls.G2Point, nChildren, nChildren)
	for i := 0; i < nChildren; i++ {
		bls.MulG1(&s1Out[i], &bls.GenG1, &sPow)
		bls.MulG2(&s2Out[i], &bls.GenG2, &sPow)
		var tmp bls.Fr
		bls.CopyFr(&tmp, &sPow)
		bls.MulModFr(&sPow, &tmp, &s)
	}

	fftCfg := kzg.NewFFTSettings(uint8(width))
	lg1, err := fftCfg.FFTG1(s1Out, true)
	if err != nil {
		panic(err)
	}

	configs[width] = initTreeConfig(width, lg1)
	return configs[width]
}

func initTreeConfig(width int, lg1 []bls.G1Point) *TreeConfig {
	tc := &TreeConfig{
		width:             width,
		nodeWidth:         1 << width,
		lg1:               lg1,
		multiExpThreshold: multiExpThreshold8,
	}
	if width == 10 {
		tc.multiExpThreshold = multiExpThreshold10
	}
	tc.omegaIs = make([]bls.Fr, tc.nodeWidth)
	tc.inverses = make([]bls.Fr, tc.nodeWidth)

	// Calculate the lagrangian evaluation basis.
	var tmp bls.Fr
	bls.CopyFr(&tmp, &bls.ONE)
	for i := 0; i < tc.nodeWidth; i++ {
		bls.CopyFr(&tc.omegaIs[i], &tmp)
		bls.MulModFr(&tmp, &tmp, &bls.Scale2RootOfUnity[width])
	}

	var ok bool
	tc.modulus, ok = big.NewInt(0).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	if !ok {
		panic("could not get modulus")
	}

	// Compute all 1 / (1 - ωⁱ)
	bls.CopyFr(&tc.inverses[0], &bls.ZERO)
	for i := 1; i < tc.nodeWidth; i++ {
		var tmp bls.Fr
		bls.SubModFr(&tmp, &bls.ONE, &tc.omegaIs[i])
		bls.DivModFr(&tc.inverses[i], &bls.ONE, &tmp)
	}

	bls.AsFr(&tc.nodeWidthInversed, uint64(tc.nodeWidth))
	bls.InvModFr(&tc.nodeWidthInversed, &tc.nodeWidthInversed)

	return tc
}

// Compute a function in eval form at one of the points in the domain
func (tc *TreeConfig) innerQuotients(f []bls.Fr, index int) []bls.Fr {
	q := make([]bls.Fr, tc.nodeWidth)

	y := f[index]
	for i := 0; i < tc.nodeWidth; i++ {
		if i != index {
			omegaIdx := (len(tc.omegaIs) - i) % len(tc.omegaIs)
			invIdx := (index + tc.nodeWidth - i) % tc.nodeWidth
			iMinIdx := (i - index + tc.nodeWidth) % tc.nodeWidth

			// calculate q[i]
			var tmp bls.Fr
			bls.SubModFr(&tmp, &f[i], &y)
			bls.MulModFr(&tmp, &tmp, &tc.omegaIs[omegaIdx])
			bls.MulModFr(&q[i], &tmp, &tc.inverses[invIdx])

			// calculate q[i]'s contribution to q[index]
			bls.MulModFr(&tmp, &tc.omegaIs[iMinIdx], &q[i])
			bls.SubModFr(&tmp, &bls.ZERO, &tmp)
			bls.AddModFr(&q[index], &q[index], &tmp)
		}
	}

	return q[:]
}

// Compute a function in eval form at a point outside of the domain
func (tc *TreeConfig) outerQuotients(f []bls.Fr, z, y *bls.Fr) []bls.Fr {
	q := make([]bls.Fr, tc.nodeWidth)

	for i := 0; i < tc.nodeWidth; i++ {
		var tmp, quo bls.Fr
		bls.SubModFr(&tmp, &f[i], y)
		bls.SubModFr(&quo, &tc.omegaIs[i], z)
		bls.DivModFr(&q[i], &tmp, &quo)
	}

	return q[:]
}
