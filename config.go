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
	"bytes"
	"sync"

	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

const (
	multiExpThreshold8 = 25

	NodeWidth    = 256
	NodeBitWidth = 8
)

type KZGConfig struct {
	omegaIs           []bls.Fr // List of the root of unity
	inverses          []bls.Fr // List of all 1 / (1 - ωⁱ)
	nodeWidthInversed bls.Fr   // Inverse of node witdh in prime field
	lg1               []bls.G1Point
}

var (
	config    *KZGConfig
	configMtx sync.Mutex
)

func GetKZGConfig() *KZGConfig {
	configMtx.Lock()
	defer configMtx.Unlock()

	if config != nil {
		return config
	}

	// Hardcode the secret to simplify the API for the
	// moment.
	var s bls.Fr
	bls.SetFr(&s, "8927347823478352432985")

	var sPow bls.Fr
	bls.CopyFr(&sPow, &bls.ONE)

	nChildren := 256
	s1Out := make([]bls.G1Point, nChildren)
	s2Out := make([]bls.G2Point, nChildren)
	for i := 0; i < nChildren; i++ {
		bls.MulG1(&s1Out[i], &bls.GenG1, &sPow)
		bls.MulG2(&s2Out[i], &bls.GenG2, &sPow)
		var tmp bls.Fr
		bls.CopyFr(&tmp, &sPow)
		bls.MulModFr(&sPow, &tmp, &s)
	}

	fftCfg := kzg.NewFFTSettings(8)
	lg1, err := fftCfg.FFTG1(s1Out, true)
	if err != nil {
		panic(err)
	}

	config = initKZGConfig(lg1)
	return config
}

func initKZGConfig(lg1 []bls.G1Point) *KZGConfig {
	tc := &KZGConfig{
		lg1: lg1,
	}
	tc.omegaIs = make([]bls.Fr, NodeWidth)
	tc.inverses = make([]bls.Fr, NodeWidth)

	// Calculate the lagrangian evaluation basis.
	var tmp bls.Fr
	bls.CopyFr(&tmp, &bls.ONE)
	for i := 0; i < NodeWidth; i++ {
		bls.CopyFr(&tc.omegaIs[i], &tmp)
		bls.MulModFr(&tmp, &tmp, &bls.Scale2RootOfUnity[8])
	}

	// Compute all 1 / (1 - ωⁱ)
	bls.CopyFr(&tc.inverses[0], &bls.ZERO)
	for i := 1; i < NodeWidth; i++ {
		var tmp bls.Fr
		bls.SubModFr(&tmp, &bls.ONE, &tc.omegaIs[i])
		bls.DivModFr(&tc.inverses[i], &bls.ONE, &tmp)
	}

	bls.AsFr(&tc.nodeWidthInversed, uint64(NodeWidth))
	bls.InvModFr(&tc.nodeWidthInversed, &tc.nodeWidthInversed)

	return tc
}

// Compute a function in eval form at one of the points in the domain
func (tc *KZGConfig) innerQuotients(f []bls.Fr, index int) []bls.Fr {
	q := make([]bls.Fr, NodeWidth)

	y := f[index]
	for i := 0; i < NodeWidth; i++ {
		if i != index {
			omegaIdx := (len(tc.omegaIs) - i) % len(tc.omegaIs)
			invIdx := (index + NodeWidth - i) % NodeWidth
			iMinIdx := (i - index + NodeWidth) % NodeWidth

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
func (tc *KZGConfig) outerQuotients(f []bls.Fr, z, y *bls.Fr) []bls.Fr {
	q := make([]bls.Fr, NodeWidth)

	for i := 0; i < NodeWidth; i++ {
		var tmp, quo bls.Fr
		bls.SubModFr(&tmp, &f[i], y)
		bls.SubModFr(&quo, &tc.omegaIs[i], z)
		bls.DivModFr(&q[i], &tmp, &quo)
	}

	return q[:]
}

// Evaluate a polynomial in the lagrange basis
func evalPoly(poly []bls.Fr, lg1 []bls.G1Point, emptyChildren int) *bls.G1Point {
	if NodeWidth-emptyChildren >= multiExpThreshold8 {
		return bls.LinCombG1(lg1, poly[:])
	} else {
		var comm bls.G1Point
		bls.CopyG1(&comm, &bls.ZERO_G1)
		for i := range poly {
			if !bls.EqualZero(&poly[i]) {
				var tmpG1, eval bls.G1Point
				bls.MulG1(&eval, &lg1[i], &poly[i])
				bls.CopyG1(&tmpG1, &comm)
				bls.AddG1(&comm, &tmpG1, &eval)
			}
		}
		return &comm
	}
}

func equalPaths(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}

	return bytes.Equal(key1[:31], key2[:31])
}

// offset2key extracts the n bits of a key that correspond to the
// index of a child node.
func offset2key(key []byte, offset int) uint {
	return uint(key[offset/8])
}
