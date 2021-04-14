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
	"github.com/protolambda/go-kzg/bls"
)

// Configuration needed for the VerkleTrie
type TreeConfig struct {
	width     int // number of key bits spanned by a node
	nodeWidth int // Number of children in an internal node
}

// Configuration needed for KZG10
type KZGConfig struct {
	width             int
	omegaIs           []bls.Fr // List of the root of unity
	inverses          []bls.Fr // List of all 1 / (1 - ωⁱ)
	nodeWidthInversed bls.Fr   // Inverse of node width in prime field
	lg1               []bls.G1Point
}

func InitTreeConfig(width int) *TreeConfig {
	tc := &TreeConfig{
		width:     width,
		nodeWidth: 1 << width,
	}

	return tc
}

func InitKZGConfig(width int, lg1 []bls.G1Point) *KZGConfig {
	nodeWidth := 1 << width
	kz := &KZGConfig{}
	kz.omegaIs = make([]bls.Fr, nodeWidth)
	kz.inverses = make([]bls.Fr, nodeWidth)
	kz.lg1 = lg1
	kz.width = width

	// Calculate the lagrangian evaluation basis.
	var tmp bls.Fr
	bls.CopyFr(&tmp, &bls.ONE)
	for i := 0; i < nodeWidth; i++ {
		bls.CopyFr(&kz.omegaIs[i], &tmp)
		bls.MulModFr(&tmp, &tmp, &bls.Scale2RootOfUnity[10])
	}

	// Compute all 1 / (1 - ωⁱ)
	bls.CopyFr(&kz.inverses[0], &bls.ZERO)
	for i := 1; i < nodeWidth; i++ {
		var tmp bls.Fr
		bls.SubModFr(&tmp, &bls.ONE, &kz.omegaIs[i])
		bls.DivModFr(&kz.inverses[i], &bls.ONE, &tmp)
	}

	bls.AsFr(&kz.nodeWidthInversed, uint64(nodeWidth))
	bls.InvModFr(&kz.nodeWidthInversed, &kz.nodeWidthInversed)

	return kz
}

// Compute a function in eval form at one of the points in the domain
func (kz *KZGConfig) innerQuotients(f []bls.Fr, index int) []bls.Fr {
	nodeWidth := 1 << kz.width
	q := make([]bls.Fr, nodeWidth)

	y := f[index]
	for i := 0; i < nodeWidth; i++ {
		if i != index {
			omegaIdx := (len(kz.omegaIs) - i) % len(kz.omegaIs)
			invIdx := (index + nodeWidth - i) % nodeWidth
			iMinIdx := (i - index + nodeWidth) % nodeWidth

			// calculate q[i]
			var tmp bls.Fr
			bls.SubModFr(&tmp, &f[i], &y)
			bls.MulModFr(&tmp, &tmp, &kz.omegaIs[omegaIdx])
			bls.MulModFr(&q[i], &tmp, &kz.inverses[invIdx])

			// calculate q[i]'s contribution to q[index]
			bls.MulModFr(&tmp, &kz.omegaIs[iMinIdx], &q[i])
			bls.SubModFr(&tmp, &bls.ZERO, &tmp)
			bls.AddModFr(&q[index], &q[index], &tmp)
		}
	}

	return q[:]
}

// Compute a function in eval form at a point outside of the domain
func (kz *KZGConfig) outerQuotients(f []bls.Fr, z, y *bls.Fr) []bls.Fr {
	nodeWidth := 1 << kz.width
	q := make([]bls.Fr, nodeWidth)

	for i := 0; i < nodeWidth; i++ {
		var tmp, quo bls.Fr
		bls.SubModFr(&tmp, &f[i], y)
		bls.SubModFr(&quo, &kz.omegaIs[i], z)
		bls.DivModFr(&q[i], &tmp, &quo)
	}

	return q[:]
}
