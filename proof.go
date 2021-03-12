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
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

func calcR(cs []*bls.G1Point, indices []*bls.Fr, ys []*bls.Fr) bls.Fr {
	digest := sha256.New()
	for _, c := range cs {
		digest.Write(bls.ToCompressedG1(c))
	}
	for _, idx := range indices {
		tmp := bls.FrTo32(idx)
		digest.Write(tmp[:])
	}
	for _, y := range ys {
		tmp := bls.FrTo32(y)
		digest.Write(tmp[:])
	}

	var tmp bls.Fr
	bls.FrFrom32(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp

}

func calcT(r bls.Fr, d *bls.G1Point) bls.Fr {
	digest := sha256.New()

	tmpBytes := bls.FrTo32(&r)
	digest.Write(tmpBytes[:])
	digest.Write(bls.ToCompressedG1(d))

	var tmp bls.Fr
	bls.FrFrom32(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}

func calcQ(e, d *bls.G1Point, y, w *bls.Fr) bls.Fr {
	digest := sha256.New()

	digest.Write(bls.ToCompressedG1(d))
	digest.Write(bls.ToCompressedG1(e))
	tmpBytes := bls.FrTo32(y)
	digest.Write(tmpBytes[:])
	tmpBytes = bls.FrTo32(w)
	digest.Write(tmpBytes[:])

	var tmp bls.Fr
	bls.FrFrom32(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}

func innerQuotients(f []bls.Fr, index int) []bls.Fr {

func outerQuotients(f []bls.Fr, z, y bls.Fr) []bls.Fr {
}

func ComputeKZGProof(poly []bls.Fr, at bls.Fr) *bls.G1Point {
}

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte, lg1 []bls.G1Point) (d *bls.G1Point, y *bls.Fr, sigma *bls.G1Point) {
	var fis [][]bls.Fr
	commitments, zis, yis, fis := root.GetCommitmentsAlongPath(key)

	// Construct g(x)
	r := calcR(commitments, zis, yis)

	var g []bls.Fr
	var powR bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for i, f := range fis {
		quotients := innerQuotients(f, i)
		for j := 0; j < InternalNodeNumChildren; j++ {
			bls.AddModFr(&g[i], &powR, &quotients[i])
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	d = bls.LinCombG1(lg1, g)

	// Compute h(x)
	t := calcT(r, d)

	var h []bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for i, f := range fis {
		var denom bls.Fr
		bls.SubModFr(&denom, &t, &omegaIs[i])
		bls.DivModFr(&denom, &powR, &denom)

		for j := 0; j < InternalNodeNumChildren; j++ {
			var tmp bls.Fr
			bls.MulModFr(&tmp, &denom, &f[j])
			bls.AddModFr(&h[i], &h[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	e := bls.LinCombG1(lg1, h)

	// compute y and w
	y = new(bls.Fr)
	w := new(bls.Fr)
	bls.EvalPolyAt(y, h, &t)
	bls.EvalPolyAt(w, g, &t)

	// compute π and ρ
	pi := ComputeKZGProof(h, lg1)
	rho := ComputeKZGProof(g, lg1)

	// compute σ
	sigma = new(bls.G1Point)
	q := calcQ(d, e, y, w)
	bls.MulG1(sigma, rho, &q)
	bls.AddG1(sigma, sigma, pi)

	return
}

func VerifyVerkleProof(d, pi, rho *bls.G1Point, y *bls.Fr, commitments []*bls.G1Point, zis, yis []*bls.Fr, s2 *bls.G2Point) bool {
	r := calcR(commitments, zis, yis)
	t := calcT(r, d)

	// Evaluate w = g₂(t) and E
	g2 := make([]bls.Fr, len(commitments))
	var powR bls.Fr
	var e bls.G1Point
	bls.CopyFr(&powR, &bls.ONE)
	for i := range g2 {
		var tMinusZi, rDivZi bls.Fr
		bls.SubModFr(&tMinusZi, &t, zis[i])
		bls.DivModFr(&rDivZi, &powR, &tMinusZi)

		// g₂(t)
		bls.MulModFr(&g2[i], &rDivZi, yis[i])

		// E
		var eTmp bls.G1Point
		bls.MulG1(&e, commitments[i], &rDivZi)
		bls.AddG1(&e, &e, &eTmp)

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	var g2t bls.Fr
	bls.EvalPolyAt(&g2t, g2, &t)

	// w = y - g₂(t)
	var w bls.Fr
	bls.SubModFr(&w, y, &g2t)

	// Calculate [s-t]₂
	var s2MinusT, tPoint bls.G2Point
	bls.MulG2(&tPoint, &bls.GenG2, &t)
	bls.SubG2(&s2MinusT, s2, &tPoint)

	// D-[w]₁
	var dMinusW, wPoint bls.G1Point
	bls.MulG1(&wPoint, &bls.GenG1, &w)
	bls.SubG1(&dMinusW, d, &wPoint)

	// E-[y]₁
	var eMinusY, yPoint bls.G1Point
	bls.MulG1(&yPoint, &bls.GenG1, y)
	bls.SubG1(&eMinusY, &e, &yPoint)

	//return checkPairing(E-[y]₁, [1]₂, pi, [s-t]₂) && checkPairing(D-[w]₁, [1]₂, ro, [s-t]₂)
	return bls.PairingsVerify(&eMinusY, &bls.GenG2, pi, &s2MinusT) && bls.PairingsVerify(&dMinusW, &bls.GenG2, rho, &s2MinusT)
}
