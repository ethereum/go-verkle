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
		h := sha256.Sum256(bls.ToCompressedG1(c))
		digest.Write(h[:])
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
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp

}

func calcT(r *bls.Fr, d *bls.G1Point) bls.Fr {
	digest := sha256.New()

	tmpBytes := bls.FrTo32(r)
	digest.Write(tmpBytes[:])
	tmpBytes = sha256.Sum256(bls.ToCompressedG1(d))
	digest.Write(tmpBytes[:])

	var tmp bls.Fr
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}

func calcQ(e, d *bls.G1Point, y, w *bls.Fr) bls.Fr {
	digest := sha256.New()
	hE := sha256.Sum256(bls.ToCompressedG1(e))
	hD := sha256.Sum256(bls.ToCompressedG1(d))

	digest.Write(hE[:])
	digest.Write(hD[:])
	tmpBytes := bls.FrTo32(y)
	digest.Write(tmpBytes[:])
	tmpBytes = bls.FrTo32(w)
	digest.Write(tmpBytes[:])

	var tmp bls.Fr
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}

func innerQuotients(f []bls.Fr, index int) []bls.Fr {
	var q [InternalNodeNumChildren]bls.Fr

	y := f[index]
	for i := 0; i < InternalNodeNumChildren; i++ {
		if i != index {
			omegaIdx := (len(omegaIs) - i) % len(omegaIs)
			invIdx := (index + InternalNodeNumChildren - i) % InternalNodeNumChildren
			iMinIdx := (i - index) % InternalNodeNumChildren

			// calculate q[i]
			var tmp bls.Fr
			bls.SubModFr(&tmp, &f[i], &y)
			bls.MulModFr(&tmp, &tmp, &omegaIs[omegaIdx])
			bls.MulModFr(&q[i], &tmp, &inverses[invIdx])

			// calculate q[i]'s contribution to q[index]
			bls.MulModFr(&tmp, &omegaIs[iMinIdx], &q[i])
			bls.SubModFr(&tmp, &bls.ZERO, &tmp)
			bls.AddModFr(&q[index], &q[index], &tmp)
		}
	}

	return q[:]
}

func outerQuotients(f []bls.Fr, z, y *bls.Fr) []bls.Fr {
	var q [InternalNodeNumChildren]bls.Fr

	for i := 0; i < InternalNodeNumChildren; i++ {
		var tmp, quo bls.Fr
		bls.SubModFr(&tmp, &f[i], y)
		bls.SubModFr(&quo, &omegaIs[i], z)
		bls.DivModFr(&q[i], &tmp, &quo)
	}

	return q[:]
}

func ComputeKZGProof(poly []bls.Fr, z, y *bls.Fr, lg1 []bls.G1Point) *bls.G1Point {
	oq := outerQuotients(poly, z, y)
	return kzg.CommitToEvalPoly(lg1, oq)
}

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte, lg1 []bls.G1Point) (d *bls.G1Point, y *bls.Fr, sigma *bls.G1Point) {
	var fis [][]bls.Fr
	commitments, zis, yis, fis := root.GetCommitmentsAlongPath(key)

	// Construct g(x)
	r := calcR(commitments, zis, yis)

	var g [InternalNodeNumChildren]bls.Fr
	var powR bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for index, f := range fis {
		quotients := innerQuotients(f, index)
		var tmp bls.Fr
		for i := 0; i < InternalNodeNumChildren; i++ {
			bls.MulModFr(&tmp, &powR, &quotients[i])
			bls.AddModFr(&g[i], &g[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	d = bls.LinCombG1(lg1, g[:])

	// Compute h(x)
	t := calcT(&r, d)

	var h [InternalNodeNumChildren]bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for index, f := range fis {
		var denom bls.Fr
		bls.SubModFr(&denom, &t, &omegaIs[index])
		bls.DivModFr(&denom, &powR, &denom)

		for i := 0; i < InternalNodeNumChildren; i++ {
			var tmp bls.Fr
			bls.MulModFr(&tmp, &denom, &f[i])
			bls.AddModFr(&h[i], &h[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}

	// compute y and w
	y = new(bls.Fr)
	w := new(bls.Fr)
	for i := range g {
		var factor, tmp bls.Fr
		bls.SubModFr(&factor, &t, &omegaIs[i])
		bls.DivModFr(&factor, &omegaIs[i], &factor)

		bls.MulModFr(&tmp, &h[i], &factor)
		bls.AddModFr(y, y, &tmp)
		bls.MulModFr(&tmp, &g[i], &factor)
		bls.AddModFr(w, w, &tmp)
	}
	// Compute t^width - 1
	var tPowWidth bls.Fr
	bls.CopyFr(&tPowWidth, &t)
	for i := 0; i < width; i++ {
		bls.MulModFr(&tPowWidth, &tPowWidth, &tPowWidth)
	}
	bls.SubModFr(&tPowWidth, &tPowWidth, &bls.ONE)
	bls.MulModFr(w, w, &tPowWidth)
	bls.MulModFr(w, w, &nodeWidthInversed)
	bls.MulModFr(y, y, &tPowWidth)
	bls.MulModFr(y, y, &nodeWidthInversed)

	// compute π and ρ
	pi := ComputeKZGProof(h[:], &t, y, lg1)
	rho := ComputeKZGProof(g[:], &t, w, lg1)

	// Compute E
	e := bls.LinCombG1(lg1, h[:])

	// compute σ
	sigma = new(bls.G1Point)
	q := calcQ(e, d, y, w)
	bls.MulG1(sigma, rho, &q)
	bls.AddG1(sigma, sigma, pi)

	return
}

func VerifyVerkleProof(d, pi, rho *bls.G1Point, y *bls.Fr, commitments []*bls.G1Point, zis, yis []*bls.Fr, s2 *bls.G2Point) bool {
	r := calcR(commitments, zis, yis)
	t := calcT(&r, d)

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
