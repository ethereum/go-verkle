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

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte, s *bls.Fr) (commitments []*bls.G1Point, y, w bls.Fr, d, pi, rho *bls.G1Point, zis, yis []*bls.Fr) {
	commitments, zis, yis = root.GetCommitmentsAlongPath(key)

	r := calcR(commitments, zis, yis)

	// Compute D = g(s) and h(s)
	var hS bls.G1Point
	d = new(bls.G1Point)
	bls.CopyG1(d, &bls.ZeroG1)
	bls.CopyG1(&hS, &bls.ZeroG1)
	var powR bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for i := range commitments {
		var gi, hi bls.G1Point
		var yiPoint bls.G1Point
		bls.MulG1(&yiPoint, &bls.GenG1, yis[i])

		// gᵢ(s) = Cᵢ - yᵢ
		// hᵢ(s) = Cᵢ
		bls.SubG1(&gi, commitments[i], &yiPoint)
		bls.CopyG1(&hi, commitments[i])

		// gᵢ(s) = rⁱ * (Cᵢ - yᵢ)
		// hᵢ(s) = rⁱ * Cᵢ
		bls.MulG1(&gi, &gi, &powR)
		bls.MulG1(&hi, &hi, &powR)

		var quotient bls.Fr
		bls.SubModFr(&quotient, s, zis[i])
		bls.InvModFr(&quotient, &quotient)

		// gᵢ(s) = rⁱ * (Cᵢ - yᵢ) / (s - zᵢ)
		// hᵢ(s) = rⁱ * Cᵢ / (s - zᵢ)
		bls.MulG1(&gi, &gi, &quotient)
		bls.MulG1(&hi, &hi, &quotient)

		bls.AddG1(d, d, &gi)
		bls.AddG1(&hS, &hS, &hi)

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}

	t := calcT(r, d)

	// Compute w = g(t) and y = h(t); It requires using the
	// barycentric formula in order to evaluate a function at
	// ∀i zᵢ ≠ t,
	g := make([]bls.Fr, 26)
	h := make([]bls.Fr, 26)
	fis := root.EvalPathAt(key, &t)
	bls.CopyFr(&powR, &bls.ONE)
	for i, fi := range fis {
		var tmp, denom bls.Fr
		bls.CopyFr(&tmp, &t)
		bls.SubModFr(&denom, &tmp, &omegaIs[i])
		bls.MulModFr(&tmp, &powR, &fi)
		bls.DivModFr(&h[i], &tmp, &denom)
		bls.SubModFr(&tmp, &tmp, yis[i])
		bls.DivModFr(&g[i], &tmp, &denom)

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	bls.EvalPolyAt(&w, g, &t)
	bls.EvalPolyAt(&y, h, &t)

	// compute π
	var sMinusT bls.Fr
	bls.SubModFr(&sMinusT, s, &t)
	var hSMinusY, yPoint bls.G1Point
	bls.MulG1(&yPoint, &bls.GenG1, &y)
	bls.SubG1(&hSMinusY, &hS, &yPoint)
	var piMul bls.Fr
	bls.InvModFr(&piMul, &sMinusT)
	pi = new(bls.G1Point)
	bls.MulG1(pi, &bls.GenG1, &piMul)

	// compute ρ
	var dMinusW, wPoint bls.G1Point
	bls.MulG1(&wPoint, &bls.GenG1, &w)
	bls.SubG1(&dMinusW, d, &wPoint)
	var rhoMul bls.Fr
	bls.InvModFr(&rhoMul, &sMinusT)
	rho = new(bls.G1Point)
	bls.MulG1(rho, &bls.GenG1, &rhoMul)

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
