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
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

// This is missing one more function, where we are given multiple keys and
// we produce a proof:
// Eg func (v *VerkleProver) MakeVerkleProofManyLeaves(keys [][]byte) VerkleProof {}

type VerkleProver struct {
	// The verkle node for which the prover will create proofs for
	root VerkleNode

	kz KZGConfig
}

// A VerkleProof is a KZG proof that a value or values are in the verkle trie
type VerkleProof struct {
	d     *bls.G1Point
	y     *bls.Fr
	sigma *bls.G1Point
}

func (v *VerkleProver) MakeVerkleProofOneLeaf(key []byte) VerkleProof {
	nodeWidth := 1 << v.kz.width

	transcript := Transcript{
		state: []byte{},
	}

	var fis [][]bls.Fr
	commitments, zis, yis, fis := v.root.GetCommitmentsAlongPath(key)

	// Construct g(x)
	//
	// Compute `r` challenge
	transcript.AppendPoints(commitments)
	transcript.AppendScalars(zis)
	transcript.AppendScalars(yis)
	r := transcript.ChallengeScalar()

	g := make([]bls.Fr, nodeWidth)
	var powR bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for index, f := range fis {
		quotients := v.kz.innerQuotients(f, index)
		var tmp bls.Fr
		for i := 0; i < nodeWidth; i++ {
			bls.MulModFr(&tmp, &powR, &quotients[i])
			bls.AddModFr(&g[i], &g[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	d := bls.LinCombG1(v.kz.lg1, g[:])

	// Compute h(x)
	//
	// Compute `t` scalar
	transcript.AppendScalar(&r)
	transcript.AppendPoint(d)
	t := transcript.ChallengeScalar()

	h := make([]bls.Fr, nodeWidth)
	bls.CopyFr(&powR, &bls.ONE)
	for index, f := range fis {
		var denom bls.Fr
		bls.SubModFr(&denom, &t, &v.kz.omegaIs[index])
		bls.DivModFr(&denom, &powR, &denom)

		for i := 0; i < nodeWidth; i++ {
			var tmp bls.Fr
			bls.MulModFr(&tmp, &denom, &f[i])
			bls.AddModFr(&h[i], &h[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}

	// compute y and w
	y := new(bls.Fr)
	w := new(bls.Fr)
	for i := range g {
		var factor, tmp bls.Fr
		bls.SubModFr(&factor, &t, &v.kz.omegaIs[i])
		bls.DivModFr(&factor, &v.kz.omegaIs[i], &factor)

		bls.MulModFr(&tmp, &h[i], &factor)
		bls.AddModFr(y, y, &tmp)
		bls.MulModFr(&tmp, &g[i], &factor)
		bls.AddModFr(w, w, &tmp)
	}
	// Compute t^width - 1
	var tPowWidth bls.Fr
	bls.CopyFr(&tPowWidth, &t)
	for i := 0; i < v.kz.width; i++ {
		bls.MulModFr(&tPowWidth, &tPowWidth, &tPowWidth)
	}
	bls.SubModFr(&tPowWidth, &tPowWidth, &bls.ONE)
	bls.MulModFr(&tPowWidth, &tPowWidth, &v.kz.nodeWidthInversed)
	bls.MulModFr(w, w, &tPowWidth)
	bls.MulModFr(y, y, &tPowWidth)

	// compute π and ρ
	pi := ComputeKZGProof(&v.kz, h, &t, y)
	rho := ComputeKZGProof(&v.kz, g, &t, w)

	// Compute E
	e := kzg.CommitToEvalPoly(v.kz.lg1, h[:])

	// compute σ
	sigma := new(bls.G1Point)
	//
	// Compute `q` challenge
	transcript.AppendPoint(e)
	transcript.AppendPoint(d)
	transcript.AppendScalar(y)
	transcript.AppendScalar(w)
	q := transcript.ChallengeScalar()

	bls.MulG1(sigma, rho, &q)
	bls.AddG1(sigma, sigma, pi)

	return VerkleProof{
		d:     d,
		y:     y,
		sigma: sigma,
	}
}

func (v *VerkleProof) Verify(ks *kzg.KZGSettings, kz *KZGConfig, commitments []*bls.G1Point, zis, yis []*bls.Fr) bool {
	transcript := Transcript{
		state: []byte{},
	}

	// Compute `r` challenge
	transcript.AppendPoints(commitments)
	transcript.AppendScalars(zis)
	transcript.AppendScalars(yis)
	r := transcript.ChallengeScalar()

	// Compute `t` challenge
	transcript.AppendScalar(&r)
	transcript.AppendPoint(v.d)
	t := transcript.ChallengeScalar()

	// Evaluate w = g₂(t) and E
	g2 := make([]bls.Fr, len(commitments))
	var powR bls.Fr
	var e bls.G1Point
	bls.CopyFr(&powR, &bls.ONE)
	for i := range g2 {
		var tMinusZi, rDivZi bls.Fr
		bls.SubModFr(&tMinusZi, &t, &kz.omegaIs[i])
		bls.DivModFr(&rDivZi, &powR, &tMinusZi)

		// g₂(t)
		bls.MulModFr(&g2[i], &rDivZi, yis[i])

		// E
		var eTmp bls.G1Point
		bls.MulG1(&eTmp, commitments[i], &rDivZi)
		bls.AddG1(&e, &e, &eTmp)

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	var g2t bls.Fr
	bls.EvalPolyAt(&g2t, g2, &t)

	// w = y - g₂(t)
	var w bls.Fr
	bls.SubModFr(&w, v.y, &g2t)

	// Compute `q` challenge
	transcript.AppendPoint(&e)
	transcript.AppendPoint(v.d) // Added twice
	transcript.AppendScalar(v.y)
	transcript.AppendScalar(&w)
	q := transcript.ChallengeScalar()

	// final=E+qD
	var final bls.G1Point
	bls.MulG1(&final, v.d, &q)
	bls.AddG1(&final, &final, &e)

	// finalAt=y+w*q
	var finalAt bls.Fr
	bls.MulModFr(&finalAt, &q, &w)
	bls.AddModFr(&finalAt, &finalAt, v.y)

	return ks.CheckProofSingle(&final, v.sigma, &t, &finalAt)
}
