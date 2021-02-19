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

func generateSetup(secret string, n uint64) ([]bls.G1Point, []bls.G2Point) {
	var s bls.Fr
	bls.SetFr(&s, secret)

	var sPow bls.Fr
	bls.CopyFr(&sPow, &bls.ONE)

	s1Out := make([]bls.G1Point, n, n)
	s2Out := make([]bls.G2Point, n, n)
	for i := uint64(0); i < n; i++ {
		bls.MulG1(&s1Out[i], &bls.GenG1, &sPow)
		bls.MulG2(&s2Out[i], &bls.GenG2, &sPow)
		var tmp bls.Fr
		bls.CopyFr(&tmp, &sPow)
		bls.MulModFr(&sPow, &tmp, &s)
	}
	return s1Out, s2Out
}

func calcR(cs []bls.G1Point, indices []bls.Fr, ys []bls.Fr) bls.Fr {
	digest := sha256.New()
	for _, c := range cs {
		digest.Write(compressG1Point(&c))
	}
	for _, idx := range indices {
		tmp := bls.FrTo32(&idx)
		digest.Write(tmp[:])
	}
	for _, y := range ys {
		tmp := bls.FrTo32(&y)
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
	digest.Write(compressG1Point(d))

	var tmp bls.Fr
	bls.FrFrom32(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}
