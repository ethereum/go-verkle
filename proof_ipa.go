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

// +build !kzg

package verkle

import (
	ipa "github.com/crate-crypto/go-ipa"
	"github.com/crate-crypto/go-ipa/common"
)

type Proof = ipa.MultiProof

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte) *Proof {
	tr := common.NewTranscript("multiproof")
	root.ComputeCommitment()
	Cs, zs, _, fs := root.GetCommitmentsAlongPath(key)
	return ipa.CreateMultiProof(tr, GetConfig().conf, Cs, fs, zs)
}

func GetCommitmentsForMultiproof(root VerkleNode, keys [][]byte) ([]*Point, []uint8, []*Fr, [][]Fr) {
	var (
		fis         [][]Fr
		commitments []*Point
		zis         []uint8
		yis         []*Fr
	)

	for _, key := range keys {
		cs, idxs, ys, fs := root.GetCommitmentsAlongPath(key)
		commitments = append(commitments, cs...)
		zis = append(zis, idxs...)
		yis = append(yis, ys...)
		fis = append(fis, fs...)
	}

	return commitments, zis, yis, fis
}

func MakeVerkleMultiProof(root VerkleNode, keys [][]byte) (proof *Proof, Cs []*Point, indices []uint8, ys []*Fr) {
	tr := common.NewTranscript("multiproof")
	root.ComputeCommitment()

	var fs [][]Fr
	var zs []uint8
	Cs, zs, ys, fs = GetCommitmentsForMultiproof(root, keys)

	proof = ipa.CreateMultiProof(tr, GetConfig().conf, Cs, fs, zs)
	return
}

func VerifyVerkleProof(proof *Proof, Cs []*Point, indices []uint8, ys []*Fr, tc *Config) bool {
	tr := common.NewTranscript("multiproof")
	return ipa.CheckMultiProof(tr, tc.conf, proof, Cs, ys, indices)
}
