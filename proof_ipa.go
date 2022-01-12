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
	ipa "github.com/crate-crypto/go-ipa"
	"github.com/crate-crypto/go-ipa/common"
)

type Proof struct {
	multipoint  *ipa.MultiProof // multipoint argument
	extStatus   []byte          // the extension status of each stem
	commitments []*Point        // commitments, sorted by their path in the tree
	poaStems    [][]byte        // stems proving another stem is absent
}

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte) *Proof {
	tr := common.NewTranscript("multiproof")
	root.ComputeCommitment()
	pe, extStatus, alt := root.GetCommitmentsAlongPath(key)
	proof := &Proof{
		multipoint:  ipa.CreateMultiProof(tr, GetConfig().conf, pe.Cis, pe.Fis, pe.Zis),
		commitments: pe.Cis,
		extStatus:   []byte{extStatus},
	}

	if alt != nil {
		proof.poaStems = [][]byte{alt}
	}

	return proof
}

func GetCommitmentsForMultiproof(root VerkleNode, keys [][]byte) (*ProofElements, []byte, [][]byte) {
	p := &ProofElements{}
	var extStatuses []byte
	var poaStems [][]byte
	for _, key := range keys {
		pe, extStatus, alt := root.GetCommitmentsAlongPath(key)
		p.Merge(pe)
		extStatuses = append(extStatuses, extStatus)

		if alt != nil {
			poaStems = append(poaStems, alt)
		}
	}

	return p, extStatuses, poaStems
}

func MakeVerkleMultiProof(root VerkleNode, keys [][]byte) (*Proof, []*Point, []byte, []*Fr) {
	tr := common.NewTranscript("multiproof")
	root.ComputeCommitment()

	pe, es, poas := GetCommitmentsForMultiproof(root, keys)

	mpArg := ipa.CreateMultiProof(tr, GetConfig().conf, pe.Cis, pe.Fis, pe.Zis)
	proof := &Proof{
		multipoint:  mpArg,
		commitments: pe.Cis,
		extStatus:   es,
		poaStems:    poas,
	}
	return proof, pe.Cis, pe.Zis, pe.Yis
}

func VerifyVerkleProof(proof *Proof, Cs []*Point, indices []uint8, ys []*Fr, tc *Config) bool {
	tr := common.NewTranscript("multiproof")
	return ipa.CheckMultiProof(tr, tc.conf, proof.multipoint, Cs, ys, indices)
}
