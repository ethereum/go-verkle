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
	"errors"
	"fmt"
	"sort"
	"unsafe"

	ipa "github.com/crate-crypto/go-ipa"
	"github.com/crate-crypto/go-ipa/common"
)

const IPA_PROOF_DEPTH = 8

type IPAProof struct {
	CL              [IPA_PROOF_DEPTH][32]byte `json:"cl"`
	CR              [IPA_PROOF_DEPTH][32]byte `json:"cr"`
	FinalEvaluation [32]byte                  `json:"finalEvaluation"`
}

type VerkleProof struct {
	OtherStems            [][31]byte `json:"otherStems"`
	DepthExtensionPresent []byte     `json:"depthExtensionPresent"`
	CommitmentsByPath     [][32]byte `json:"commitmentsByPath"`
	D                     [32]byte   `json:"d"`
	IPAProof              *IPAProof  `json:"ipa_proof"`
}

type Proof struct {
	Multipoint *ipa.MultiProof // multipoint argument
	ExtStatus  []byte          // the extension status of each stem
	Cs         []*Point        // commitments, sorted by their path in the tree
	PoaStems   [][]byte        // stems proving another stem is absent
	Keys       [][]byte
	PreValues  [][]byte
	PostValues [][]byte
}

type SuffixStateDiff struct {
	Suffix       byte      `json:"suffix"`
	CurrentValue *[32]byte `json:"currentValue"`
	NewValue     *[32]byte `json:"new_value"`
}

type SuffixStateDiffs []SuffixStateDiff

type StemStateDiff struct {
	Stem        [31]byte         `json:"stem"`
	SuffixDiffs SuffixStateDiffs `json:"suffixDiffs"`
}

type StateDiff []StemStateDiff

func GetCommitmentsForMultiproof(root VerkleNode, keys [][]byte, resolver NodeResolverFn) (*ProofElements, []byte, [][]byte, error) {
	sort.Sort(keylist(keys))
	return root.GetProofItems(keylist(keys), resolver)
}

func getProofElementsFromTree(preroot, postroot VerkleNode, keys [][]byte, resolver NodeResolverFn) (*ProofElements, []byte, [][]byte, [][]byte, []*Point, [][]Fr, []*Fr, []byte, error) {
	// go-ipa won't accept no key as an input, catch this corner case
	// and return an empty result.
	if len(keys) == 0 {
		return nil, nil, nil, nil, nil, nil, nil, nil, errors.New("no key provided for proof")
	}

	pe, es, poas, err := GetCommitmentsForMultiproof(preroot, keys, resolver)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("error getting pre-state proof data: %w", err)
	}

	// List of points and vectors and indices used to generate the IPA proof
	// If only a pre-state root is available, it's a simple copy, but if both
	// pre- and post-state root are present, it's merging the two lists.
	var (
		proof_cis []*Point
		proof_fs  [][]Fr
		proof_zs  []uint8
		proof_ys  []*Fr
		postvals  = make([][]byte, len(keys))
	)
	for i := range pe.Cis {
		proof_cis = append(proof_cis, pe.Cis[i])
		proof_fs = append(proof_fs, pe.Fis[i])
		proof_ys = append(proof_ys, pe.Yis[i])
		proof_zs = append(proof_zs, pe.Zis[i])
	}

	if postroot != nil {
		pe_post, _, _, err := GetCommitmentsForMultiproof(postroot, keys, resolver)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("error getting post-state proof data: %w", err)
		}

		for i := range pe_post.Cis {
			proof_cis = append(proof_cis, pe_post.Cis[i])
			proof_fs = append(proof_fs, pe_post.Fis[i])
			proof_ys = append(proof_ys, pe_post.Yis[i])
			proof_zs = append(proof_zs, pe_post.Zis[i])
		}

		// Set the post values, if they are untouched, leave them `nil`
		for i, v := range pe.Vals {
			if !bytes.Equal(v, pe_post.Vals[i]) {
				postvals[i] = v
			}
		}
	}

	return pe, es, poas, postvals, proof_cis, proof_fs, proof_ys, proof_zs, nil
}

func MakeVerkleMultiProof(preroot, postroot VerkleNode, keys [][]byte, resolver NodeResolverFn) (*Proof, []*Point, []byte, []*Fr, error) {
	pe, es, poas, postvals, proof_cis, proof_fs, _, proof_zs, err := getProofElementsFromTree(preroot, postroot, keys, resolver)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error getting proof elements: %w", err)
	}

	cfg := GetConfig()
	tr := common.NewTranscript("vt")
	mpArg := ipa.CreateMultiProof(tr, cfg.conf, proof_cis, proof_fs, proof_zs)

	// It's wheel-reinvention time again 🎉: reimplement a basic
	// feature that should be part of the stdlib.
	// "But golang is a high-productivity language!!!" 🤪
	// len()-1, because the root is already present in the
	// parent block, so we don't keep it in the proof.
	paths := make([]string, 0, len(pe.ByPath)-1)
	for path := range pe.ByPath {
		if len(path) > 0 {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	cis := make([]*Point, len(pe.ByPath)-1)
	for i, path := range paths {
		cis[i] = pe.ByPath[path]
	}

	proof := &Proof{
		Multipoint: mpArg,
		Cs:         cis,
		ExtStatus:  es,
		PoaStems:   poas,
		Keys:       keys,
		PreValues:  pe.Vals,
		PostValues: postvals,
	}
	return proof, pe.Cis, pe.Zis, pe.Yis, nil
}

func VerifyVerkleProofWithPreAndPostTrie(proof *Proof, preroot, postroot VerkleNode, keys [][]byte, resolver NodeResolverFn, tc *Config) bool {
	_, _, _, _, proof_cis, _, proof_ys, proof_zs, err := getProofElementsFromTree(preroot, postroot, keys, resolver)
	if err != nil {
		return false
	}

	return VerifyVerkleProof(proof, proof_cis, proof_zs, proof_ys, tc)
}

func VerifyVerkleProof(proof *Proof, Cs []*Point, indices []uint8, ys []*Fr, tc *Config) bool {
	tr := common.NewTranscript("vt")
	return ipa.CheckMultiProof(tr, tc.conf, proof.Multipoint, Cs, ys, indices)
}

// SerializeProof serializes the proof in the rust-verkle format:
// * len(Proof of absence stem) || Proof of absence stems
// * len(depths) || serialize(depth || ext statusi)
// * len(commitments) || serialize(commitment)
// * Multipoint proof
// it also returns the serialized keys and values
func SerializeProof(proof *Proof) (*VerkleProof, StateDiff, error) {
	otherstems := make([][31]byte, len(proof.PoaStems))
	for i, stem := range proof.PoaStems {
		copy(otherstems[i][:], stem)
	}

	cbp := make([][32]byte, len(proof.Cs))
	for i, C := range proof.Cs {
		serialized := C.Bytes()
		copy(cbp[i][:], serialized[:])
	}

	var cls, crs [IPA_PROOF_DEPTH][32]byte
	for i := 0; i < IPA_PROOF_DEPTH; i++ {

		l := proof.Multipoint.IPA.L[i].Bytes()
		copy(cls[i][:], l[:])
		r := proof.Multipoint.IPA.R[i].Bytes()
		copy(crs[i][:], r[:])
	}

	var stemdiff *StemStateDiff
	var statediff StateDiff
	for i, key := range proof.Keys {
		if stemdiff == nil || !bytes.Equal(stemdiff.Stem[:], key[:31]) {
			statediff = append(statediff, StemStateDiff{})
			stemdiff = &statediff[len(statediff)-1]
			copy(stemdiff.Stem[:], key[:31])
		}
		stemdiff.SuffixDiffs = append(stemdiff.SuffixDiffs, SuffixStateDiff{Suffix: key[31]})
		newsd := &stemdiff.SuffixDiffs[len(stemdiff.SuffixDiffs)-1]

		var valueLen = len(proof.PreValues[i])
		switch valueLen {
		case 0:
			// null value
		case 32:
			newsd.CurrentValue = (*[32]byte)(proof.PreValues[i])
		default:
			var aligned [32]byte
			copy(aligned[:valueLen], proof.PreValues[i])
			newsd.CurrentValue = (*[32]byte)(unsafe.Pointer(&aligned[0]))
		}

		valueLen = len(proof.PostValues[i])
		switch valueLen {
		case 0:
			// null value
		case 32:
			newsd.NewValue = (*[32]byte)(proof.PostValues[i])
		default:
			var aligned [32]byte
			copy(aligned[:valueLen], proof.PostValues[i])
			newsd.NewValue = (*[32]byte)(unsafe.Pointer(&aligned[0]))
		}
	}

	return &VerkleProof{
		OtherStems:            otherstems,
		DepthExtensionPresent: proof.ExtStatus,
		CommitmentsByPath:     cbp,
		D:                     proof.Multipoint.D.Bytes(),
		IPAProof: &IPAProof{
			CL:              cls,
			CR:              crs,
			FinalEvaluation: proof.Multipoint.IPA.A_scalar.Bytes(),
		},
	}, statediff, nil
}

// DeserializeProof deserializes the proof found in blocks, into a format that
// can be used to rebuild a stateless version of the tree.
func DeserializeProof(vp *VerkleProof, statediff StateDiff) (*Proof, error) {
	var (
		poaStems, keys        [][]byte
		prevalues, postvalues [][]byte
		extStatus             []byte
		commitments           []*Point
		multipoint            ipa.MultiProof
	)

	poaStems = make([][]byte, len(vp.OtherStems))
	for i, poaStem := range vp.OtherStems {
		poaStems[i] = poaStem[:]
	}

	extStatus = vp.DepthExtensionPresent

	commitments = make([]*Point, len(vp.CommitmentsByPath))
	for i, commitmentBytes := range vp.CommitmentsByPath {
		var commitment Point
		if err := commitment.SetBytesUnsafe(commitmentBytes[:]); err != nil {
			return nil, err
		}
		commitments[i] = &commitment
	}

	multipoint.D.SetBytes(vp.D[:])
	multipoint.IPA.A_scalar.SetBytes(vp.IPAProof.FinalEvaluation[:])
	multipoint.IPA.L = make([]Point, IPA_PROOF_DEPTH)
	for i, b := range vp.IPAProof.CL {
		multipoint.IPA.L[i].SetBytes(b[:])
	}
	multipoint.IPA.R = make([]Point, IPA_PROOF_DEPTH)
	for i, b := range vp.IPAProof.CR {
		multipoint.IPA.R[i].SetBytes(b[:])
	}

	// turn statediff into keys and values
	for _, stemdiff := range statediff {
		for _, suffixdiff := range stemdiff.SuffixDiffs {
			var k [32]byte
			copy(k[:31], stemdiff.Stem[:])
			k[31] = suffixdiff.Suffix
			keys = append(keys, k[:])
			if suffixdiff.CurrentValue != nil {
				prevalues = append(prevalues, suffixdiff.CurrentValue[:])
			} else {
				prevalues = append(prevalues, nil)
			}

			if suffixdiff.NewValue != nil {
				postvalues = append(postvalues, suffixdiff.NewValue[:])
			} else {
				postvalues = append(postvalues, nil)
			}
		}
	}

	proof := Proof{
		&multipoint,
		extStatus,
		commitments,
		poaStems,
		keys,
		prevalues,
		postvalues,
	}
	return &proof, nil
}

type stemInfo struct {
	depth          byte
	stemType       byte
	has_c1, has_c2 bool
	values         map[byte][]byte
	stem           []byte
}

// PreStateTreeFromProof builds a stateless prestate tree from the proof.
func PreStateTreeFromProof(proof *Proof, rootC *Point) (VerkleNode, error) {
	stems := make([][]byte, 0, len(proof.Keys))
	for _, k := range proof.Keys {
		if len(stems) == 0 || !bytes.Equal(stems[len(stems)-1], k[:31]) {
			stems = append(stems, k[:31])
		}
	}
	stemIndex := 0

	var (
		info  = map[string]stemInfo{}
		paths [][]byte
		err   error
		poas  = proof.PoaStems
	)

	// assign one or more stem to each stem info
	for _, es := range proof.ExtStatus {
		depth := es >> 3
		path := stems[stemIndex][:depth]
		si := stemInfo{
			depth:    depth,
			stemType: es & 3,
		}
		switch si.stemType {
		case extStatusAbsentEmpty:
		case extStatusAbsentOther:
			si.stem = poas[0]
			poas = poas[1:]
		default:
			// the first stem could be missing (e.g. the second stem in the
			// group is the one that is present. Compare each key to the first
			// stem, along the length of the path only.
			stemPath := stems[stemIndex][:len(path)]
			si.values = map[byte][]byte{}
			for i, k := range proof.Keys {
				if bytes.Equal(k[:len(path)], stemPath) && proof.PreValues[i] != nil {
					si.values[k[31]] = proof.PreValues[i]
					si.has_c1 = si.has_c1 || (k[31] < 128)
					si.has_c2 = si.has_c2 || (k[31] >= 128)
					// This key has values, its stem is the one that
					// is present.
					si.stem = k[:31]
				}
			}
		}
		info[string(path)] = si
		paths = append(paths, path)

		// Skip over all the stems that share the same path
		// to the extension tree. This happens e.g. if two
		// stems have the same path, but one is a proof of
		// absence and the other one is present.
		stemIndex++
		for ; stemIndex < len(stems); stemIndex++ {
			if !bytes.Equal(stems[stemIndex][:depth], path) {
				break
			}
		}
	}

	root := NewStatelessInternal(0, rootC).(*InternalNode)
	comms := proof.Cs
	for _, p := range paths {
		// NOTE: the reconstructed tree won't tell the
		// difference between leaves missing from view
		// and absent leaves. This is enough for verification
		// but not for block validation.
		values := make([][]byte, NodeWidth)
		for i, k := range proof.Keys {
			if len(proof.PreValues[i]) == 0 {
				// Skip the nil keys, they are here to prove
				// an absence.
				continue
			}

			if bytes.Equal(k[:31], info[string(p)].stem) {
				values[k[31]] = proof.PreValues[i]
			}
		}
		comms, err = root.CreatePath(p, info[string(p)], comms, values)
		if err != nil {
			return nil, err
		}
	}

	return root, nil
}

func PostStateTreeFromProof(preroot VerkleNode, statediff StateDiff) (VerkleNode, error) {
	postroot := preroot.Copy()
	for _, stemstatediff := range statediff {
		var (
			values     = make([][]byte, NodeWidth)
			overwrites bool
		)

		for _, suffixdiff := range stemstatediff.SuffixDiffs {
			if len(suffixdiff.NewValue) > 0 {
				// If the prestate is present, it means that at least one
				// post value will be non-nil. In this case, make a copy
				// of the pre tree and update all post values.

				overwrites = true
				values[suffixdiff.Suffix] = suffixdiff.NewValue[:]
			}
		}

		if overwrites {
			if err := postroot.(*InternalNode).InsertStem(stemstatediff.Stem[:], values, nil); err != nil {
				return nil, fmt.Errorf("error overwriting value in post state: %w", err)
			}
		}
	}
	postroot.Commit()

	return postroot, nil
}
