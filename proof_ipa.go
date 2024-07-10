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
	OtherStems            [][StemSize]byte `json:"otherStems"`
	DepthExtensionPresent []byte           `json:"depthExtensionPresent"`
	CommitmentsByPath     [][32]byte       `json:"commitmentsByPath"`
	D                     [32]byte         `json:"d"`
	IPAProof              *IPAProof        `json:"ipa_proof"`
}

func (vp *VerkleProof) Copy() *VerkleProof {
	ret := &VerkleProof{
		OtherStems:            make([][StemSize]byte, len(vp.OtherStems)),
		DepthExtensionPresent: make([]byte, len(vp.DepthExtensionPresent)),
		CommitmentsByPath:     make([][32]byte, len(vp.CommitmentsByPath)),
		IPAProof:              &IPAProof{},
	}

	copy(ret.OtherStems, vp.OtherStems)
	copy(ret.DepthExtensionPresent, vp.DepthExtensionPresent)
	copy(ret.CommitmentsByPath, vp.CommitmentsByPath)

	ret.D = vp.D

	if vp.IPAProof != nil {
		ret.IPAProof = vp.IPAProof
	}

	return ret
}

type Proof struct {
	Multipoint *ipa.MultiProof // multipoint argument
	ExtStatus  []byte          // the extension status of each stem
	Cs         []*Point        // commitments, sorted by their path in the tree
	PoaStems   []Stem          // stems proving another stem is absent
	Keys       [][]byte
	PreValues  [][]byte
	PostValues [][]byte
}

type StemStateDiff struct {
	Stem [StemSize]byte `json:"stem"`

	UpdatedSuffixes []byte   `json:"updatedsuffixes"`
	UpdatedCurrent  [][]byte `json:"updatedcurrent"`
	UpdatedNew      [][]byte `json:"updatednew"`

	ReadSuffixes []byte   `json:"readsuffixes"`
	ReadCurrent  [][]byte `json:"readcurrent"`

	InsertedSuffixes []byte   `json:"insertedsuffixes"`
	InsertedNew      [][]byte `json:"insertednew"`

	UntouchedSuffixes []byte `json:"untouchedsuffixes"`
}

type StateDiff []StemStateDiff

func (sd StateDiff) Copy() StateDiff {
	ret := make(StateDiff, len(sd))
	for i := range sd {
		copy(ret[i].Stem[:], sd[i].Stem[:])

		ret[i].UpdatedSuffixes = make([]byte, len(sd[i].UpdatedSuffixes))
		copy(ret[i].UpdatedSuffixes, sd[i].UpdatedSuffixes)
		ret[i].ReadSuffixes = make([]byte, len(sd[i].ReadSuffixes))
		copy(ret[i].ReadSuffixes, sd[i].ReadSuffixes)
		ret[i].InsertedSuffixes = make([]byte, len(sd[i].InsertedSuffixes))
		copy(ret[i].InsertedSuffixes, sd[i].InsertedSuffixes)
		ret[i].UntouchedSuffixes = make([]byte, len(sd[i].UntouchedSuffixes))
		copy(ret[i].UntouchedSuffixes, sd[i].UntouchedSuffixes)

		ret[i].UpdatedCurrent = make([][]byte, len(sd[i].UpdatedCurrent))
		for j := range sd[i].UpdatedCurrent {
			if len(sd[i].UpdatedCurrent[j]) == 0 {

			} else {
				copy(ret[i].UpdatedCurrent[j], sd[i].UpdatedCurrent[j])
			}
		}
		ret[i].ReadCurrent = make([][]byte, len(sd[i].ReadCurrent))
		for j := range sd[i].ReadCurrent {
			if len(sd[i].ReadCurrent[j]) == 0 {

			} else {
				copy(ret[i].ReadCurrent[j], sd[i].ReadCurrent[j])
			}
		}

		ret[i].UpdatedNew = make([][]byte, len(sd[i].UpdatedNew))
		for j := range sd[i].UpdatedNew {
			if len(sd[i].UpdatedNew[j]) == 0 {

			} else {
				copy(ret[i].UpdatedNew[j], sd[i].UpdatedNew[j])
			}
		}
		ret[i].InsertedNew = make([][]byte, len(sd[i].InsertedNew))
		for j := range sd[i].InsertedNew {
			if len(sd[i].InsertedNew[j]) == 0 {

			} else {
				copy(ret[i].InsertedNew[j], sd[i].InsertedNew[j])
			}
		}
	}
	return ret
}

func GetCommitmentsForMultiproof(root VerkleNode, keys [][]byte, resolver NodeResolverFn) (*ProofElements, []byte, []Stem, error) {
	sort.Sort(keylist(keys))
	return root.GetProofItems(keylist(keys), resolver)
}

// getProofElementsFromTree factors the logic that is used both in the proving and verification methods. It takes a pre-state
// tree and an optional post-state tree, extracts the proof data from them and returns all the items required to build/verify
// a proof.
func getProofElementsFromTree(preroot, postroot VerkleNode, keys [][]byte, resolver NodeResolverFn) (*ProofElements, []byte, []Stem, [][]byte, error) {
	// go-ipa won't accept no key as an input, catch this corner case
	// and return an empty result.
	if len(keys) == 0 {
		return nil, nil, nil, nil, errors.New("no key provided for proof")
	}

	pe, es, poas, err := GetCommitmentsForMultiproof(preroot, keys, resolver)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error getting pre-state proof data: %w", err)
	}

	// if a post-state tree is present, merge its proof elements with
	// those of the pre-state tree, so that they can be proved together.
	postvals := make([][]byte, len(keys))
	if postroot != nil {
		// keys were sorted already in the above GetcommitmentsForMultiproof.
		// Set the post values, if they are untouched, leave them `nil`
		for i := range keys {
			val, err := postroot.Get(keys[i], resolver)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("error getting post-state value for key %x: %w", keys[i], err)
			}
			if !bytes.Equal(pe.Vals[i], val) {
				postvals[i] = val
			}
		}
	}

	// [0:3]: proof elements of the pre-state trie for serialization,
	// 3: values to be inserted in the post-state trie for serialization
	return pe, es, poas, postvals, nil
}

func MakeVerkleMultiProof(preroot, postroot VerkleNode, keys [][]byte, resolver NodeResolverFn) (*Proof, []*Point, []byte, []*Fr, error) {
	pe, es, poas, postvals, err := getProofElementsFromTree(preroot, postroot, keys, resolver)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("get commitments for multiproof: %s", err)
	}

	cfg := GetConfig()
	tr := common.NewTranscript("vt")
	mpArg, err := ipa.CreateMultiProof(tr, cfg.conf, pe.Cis, pe.Fis, pe.Zis)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("creating multiproof: %w", err)
	}

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

// VerifyVerkleProofWithPreState takes a proof and a trusted tree root and verifies that the proof is valid.
func VerifyVerkleProofWithPreState(proof *Proof, preroot VerkleNode) error {
	pe, _, _, _, err := getProofElementsFromTree(preroot, nil, proof.Keys, nil)
	if err != nil {
		return fmt.Errorf("error getting proof elements: %w", err)
	}

	if ok, err := VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()); !ok || err != nil {
		return fmt.Errorf("error verifying proof: verifies=%v, error=%w", ok, err)
	}

	return nil
}

func VerifyVerkleProof(proof *Proof, Cs []*Point, indices []uint8, ys []*Fr, tc *Config) (bool, error) {
	tr := common.NewTranscript("vt")
	return ipa.CheckMultiProof(tr, tc.conf, proof.Multipoint, Cs, ys, indices)
}

func isInsertion(preLen, postLen int) bool {
	return preLen == 0 && postLen != 0
}
func isRead(preLen, postLen int) bool {
	return preLen != 0 && postLen == 0
}
func isUpdate(preLen, postLen int) bool {
	return preLen != 0 && postLen != 0
}

// SerializeProof serializes the proof in the rust-verkle format:
// * len(Proof of absence stem) || Proof of absence stems
// * len(depths) || serialize(depth || ext statusi)
// * len(commitments) || serialize(commitment)
// * Multipoint proof
// it also returns the serialized keys and values
func SerializeProof(proof *Proof) (*VerkleProof, StateDiff, error) {
	otherstems := make([][StemSize]byte, len(proof.PoaStems))
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
		stem := KeyToStem(key)
		if stemdiff == nil || !bytes.Equal(stemdiff.Stem[:], stem) {
			statediff = append(statediff, StemStateDiff{})
			stemdiff = &statediff[len(statediff)-1]
			copy(stemdiff.Stem[:], stem)
		}
		preLen := len(proof.PreValues[i])
		postLen := len(proof.PostValues[i])
		switch {
		case isInsertion(preLen, postLen):
			stemdiff.InsertedSuffixes = append(stemdiff.InsertedSuffixes, key[StemSize])
			if postLen == 0 {
				stemdiff.InsertedNew = append(stemdiff.InsertedNew, proof.PostValues[i])
			} else {
				var aligned [32]byte
				copy(aligned[:postLen], proof.PostValues[i])
				stemdiff.InsertedNew = append(stemdiff.InsertedNew, aligned[:])
			}
		case isRead(preLen, postLen):
			stemdiff.ReadSuffixes = append(stemdiff.ReadSuffixes, key[StemSize])
			if preLen == 0 {
				stemdiff.ReadCurrent = append(stemdiff.ReadCurrent, proof.PreValues[i])
			} else {
				var aligned [32]byte
				copy(aligned[:preLen], proof.PreValues[i])
				stemdiff.ReadCurrent = append(stemdiff.ReadCurrent, aligned[:])
			}
		case isUpdate(preLen, postLen):
			stemdiff.UpdatedSuffixes = append(stemdiff.UpdatedSuffixes, key[StemSize])
			if preLen == 0 {
				stemdiff.UpdatedCurrent = append(stemdiff.UpdatedCurrent, proof.PreValues[i])
			} else {
				var aligned [32]byte
				copy(aligned[:preLen], proof.PreValues[i])
				stemdiff.UpdatedCurrent = append(stemdiff.UpdatedCurrent, aligned[:])
			}
			if postLen == 0 {
				stemdiff.UpdatedNew = append(stemdiff.UpdatedNew, proof.PostValues[i])
			} else {
				var aligned [32]byte
				copy(aligned[:postLen], proof.PostValues[i])
				stemdiff.UpdatedNew = append(stemdiff.UpdatedNew, aligned[:])
			}
		default:
			stemdiff.UntouchedSuffixes = append(stemdiff.UntouchedSuffixes, key[StemSize])
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
		poaStems              []Stem
		keys                  [][]byte
		prevalues, postvalues [][]byte
		extStatus             []byte
		commitments           []*Point
		multipoint            ipa.MultiProof
	)

	poaStems = make([]Stem, len(vp.OtherStems))
	for i, poaStem := range vp.OtherStems {
		poaStems[i] = make([]byte, len(poaStem))
		copy(poaStems[i], poaStem[:])
	}

	extStatus = vp.DepthExtensionPresent

	commitments = make([]*Point, len(vp.CommitmentsByPath))
	for i, commitmentBytes := range vp.CommitmentsByPath {
		var commitment Point
		if err := commitment.SetBytes(commitmentBytes[:]); err != nil {
			return nil, err
		}
		commitments[i] = &commitment
	}

	if err := multipoint.D.SetBytes(vp.D[:]); err != nil {
		return nil, fmt.Errorf("setting D: %w", err)
	}
	multipoint.IPA.A_scalar.SetBytes(vp.IPAProof.FinalEvaluation[:])
	multipoint.IPA.L = make([]Point, IPA_PROOF_DEPTH)
	for i, b := range vp.IPAProof.CL {
		if err := multipoint.IPA.L[i].SetBytes(b[:]); err != nil {
			return nil, fmt.Errorf("setting L[%d]: %w", i, err)
		}
	}
	multipoint.IPA.R = make([]Point, IPA_PROOF_DEPTH)
	for i, b := range vp.IPAProof.CR {
		if err := multipoint.IPA.R[i].SetBytes(b[:]); err != nil {
			return nil, fmt.Errorf("setting R[%d]: %w", i, err)
		}
	}

	// turn statediff into keys and values
	for _, stemdiff := range statediff {
		for i, suffix := range stemdiff.UpdatedSuffixes {
			var k [32]byte
			copy(k[:StemSize], stemdiff.Stem[:])
			k[StemSize] = suffix
			keys = append(keys, k[:])
			prevalues = append(prevalues, stemdiff.UpdatedCurrent[i])
			postvalues = append(postvalues, stemdiff.UpdatedNew[i])
		}
		for i, suffix := range stemdiff.InsertedSuffixes {
			var k [32]byte
			copy(k[:StemSize], stemdiff.Stem[:])
			k[StemSize] = suffix
			keys = append(keys, k[:])
			prevalues = append(prevalues, nil)
			postvalues = append(postvalues, stemdiff.InsertedNew[i])
		}
		for i, suffix := range stemdiff.ReadSuffixes {
			var k [32]byte
			copy(k[:StemSize], stemdiff.Stem[:])
			k[StemSize] = suffix
			keys = append(keys, k[:])
			prevalues = append(prevalues, stemdiff.ReadCurrent[i])
			postvalues = append(postvalues, nil)
		}
		for _, suffix := range stemdiff.UntouchedSuffixes {
			var k [32]byte
			copy(k[:StemSize], stemdiff.Stem[:])
			k[StemSize] = suffix
			keys = append(keys, k[:])
			prevalues = append(prevalues, nil)
			postvalues = append(postvalues, nil)
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
func PreStateTreeFromProof(proof *Proof, rootC *Point) (VerkleNode, error) { // skipcq: GO-R1005
	if len(proof.Keys) != len(proof.PreValues) {
		return nil, fmt.Errorf("incompatible number of keys and pre-values: %d != %d", len(proof.Keys), len(proof.PreValues))
	}
	if len(proof.Keys) != len(proof.PostValues) {
		return nil, fmt.Errorf("incompatible number of keys and post-values: %d != %d", len(proof.Keys), len(proof.PostValues))
	}
	stems := make([][]byte, 0, len(proof.Keys))
	for _, k := range proof.Keys {
		stem := KeyToStem(k)
		if len(stems) == 0 || !bytes.Equal(stems[len(stems)-1], stem) {
			stems = append(stems, stem)
		}
	}
	if len(stems) != len(proof.ExtStatus) {
		return nil, fmt.Errorf("invalid number of stems and extension statuses: %d != %d", len(stems), len(proof.ExtStatus))
	}
	var (
		info  = map[string]stemInfo{}
		paths [][]byte
		err   error
		poas  = proof.PoaStems
	)

	// The proof of absence stems must be sorted. If that isn't the case, the proof is invalid.
	if !sort.IsSorted(bytesSlice(proof.PoaStems)) {
		return nil, fmt.Errorf("proof of absence stems are not sorted")
	}

	// We build a cache of paths that have a presence extension status.
	pathsWithExtPresent := map[string]struct{}{}
	i := 0
	for _, es := range proof.ExtStatus {
		if es&3 == extStatusPresent {
			pathsWithExtPresent[string(stems[i][:es>>3])] = struct{}{}
		}
		i++
	}

	// assign one or more stem to each stem info
	for i, es := range proof.ExtStatus {
		si := stemInfo{
			depth:    es >> 3,
			stemType: es & 3,
		}
		path := stems[i][:si.depth]
		switch si.stemType {
		case extStatusAbsentEmpty:
			// All keys that are part of a proof of absence, must contain empty
			// prestate values. If that isn't the case, the proof is invalid.
			for j := range proof.Keys { // TODO: DoS risk, use map or binary search.
				if bytes.HasPrefix(proof.Keys[j], stems[i]) && proof.PreValues[j] != nil {
					return nil, fmt.Errorf("proof of absence (empty) stem %x has a value", si.stem)
				}
			}
		case extStatusAbsentOther:
			// All keys that are part of a proof of absence, must contain empty
			// prestate values. If that isn't the case, the proof is invalid.
			for j := range proof.Keys { // TODO: DoS risk, use map or binary search.
				if bytes.HasPrefix(proof.Keys[j], stems[i]) && proof.PreValues[j] != nil {
					return nil, fmt.Errorf("proof of absence (other) stem %x has a value", si.stem)
				}
			}

			// For this absent path, we must first check if this path contains a proof of presence.
			// If that is the case, we don't have to do anything since the corresponding leaf will be
			// constructed by that extension status (already processed or to be processed).
			// In other case, we should get the stem from the list of proof of absence stems.
			if _, ok := pathsWithExtPresent[string(path)]; ok {
				continue
			}

			// Note that this path doesn't have proof of presence (previous if check above), but
			// it can have multiple proof of absence. If a previous proof of absence had already
			// created the stemInfo for this path, we don't have to do anything.
			if _, ok := info[string(path)]; ok {
				continue
			}

			si.stem = poas[0]
			poas = poas[1:]
		case extStatusPresent:
			si.values = map[byte][]byte{}
			si.stem = stems[i]
			for j, k := range proof.Keys { // TODO: DoS risk, use map or binary search.
				if bytes.Equal(KeyToStem(k), si.stem) {
					si.values[k[StemSize]] = proof.PreValues[j]
					si.has_c1 = si.has_c1 || (k[StemSize] < 128)
					si.has_c2 = si.has_c2 || (k[StemSize] >= 128)
				}
			}
		default:
			return nil, fmt.Errorf("invalid extension status: %d", si.stemType)
		}
		info[string(path)] = si
		paths = append(paths, path)
	}

	if len(poas) != 0 {
		return nil, fmt.Errorf("not all proof of absence stems were used: %d", len(poas))
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

			if bytes.Equal(KeyToStem(k), info[string(p)].stem) {
				values[k[StemSize]] = proof.PreValues[i]
			}
		}
		comms, err = root.CreatePath(p, info[string(p)], comms, values)
		if err != nil {
			return nil, err
		}
	}

	return root, nil
}

// PostStateTreeFromProof uses the pre-state trie and the list of updated values
// to produce the stateless post-state trie.
func PostStateTreeFromStateDiff(preroot VerkleNode, statediff StateDiff) (VerkleNode, error) {
	postroot := preroot.Copy()

	for _, stemstatediff := range statediff {
		var (
			values    = make([][]byte, NodeWidth)
			overwrite bool
		)

		for i, suffix := range stemstatediff.InsertedSuffixes {
			if /* len(suffixdiff.NewValue) > 0 - this only works for a slice */ stemstatediff.InsertedNew[i] != nil {
				// if this value is non-nil, it means InsertValuesAtStem should be
				// called, otherwise, skip updating the tree.
				values[suffix] = stemstatediff.InsertedNew[i]
				overwrite = true
			}
		}
		for i, suffix := range stemstatediff.UpdatedSuffixes {
			if /* len(suffixdiff.NewValue) > 0 - this only works for a slice */ stemstatediff.UpdatedNew[i] != nil {
				// if this value is non-nil, it means InsertValuesAtStem should be
				// called, otherwise, skip updating the tree.
				values[suffix] = stemstatediff.UpdatedNew[i]
				overwrite = true
			}
		}

		if overwrite {
			var stem [StemSize]byte
			copy(stem[:StemSize], stemstatediff.Stem[:])
			if err := postroot.(*InternalNode).InsertValuesAtStem(stem[:], values, nil); err != nil {
				return nil, fmt.Errorf("error overwriting value in post state: %w", err)
			}
		}
	}
	postroot.Commit()

	return postroot, nil
}

type bytesSlice []Stem

func (x bytesSlice) Len() int           { return len(x) }
func (x bytesSlice) Less(i, j int) bool { return bytes.Compare(x[i], x[j]) < 0 }
func (x bytesSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
