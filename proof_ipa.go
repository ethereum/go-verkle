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
	"encoding/binary"
	"sort"

	ipa "github.com/crate-crypto/go-ipa"
	"github.com/crate-crypto/go-ipa/bandersnatch/fp"
	"github.com/crate-crypto/go-ipa/common"
)

type Proof struct {
	Multipoint *ipa.MultiProof // multipoint argument
	ExtStatus  []byte          // the extension status of each stem
	Cs         []*Point        // commitments, sorted by their path in the tree
	PoaStems   [][]byte        // stems proving another stem is absent
	Keys       [][]byte
	Values     [][]byte
}

func GetCommitmentsForMultiproof(root VerkleNode, keys [][]byte) (*ProofElements, []byte, [][]byte) {
	sort.Sort(keylist(keys))
	return root.GetProofItems(keylist(keys))
}

func MakeVerkleMultiProof(root VerkleNode, keys [][]byte, keyvals map[string][]byte) (*Proof, []*Point, []byte, []*Fr) {
	tr := common.NewTranscript("vt")
	root.ComputeCommitment()

	pe, es, poas := GetCommitmentsForMultiproof(root, keys)

	var vals [][]byte
	for _, k := range keys {
		// TODO at the moment, do not include the post-data
		//val, _ := root.Get(k, nil)
		//vals = append(vals, val)
		vals = append(vals, keyvals[string(k)])
	}

	cfg, _ := GetConfig()
	mpArg := ipa.CreateMultiProof(tr, cfg.conf, pe.Cis, pe.Fis, pe.Zis)

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
		Values:     vals,
	}
	return proof, pe.Cis, pe.Zis, pe.Yis
}

func VerifyVerkleProof(proof *Proof, Cs []*Point, indices []uint8, ys []*Fr, tc *Config) bool {
	tr := common.NewTranscript("vt")
	return ipa.CheckMultiProof(tr, tc.conf, proof.Multipoint, Cs, ys, indices)
}

// A structure representing a tuple
type KeyValuePair struct {
	Key   []byte
	Value []byte
}

// SerializeProof serializes the proof in the rust-verkle format:
// * len(Proof of absence stem) || Proof of absence stems
// * len(depths) || serialize(depthi || ext statusi)
// * len(commitments) || serialize(commitment)
// * Multipoint proof
// it also returns the serialized keys and values
func SerializeProof(proof *Proof) ([]byte, []KeyValuePair, error) {
	var bufProof bytes.Buffer

	binary.Write(&bufProof, binary.LittleEndian, uint32(len(proof.PoaStems)))
	for _, stem := range proof.PoaStems {
		_, err := bufProof.Write(stem)
		if err != nil {
			return nil, nil, err
		}
	}

	binary.Write(&bufProof, binary.LittleEndian, uint32(len(proof.ExtStatus)))
	for _, daes := range proof.ExtStatus {
		err := bufProof.WriteByte(daes)
		if err != nil {
			return nil, nil, err
		}
	}

	binary.Write(&bufProof, binary.LittleEndian, uint32(len(proof.Cs)))
	for _, C := range proof.Cs {
		serialized := C.Bytes()
		_, err := bufProof.Write(serialized[:])
		if err != nil {
			return nil, nil, err
		}
	}

	proof.Multipoint.Write(&bufProof)

	keyvals := make([]KeyValuePair, 0, len(proof.Keys))
	for i, key := range proof.Keys {
		var (
			valueLen = len(proof.Values[i])
			aligned  []byte
		)
		switch valueLen {
		case 0, 32:
			aligned = proof.Values[i]
		default:
			aligned = make([]byte, 32)
			copy(aligned[:valueLen], proof.Values[i])
		}
		keyvals = append(keyvals, KeyValuePair{key, aligned})
	}

	return bufProof.Bytes(), keyvals, nil
}

// DeserializeProof deserializes the proof found in blocks, into a format that
// can be used to rebuild a stateless version of the tree.
func DeserializeProof(proofSerialized []byte, keyvals []KeyValuePair) (*Proof, error) {
	var (
		numPoaStems, numExtStatus uint32
		numCommitments            uint32
		poaStems, keys, values    [][]byte
		extStatus                 []byte
		commitments               []*Point
		multipoint                ipa.MultiProof
	)
	reader := bytes.NewReader(proofSerialized)

	if err := binary.Read(reader, binary.LittleEndian, &numPoaStems); err != nil {
		return nil, err
	}
	poaStems = make([][]byte, numPoaStems)
	for i := 0; i < int(numPoaStems); i++ {
		var poaStem [31]byte
		if err := binary.Read(reader, binary.LittleEndian, &poaStem); err != nil {
			return nil, err
		}

		poaStems[i] = poaStem[:]
	}

	if err := binary.Read(reader, binary.LittleEndian, &numExtStatus); err != nil {
		return nil, err
	}
	extStatus = make([]byte, numExtStatus)
	for i := 0; i < int(numExtStatus); i++ {
		var e byte
		if err := binary.Read(reader, binary.LittleEndian, &e); err != nil {
			return nil, err
		}
		extStatus[i] = e
	}

	if err := binary.Read(reader, binary.LittleEndian, &numCommitments); err != nil {
		return nil, err
	}
	commitments = make([]*Point, numCommitments)
	commitmentBytes := make([]byte, fp.Bytes)
	for i := 0; i < int(numCommitments); i++ {
		var commitment Point
		if err := binary.Read(reader, binary.LittleEndian, commitmentBytes); err != nil {
			return nil, err
		}

		if err := commitment.SetBytes(commitmentBytes); err != nil {
			return nil, err
		}

		commitments[i] = &commitment
	}

	// TODO submit PR to go-ipa to make this return an error if it fails to Read
	multipoint.Read(reader)

	// Turn keyvals into keys and values
	for _, kv := range keyvals {
		keys = append(keys, kv.Key)
		values = append(values, kv.Value)
	}

	proof := Proof{
		&multipoint,
		extStatus,
		commitments,
		poaStems,
		keys,
		values,
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

// TreeFromProof builds a stateless tree from the proof
func TreeFromProof(proof *Proof, rootC *Point) (VerkleNode, error) {
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
			si.stem = stems[stemIndex]
			si.values = map[byte][]byte{}
			for i, k := range proof.Keys {
				if bytes.Equal(k[:31], si.stem) && proof.Values[i] != nil {
					si.values[k[31]] = proof.Values[i]
					si.has_c1 = si.has_c1 || (k[31] < 128)
					si.has_c2 = si.has_c2 || (k[31] >= 128)
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

	root := NewStatelessWithCommitment(rootC)
	comms := proof.Cs
	for _, p := range paths {
		comms, err = root.insertStem(p, info[string(p)], comms)
		if err != nil {
			return nil, err
		}
	}

	for i, k := range proof.Keys {
		if len(proof.Values[i]) == 0 {
			// Skip the nil keys, they are here to prove
			// an absence.
			continue
		}

		err = root.insertValue(k, proof.Values[i])
		if err != nil {
			return nil, err
		}
	}

	return root, nil
}
