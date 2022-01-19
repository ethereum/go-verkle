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

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte) *Proof {
	tr := common.NewTranscript("multiproof")
	root.ComputeCommitment()
	pe, extStatus, alt := root.GetCommitmentsAlongPath(key)
	proof := &Proof{
		Multipoint: ipa.CreateMultiProof(tr, GetConfig().conf, pe.Cis, pe.Fis, pe.Zis),
		Cs:         pe.Cis,
		ExtStatus:  []byte{extStatus},
	}

	if alt != nil {
		proof.PoaStems = [][]byte{alt}
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
		Multipoint: mpArg,
		Cs:         pe.Cis,
		ExtStatus:  es,
		PoaStems:   poas,
	}
	return proof, pe.Cis, pe.Zis, pe.Yis
}

func VerifyVerkleProof(proof *Proof, Cs []*Point, indices []uint8, ys []*Fr, tc *Config) bool {
	tr := common.NewTranscript("multiproof")
	return ipa.CheckMultiProof(tr, tc.conf, proof.Multipoint, Cs, ys, indices)
}

// SerializeProof serializes the proof in the rust-verkle format:
// * len(Proof of absence stem) || Proof of absence stems
// * len(depths) || serialize(depthi || ext statusi)
// * len(commitments) || serialize(commitment)
// * Multipoint proof
func SerializeProof(proof *Proof) ([]byte, error) {
	var buf bytes.Buffer

	// Temporary: add the keys and values to the proof
	binary.Write(&buf, binary.LittleEndian, uint32(len(proof.Keys)))
	for i, key := range proof.Keys {
		buf.Write(key)
		if proof.Values[i] != nil {
			buf.WriteByte(1)
			buf.Write(proof.Values[i])
		} else {
			buf.WriteByte(0)
		}
	}

	binary.Write(&buf, binary.LittleEndian, uint32(len(proof.PoaStems)))
	for _, stem := range proof.PoaStems {
		_, err := buf.Write(stem)
		if err != nil {
			return nil, err
		}
	}

	binary.Write(&buf, binary.LittleEndian, uint32(len(proof.ExtStatus)))
	for _, daes := range proof.ExtStatus {
		err := buf.WriteByte(daes)
		if err != nil {
			return nil, err
		}
	}

	binary.Write(&buf, binary.LittleEndian, uint32(len(proof.Cs)))
	for _, C := range proof.Cs {
		serialized := C.Bytes()
		_, err := buf.Write(serialized[:])
		if err != nil {
			return nil, err
		}
	}

	proof.Multipoint.Write(&buf)

	return buf.Bytes(), nil
}

func DeserializeProof(proofSerialized []byte) (*Proof, error) {
	var (
		numPoaStems, numExtStatus uint32
		numCommitments, numKeys   uint32
		poaStems, keys, values    [][]byte
		extStatus                 []byte
		commitments               []*Point
		multipoint                ipa.MultiProof
	)
	reader := bytes.NewReader(proofSerialized)

	// Temporary: read the keys and values, serialized as binary data
	if err := binary.Read(reader, binary.LittleEndian, &numKeys); err != nil {
		return nil, err
	}
	for i := 0; i < int(numKeys); i++ {
		var key, value [32]byte
		reader.Read(key[:])
		keys = append(keys, key[:])
		b, _ := reader.ReadByte()
		if b == 1 {
			reader.Read(value[:])
			values = append(values, value[:])
		} else {
			values = append(values, nil)
		}
	}

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
		if err := commitment.Unmarshal(commitmentBytes); err != nil {
			return nil, err
		}

		commitments[i] = &commitment
	}

	// TODO submit PR to go-ipa to make this return an error if it fails to Read
	multipoint.Read(reader)
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
