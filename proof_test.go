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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestProofVerifyTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	proof := MakeVerkleProofOneLeaf(root, ffx32KeyTest)

	pe, _, _ := root.GetCommitmentsAlongPath(ffx32KeyTest)
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofVerifyMultipleLeaves(t *testing.T) {
	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	proof := MakeVerkleProofOneLeaf(root, keys[0])

	pe, _, _ := root.GetCommitmentsAlongPath(keys[0])
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeaves(t *testing.T) {
	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	proof, _, _, _ := MakeVerkleMultiProof(root, keys[0:2])

	pe, _, _ := GetCommitmentsForMultiproof(root, keys[0:2])
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeavesWithAbsentStem(t *testing.T) {
	const leafCount = 10

	var keys [][]byte
	var absentstem [31]byte
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		key[2] = byte(i)
		root.Insert(key, fourtyKeyTest, nil)
		if i%2 == 0 {
			keys = append(keys, key)
		}
		if i == 3 {
			copy(absentstem[:], key[:31])
		}
	}
	absent := make([]byte, 32)
	absent[2] = 3 // not in the proof, but leads to a stem
	absent[3] = 1 // and the stem differs
	keys = append(keys, absent)

	proof, _, _, _ := MakeVerkleMultiProof(root, keys)

	pe, _, isabsent := GetCommitmentsForMultiproof(root, keys)
	if len(isabsent) == 0 {
		t.Fatal("should have detected an absent stem")
	}
	if !bytes.Equal(isabsent[0], absentstem[:]) {
		t.Fatalf("returning the wrong absent stem: %x != %x", isabsent[0], absentstem)
	}

	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeavesCommitmentRedundancy(t *testing.T) {
	keys := make([][]byte, 2)
	root := New()
	keys[0] = zeroKeyTest
	root.Insert(keys[0], fourtyKeyTest, nil)
	keys[1] = oneKeyTest
	root.Insert(keys[1], fourtyKeyTest, nil)

	proof, _, _, _ := MakeVerkleMultiProof(root, keys)

	pe, _, _ := GetCommitmentsForMultiproof(root, keys)
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceInternalVerify(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)

	proof := MakeVerkleProofOneLeaf(root, ffx32KeyTest)

	pe, _, _ := root.GetCommitmentsAlongPath(ffx32KeyTest)
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceLeafVerify(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	proof := MakeVerkleProofOneLeaf(root, oneKeyTest)

	pe, _, _ := root.GetCommitmentsAlongPath(oneKeyTest)
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}
func TestProofOfAbsenceLeafVerifyOtherSuffix(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	key := func() []byte {
		ret, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000080")
		return ret
	}()

	proof := MakeVerkleProofOneLeaf(root, key)

	pe, _, _ := root.GetCommitmentsAlongPath(key)
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceStemVerify(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)

	key := func() []byte {
		ret, _ := hex.DecodeString("0000000000000000000000000000000000000000100000000000000000000000")
		return ret
	}()

	proof := MakeVerkleProofOneLeaf(root, key)

	pe, _, _ := root.GetCommitmentsAlongPath(key)
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func BenchmarkProofCalculation(b *testing.B) {
	keys := make([][]byte, 100000)
	root := New()
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, zeroKeyTest, nil)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		MakeVerkleProofOneLeaf(root, keys[len(keys)/2])
	}
}

func BenchmarkProofVerification(b *testing.B) {
	keys := make([][]byte, 100000)
	root := New()
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, zeroKeyTest, nil)
	}

	root.ComputeCommitment()
	pe, _, _ := root.GetCommitmentsAlongPath(keys[len(keys)/2])
	proof := MakeVerkleProofOneLeaf(root, keys[len(keys)/2])

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, GetConfig())
	}
}

func TestProofSerializationNoAbsentStem(t *testing.T) {
	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	proof := MakeVerkleProofOneLeaf(root, keys[0])

	serialized, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) == 0 {
		t.Fatal("zero-length serialized proof payload")
	}
	stemsize := binary.LittleEndian.Uint32(serialized[:4])
	if stemsize != 0 {
		t.Fatalf("first byte indicates that there are %d stems that should not be here", stemsize)
	}
	extsize := binary.LittleEndian.Uint32(serialized[4:8])
	if extsize != 1 {
		t.Fatalf("second byte indicates that there are %d extension statuses, should be 1", extsize)
	}
	// TODO keep checking the serialized values here
}

func TestProofSerializationWithAbsentStem(t *testing.T) {
	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		key[2] = byte(i)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	// Create stem  0x0000020100000.... that is not present in the tree,
	// however stem 0x0000020000000.... is present and will be returned
	// as a proof of absence.
	var absentkey [32]byte
	absentkey[2] = 2
	absentkey[3] = 1

	proof := MakeVerkleProofOneLeaf(root, absentkey[:])

	serialized, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) == 0 {
		t.Fatal("zero-length serialized proof payload")
	}
	stemsize := binary.LittleEndian.Uint32(serialized[:4])
	if stemsize != 1 {
		t.Fatalf("first byte indicates that there are %d stems that should not be here", stemsize)
	}
	extsize := binary.LittleEndian.Uint32(serialized[4+stemsize*31 : 4+stemsize*31+4])
	if extsize != 1 {
		t.Fatalf("second byte indicates that there are %d extension statuses, should be 1", extsize)
	}
	// TODO keep checking the serialized values here, they should be the same as in the previous test
}

func TestProofDeserialize(t *testing.T) {
	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		key[2] = byte(i)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	// Create stem  0x0000020100000.... that is not present in the tree,
	// however stem 0x0000020000000.... is present and will be returned
	// as a proof of absence.
	var absentkey [32]byte
	absentkey[2] = 2
	absentkey[3] = 1

	proof := MakeVerkleProofOneLeaf(root, absentkey[:])

	serialized, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) == 0 {
		t.Fatal("zero-length serialized proof payload")
	}

	deserialized, err := DeserializeProof(serialized)
	if err != nil {
		t.Fatalf("could not deserialize verkle proof: %v", err)
	}
	_ = deserialized

	pe, _, _ := root.GetCommitmentsAlongPath(absentkey[:])
	if !VerifyVerkleProof(deserialized, pe.Cis, pe.Zis, pe.Yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofDeserializeErrors(t *testing.T) {

	deserialized, err := DeserializeProof([]byte{0})
	if err == nil {
		t.Fatal("deserializing invalid proof didn't cause an error")
	}
	if deserialized != nil {
		t.Fatalf("non-nil deserialized data returned %v", deserialized)
	}

	deserialized, err = DeserializeProof([]byte{1, 0, 0, 0})
	if err == nil {
		t.Fatal("deserializing invalid proof didn't cause an error")
	}
	if deserialized != nil {
		t.Fatalf("non-nil deserialized data returned %v", deserialized)
	}

	deserialized, err = DeserializeProof([]byte{0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("deserializing invalid proof didn't cause an error")
	}
	if deserialized != nil {
		t.Fatalf("non-nil deserialized data returned %v", deserialized)
	}

	deserialized, err = DeserializeProof([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("deserializing invalid proof didn't cause an error")
	}
	if deserialized != nil {
		t.Fatalf("non-nil deserialized data returned %v", deserialized)
	}
}
