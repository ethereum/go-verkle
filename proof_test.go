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
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func TestProofVerifyTwoLeaves(t *testing.T) {
	t.Parallel()

	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)
	root.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ffx32KeyTest}, nil)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
		t.Fatalf("could not verify verkle proof: %s", ToDot(root))
	}
}

func TestProofVerifyMultipleLeaves(t *testing.T) {
	t.Parallel()

	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{keys[0]}, nil)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeaves(t *testing.T) {
	t.Parallel()

	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keys[0:2], nil)

	pe, _, _, err := GetCommitmentsForMultiproof(root, keys[0:2], nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := GetConfig()
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeavesWithAbsentStem(t *testing.T) {
	t.Parallel()

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

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keys, nil)

	pe, _, isabsent, err := GetCommitmentsForMultiproof(root, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(isabsent) == 0 {
		t.Fatal("should have detected an absent stem")
	}
	if !bytes.Equal(isabsent[0], absentstem[:]) {
		t.Fatalf("returning the wrong absent stem: %x != %x", isabsent[0], absentstem)
	}

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeavesCommitmentRedundancy(t *testing.T) {
	t.Parallel()

	keys := make([][]byte, 2)
	root := New()
	keys[0] = zeroKeyTest
	root.Insert(keys[0], fourtyKeyTest, nil)
	keys[1] = oneKeyTest
	root.Insert(keys[1], fourtyKeyTest, nil)

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keys, nil)

	pe, _, _, err := GetCommitmentsForMultiproof(root, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := GetConfig()
	if !VerifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceInternalVerify(t *testing.T) {
	t.Parallel()

	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ffx32KeyTest}, nil)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceLeafVerify(t *testing.T) {
	t.Parallel()

	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{oneKeyTest}, nil)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}
func TestProofOfAbsenceLeafVerifyOtherSuffix(t *testing.T) {
	t.Parallel()

	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	key := func() []byte {
		ret, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000080")
		return ret
	}()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{key}, nil)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceStemVerify(t *testing.T) {
	t.Parallel()

	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)

	key := func() []byte {
		ret, _ := hex.DecodeString("0000000000000000000000000000000000000000100000000000000000000000")
		return ret
	}()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{key}, nil)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
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
		MakeVerkleMultiProof(root, nil, [][]byte{keys[len(keys)/2]}, nil)
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

	root.Commit()
	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{keys[len(keys)/2]}, nil)

	b.ResetTimer()
	b.ReportAllocs()

	cfg := GetConfig()
	for i := 0; i < b.N; i++ {
		VerifyVerkleProof(proof, cis, zis, yis, cfg)
	}
}

func TestProofSerializationNoAbsentStem(t *testing.T) {
	t.Parallel()

	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, fourtyKeyTest, nil)
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, [][]byte{keys[0]}, nil)

	vp, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(vp.OtherStems) > 0 {
		t.Fatalf("first byte indicates that there are %d stems that should not be here", len(vp.OtherStems))
	}
	extsize := len(statediff)
	if extsize != 1 {
		t.Fatalf("second byte indicates that there are %d extension statuses, should be 1", extsize)
	}
}

func TestProofSerializationWithAbsentStem(t *testing.T) {
	t.Parallel()

	const leafCount = 256

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

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, [][]byte{absentkey[:]}, nil)

	vp, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	stemsize := len(vp.OtherStems)
	if stemsize != 1 {
		t.Fatalf("first byte indicates that there are %d stems that should not be here", stemsize)
	}
	extsize := len(statediff)
	if extsize != 1 {
		t.Fatalf("second byte indicates that there are %d extension statuses, should be 1", extsize)
	}
	// TODO keep checking the serialized values here, they should be the same as in the previous test
}

func TestProofDeserialize(t *testing.T) {
	t.Parallel()

	const leafCount = 256

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

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, [][]byte{absentkey[:]}, nil)

	vp, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}

	deserialized, err := DeserializeProof(vp, statediff)
	if err != nil {
		t.Fatalf("could not deserialize verkle proof: %v", err)
	}
	_ = deserialized

	pe, _, _, err := root.GetProofItems(keylist{absentkey[:]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := GetConfig()
	if !VerifyVerkleProof(deserialized, pe.Cis, pe.Zis, pe.Yis, cfg) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceEdgeCase(t *testing.T) {
	t.Parallel()

	root := New()
	root.Commit()

	ret, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030303")
	proof, cs, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ret}, nil)
	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cs, zis, yis, cfg) {
		t.Fatal("could not verify proof")
	}
}

func TestProofOfAbsenceOtherMultipleLeaves(t *testing.T) {
	t.Parallel()

	// Create a stem that isn't the one that will be proven,
	// but does look the same for most of its length.
	root := New()
	key, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030000")
	root.Insert(key, testValue, nil)
	root.Commit()

	ret1, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030300")
	ret2, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030301")
	proof, cs, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ret1, ret2}, nil)
	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cs, zis, yis, cfg) {
		t.Fatal("could not verify proof")
	}

	if len(proof.PoaStems) > 1 {
		t.Fatalf("invalid number of proof-of-absence stems: %d", len(proof.PoaStems))
	}
}

func TestProofOfAbsenceNoneMultipleStems(t *testing.T) {
	t.Parallel()

	root := New()
	key, _ := hex.DecodeString("0403030303030303030303030303030303030303030303030303030303030000")
	root.Insert(key, testValue, nil)
	root.Commit()

	ret1, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030300")
	ret2, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030200")
	proof, cs, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ret1, ret2}, nil)
	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cs, zis, yis, cfg) {
		t.Fatal("could not verify proof")
	}

	if len(proof.PoaStems) != 0 {
		t.Fatalf("invalid number of proof-of-absence stems: %d", len(proof.PoaStems))
	}

	if len(proof.ExtStatus) != 1 {
		t.Fatalf("invalid number of none extension statuses: %d ≠ 1", len(proof.ExtStatus))
	}
}

func TestSuffixStateDiffJSONMarshalUn(t *testing.T) {
	t.Parallel()

	ssd := SuffixStateDiff{
		Suffix: 0x41,
		CurrentValue: &[32]byte{
			0x10, 0x20, 0x30, 0x40,
			0x50, 0x60, 0x70, 0x80,
			0x90, 0xA0, 0xB0, 0xC0,
			0xD0, 0xE0, 0xF0, 0x00,
			0x11, 0x22, 0x33, 0x44,
			0x55, 0x66, 0x77, 0x88,
			0x99, 0xAA, 0xBB, 0xCC,
			0xDD, 0xEE, 0xFF, 0x00,
		},
	}

	expectedJSON := `{"suffix":65,"currentValue":"0x102030405060708090a0b0c0d0e0f000112233445566778899aabbccddeeff00"}`
	actualJSON, err := json.Marshal(ssd)
	if err != nil {
		t.Errorf("error marshalling SuffixStateDiff to JSON: %v", err)
	}

	if string(actualJSON) != expectedJSON {
		t.Errorf("JSON output doesn't match expected value.\nExpected: %s\nActual: %s", expectedJSON, string(actualJSON))
	}

	var actualSSD SuffixStateDiff
	err = json.Unmarshal(actualJSON, &actualSSD)
	if err != nil {
		t.Errorf("error unmarshalling JSON to SuffixStateDiff: %v", err)
	}

	if !reflect.DeepEqual(actualSSD, ssd) {
		t.Errorf("SuffixStateDiff doesn't match expected value.\nExpected: %+v\nActual: %+v", ssd, actualSSD)
	}
}

func TestStemStateDiffJSONMarshalUn(t *testing.T) {
	t.Parallel()

	ssd := StemStateDiff{
		Stem: [31]byte{10},
		SuffixDiffs: []SuffixStateDiff{{
			Suffix: 0x41,
			CurrentValue: &[32]byte{
				0x10, 0x20, 0x30, 0x40,
				0x50, 0x60, 0x70, 0x80,
				0x90, 0xA0, 0xB0, 0xC0,
				0xD0, 0xE0, 0xF0, 0x00,
				0x11, 0x22, 0x33, 0x44,
				0x55, 0x66, 0x77, 0x88,
				0x99, 0xAA, 0xBB, 0xCC,
				0xDD, 0xEE, 0xFF, 0x00,
			},
		}},
	}

	expectedJSON := `{"stem":"0x0a000000000000000000000000000000000000000000000000000000000000","suffixDiffs":[{"suffix":65,"currentValue":"0x102030405060708090a0b0c0d0e0f000112233445566778899aabbccddeeff00"}]}`
	actualJSON, err := json.Marshal(ssd)
	if err != nil {
		t.Errorf("error marshalling SuffixStateDiff to JSON: %v", err)
	}

	if string(actualJSON) != expectedJSON {
		t.Errorf("JSON output doesn't match expected value.\nExpected: %s\nActual: %s", expectedJSON, string(actualJSON))
	}

	var actualSSD StemStateDiff
	err = json.Unmarshal(actualJSON, &actualSSD)
	if err != nil {
		t.Errorf("error unmarshalling JSON to StemStateDiff: %v", err)
	}

	if !reflect.DeepEqual(actualSSD, ssd) {
		t.Errorf("SuffixStateDiff doesn't match expected value.\nExpected: %+v\nActual: %+v", ssd, actualSSD)
	}
}

func TestSuffixStateDiffJSONMarshalUnCurrentValueNil(t *testing.T) {
	t.Parallel()

	ssd := SuffixStateDiff{
		Suffix:       0x41,
		CurrentValue: nil,
	}

	expectedJSON := `{"suffix":65,"currentValue":null}`
	actualJSON, err := json.Marshal(ssd)
	if err != nil {
		t.Errorf("error marshalling SuffixStateDiff to JSON: %v", err)
	}

	if string(actualJSON) != expectedJSON {
		t.Errorf("JSON output doesn't match expected value.\nExpected: %s\nActual: %s", expectedJSON, string(actualJSON))
	}

	var actualSSD SuffixStateDiff
	err = json.Unmarshal(actualJSON, &actualSSD)
	if err != nil {
		t.Errorf("error unmarshalling JSON to SuffixStateDiff: %v", err)
	}

	if !reflect.DeepEqual(actualSSD, ssd) {
		t.Errorf("SuffixStateDiff doesn't match expected value.\nExpected: %+v\nActual: %+v", ssd, actualSSD)
	}
}

func TestIPAProofMarshalUnmarshalJSON(t *testing.T) {
	t.Parallel()

	ip1 := &IPAProof{
		CL:              [IPA_PROOF_DEPTH][32]byte{{1}, {2}, {3}},
		CR:              [IPA_PROOF_DEPTH][32]byte{{4}, {5}, {6}},
		FinalEvaluation: [32]byte{7},
	}
	ipJSON, err := json.Marshal(ip1)
	if err != nil {
		t.Fatal(err)
	}
	ip2 := &IPAProof{}
	err = json.Unmarshal(ipJSON, ip2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ip1, ip2) {
		t.Errorf("expected %v, got %v", ip1, ip2)
	}
}

func TestVerkleProofMarshalUnmarshalJSON(t *testing.T) {
	t.Parallel()

	vp1 := &VerkleProof{
		OtherStems:            [][31]byte{{1}, {2}, {3}},
		DepthExtensionPresent: []byte{4, 5, 6},
		CommitmentsByPath:     [][32]byte{{7}, {8}, {9}},
		D:                     [32]byte{10},
		IPAProof: &IPAProof{
			CL:              [IPA_PROOF_DEPTH][32]byte{{11}, {12}, {13}},
			CR:              [IPA_PROOF_DEPTH][32]byte{{14}, {15}, {16}},
			FinalEvaluation: [32]byte{17},
		},
	}
	vpJSON, err := json.Marshal(vp1)
	if err != nil {
		t.Fatal(err)
	}
	vp2 := &VerkleProof{}
	err = json.Unmarshal(vpJSON, vp2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(vp1, vp2) {
		t.Errorf("expected %v, got %v", vp1, vp2)
	}
}

func TestStatelessDeserialize(t *testing.T) {
	t.Parallel()

	root := New()
	for _, k := range [][]byte{zeroKeyTest, oneKeyTest, fourtyKeyTest, ffx32KeyTest} {
		root.Insert(k, fourtyKeyTest, nil)
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keylist{zeroKeyTest, fourtyKeyTest}, nil)

	serialized, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, statediff)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	if !droot.Commit().Equal(root.Commitment()) {
		t.Log(ToDot(droot), ToDot(root))
		t.Fatalf("differing root commitments %x != %x", droot.Commitment().Bytes(), root.Commitment().Bytes())
	}

	if !droot.(*InternalNode).children[0].(*LeafNode).commitment.Equal(root.(*InternalNode).children[0].Commit()) {
		t.Fatal("differing commitment for child #0")
	}

	if !droot.(*InternalNode).children[64].Commit().Equal(root.(*InternalNode).children[64].Commit()) {
		t.Fatal("differing commitment for child #64")
	}
}

func TestStatelessDeserializeMissingChildNode(t *testing.T) {
	t.Parallel()

	root := New()
	for _, k := range [][]byte{zeroKeyTest, oneKeyTest, ffx32KeyTest} {
		root.Insert(k, fourtyKeyTest, nil)
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keylist{zeroKeyTest, fourtyKeyTest}, nil)

	serialized, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, statediff)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	if !droot.Commit().Equal(root.Commit()) {
		t.Fatal("differing root commitments")
	}
	if !droot.(*InternalNode).children[0].Commit().Equal(root.(*InternalNode).children[0].Commit()) {
		t.Fatal("differing commitment for child #0")
	}

	if droot.(*InternalNode).children[64] != Empty(struct{}{}) {
		t.Fatalf("non-empty child #64: %v", droot.(*InternalNode).children[64])
	}
}

func TestStatelessDeserializeDepth2(t *testing.T) {
	t.Parallel()

	root := New()
	key1, _ := hex.DecodeString("0000010000000000000000000000000000000000000000000000000000000000")
	for _, k := range [][]byte{zeroKeyTest, key1} {
		root.Insert(k, fourtyKeyTest, nil)
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keylist{zeroKeyTest, key1}, nil)

	serialized, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, statediff)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	if !droot.Commit().Equal(root.Commit()) {
		t.Fatal("differing root commitments")
	}

	if !droot.(*InternalNode).children[0].Commit().Equal(root.(*InternalNode).children[0].Commit()) {
		t.Fatal("differing commitment for child #0")
	}
}
