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
// For more information, please refer to <https://unlicense.org>

package verkle

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/crate-crypto/go-ipa/common"
)

func TestProofEmptyTree(t *testing.T) {
	t.Parallel()

	root := New()
	root.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ffx32KeyTest}, nil)
	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
		t.Fatalf("could not verify verkle proof: %s", ToDot(root))
	}
}

func TestProofVerifyTwoLeaves(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatal(err)
	}
	if err := root.Insert(oneKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	if err := root.Insert(ffx32KeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	root.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ffx32KeyTest}, nil)

	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
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
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("could not read random bytes: %v", err)
		}
		keys[i] = key
		if err := root.Insert(key, fourtyKeyTest, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
	}
	root.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{keys[0]}, nil)

	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
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
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("could not read random bytes: %v", err)
		}
		keys[i] = key
		if err := root.Insert(key, fourtyKeyTest, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
	}
	root.Commit()

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keys[0:2], nil)

	pe, _, _, err := GetCommitmentsForMultiproof(root, keys[0:2], nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeavesWithAbsentStem(t *testing.T) {
	t.Parallel()

	const leafCount = 10

	var keys [][]byte
	var absentstem [StemSize]byte
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		key[2] = byte(i)
		if err := root.Insert(key, fourtyKeyTest, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
		if i%2 == 0 {
			keys = append(keys, key)
		}
		if i == 3 {
			copy(absentstem[:], key[:StemSize])
		}
	}
	root.Commit()

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
	if ok, err := verifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeavesCommitmentRedundancy(t *testing.T) {
	t.Parallel()

	keys := make([][]byte, 2)
	root := New()
	keys[0] = zeroKeyTest
	if err := root.Insert(keys[0], fourtyKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	keys[1] = oneKeyTest
	if err := root.Insert(keys[1], fourtyKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	root.Commit()

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, keys, nil)

	pe, _, _, err := GetCommitmentsForMultiproof(root, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, pe.Cis, pe.Zis, pe.Yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceInternalVerify(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	if err := root.Insert(oneKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	root.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ffx32KeyTest}, nil)

	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceLeafVerify(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	if err := root.Insert(ffx32KeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	root.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{oneKeyTest}, nil)

	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}
func TestProofOfAbsenceLeafVerifyOtherSuffix(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	if err := root.Insert(ffx32KeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	root.Commit()

	key := func() []byte {
		ret, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000080")
		return ret
	}()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{key}, nil)

	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceStemVerify(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}

	key := func() []byte {
		ret, _ := hex.DecodeString("0000000000000000000000000000000000000000100000000000000000000000")
		return ret
	}()

	root.Commit()
	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{key}, nil)

	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify verkle proof")
	}
}

func BenchmarkProofCalculation(b *testing.B) {
	keys := make([][]byte, 100000)
	root := New()
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			b.Fatal(err)
		}
		keys[i] = key
		if err := root.Insert(key, zeroKeyTest, nil); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, _, _, _, err := MakeVerkleMultiProof(root, nil, [][]byte{keys[len(keys)/2]}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProofVerification(b *testing.B) {
	keys := make([][]byte, 100000)
	root := New()
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			b.Fatal(err)
		}
		keys[i] = key
		if err := root.Insert(key, zeroKeyTest, nil); err != nil {
			b.Fatal(err)
		}
	}

	root.Commit()
	proof, cis, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{keys[len(keys)/2]}, nil)

	b.ResetTimer()
	b.ReportAllocs()

	cfg := GetConfig()
	for i := 0; i < b.N; i++ {
		if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); err != nil || !ok {
			b.Fatal(err)
		}
	}
}

func TestProofSerializationNoAbsentStem(t *testing.T) {
	t.Parallel()

	const leafCount = 1000

	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("could not read random bytes: %v", err)
		}
		keys[i] = key
		if err := root.Insert(key, fourtyKeyTest, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
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
		if err := root.Insert(key, fourtyKeyTest, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
	}
	root.Commit()

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
		if err := root.Insert(key, fourtyKeyTest, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
	}
	root.Commit()

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

	pe, _, _, err := root.GetProofItems(Keylist{absentkey[:]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := GetConfig()
	if ok, err := verifyVerkleProof(deserialized, pe.Cis, pe.Zis, pe.Yis, cfg); !ok || err != nil {
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
	if ok, err := verifyVerkleProof(proof, cs, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify proof")
	}
}

func TestProofOfAbsenceOtherMultipleLeaves(t *testing.T) {
	t.Parallel()

	// Create a stem that isn't the one that will be proven,
	// but does look the same for most of its length.
	root := New()
	key, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030000")
	if err := root.Insert(key, testValue, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	rootC := root.Commit()

	ret1, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030300")
	ret2, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030301")
	proof, cs, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ret1, ret2}, nil)
	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cs, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify proof")
	}

	if len(proof.PoaStems) > 1 {
		t.Fatalf("invalid number of proof-of-absence stems: %d", len(proof.PoaStems))
	}

	deserialized, err := PreStateTreeFromProof(proof, rootC)
	if err != nil {
		t.Fatalf("error deserializing %v", err)
	}

	got, err := deserialized.Get(ret1, nil)
	if err != nil {
		t.Fatalf("error while trying to read missing value: %v", err)
	}
	if got != nil {
		t.Fatalf("should have returned nil, got: %v", got)
	}

	// simulate the execution of a tx that creates a leaf at an address that isn't the one that is
	// proven for absence, but needs to be inserted in the proof-of-absence stem.
	// It differs from the poa stem here: 🠃
	ret3, _ := hex.DecodeString("0303030304030303030303030303030303030303030303030303030303030300")
	err = deserialized.Insert(ret3, testValue, nil)
	if err != nil {
		t.Fatalf("error inserting value in proof-of-asbsence stem: %v", err)
	}

	// check that there are splits up to depth 4
	node := deserialized.(*InternalNode)
	for node.depth < 4 {
		child, ok := node.children[ret3[node.depth]].(*InternalNode)
		if !ok {
			t.Fatalf("expected Internal node at depth %d, trie = %s", node.depth, ToDot(deserialized))
		}
		node = child
	}

	if _, ok := node.children[ret3[4]].(*LeafNode); !ok {
		t.Fatalf("expected leaf node at depth 5, got %v", node.children[ret3[4]])
	}
	if ln, ok := node.children[key[4]].(*LeafNode); !ok || !ln.isPOAStub {
		t.Fatalf("expected unknown node at depth 5, got %v", node.children[key[4]])
	}
}

func TestProofOfAbsenceNoneMultipleStems(t *testing.T) {
	t.Parallel()

	root := New()
	key, _ := hex.DecodeString("0403030303030303030303030303030303030303030303030303030303030000")
	if err := root.Insert(key, testValue, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	root.Commit()

	ret1, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030300")
	ret2, _ := hex.DecodeString("0303030303030303030303030303030303030303030303030303030303030200")
	proof, cs, zis, yis, _ := MakeVerkleMultiProof(root, nil, [][]byte{ret1, ret2}, nil)
	cfg := GetConfig()
	if ok, err := verifyVerkleProof(proof, cs, zis, yis, cfg); !ok || err != nil {
		t.Fatal("could not verify proof")
	}

	if len(proof.PoaStems) != 0 {
		t.Fatalf("invalid number of proof-of-absence stems: %d", len(proof.PoaStems))
	}

	if len(proof.ExtStatus) != 2 {
		t.Fatalf("invalid number of extension statuses: %d ≠ 2", len(proof.ExtStatus))
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

	expectedJSON := `{"suffix":65,"currentValue":"0x102030405060708090a0b0c0d0e0f000112233445566778899aabbccddeeff00","newValue":null}`
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
		Stem: [StemSize]byte{10},
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

	expectedJSON := `{"stem":"0x0a000000000000000000000000000000000000000000000000000000000000","suffixDiffs":[{"suffix":65,"currentValue":"0x102030405060708090a0b0c0d0e0f000112233445566778899aabbccddeeff00","newValue":null}]}`
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

	expectedJSON := `{"suffix":65,"currentValue":null,"newValue":null}`
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
		OtherStems:            [][StemSize]byte{{1}, {2}, {3}},
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

	insertKVs := map[string][]byte{
		string(zeroKeyTest):   fourtyKeyTest,
		string(oneKeyTest):    fourtyKeyTest,
		string(fourtyKeyTest): fourtyKeyTest,
		string(ffx32KeyTest):  fourtyKeyTest,
	}
	proveKeys := Keylist{zeroKeyTest, fourtyKeyTest}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestStatelessDeserializeMissingLeafNode(t *testing.T) {
	t.Parallel()

	insertKVs := map[string][]byte{
		string(zeroKeyTest):  fourtyKeyTest,
		string(oneKeyTest):   fourtyKeyTest,
		string(ffx32KeyTest): fourtyKeyTest,
	}
	proveKeys := Keylist{zeroKeyTest, fourtyKeyTest}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestStatelessDeserializeAbsentValueInExistingLeafNode(t *testing.T) {
	t.Parallel()

	insertKVs := map[string][]byte{
		string(zeroKeyTest):  fourtyKeyTest,
		string(ffx32KeyTest): fourtyKeyTest,
	}
	proveKeys := Keylist{zeroKeyTest, oneKeyTest}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestStatelessDeserializeDepth2(t *testing.T) {
	t.Parallel()

	key1, _ := hex.DecodeString("0000010000000000000000000000000000000000000000000000000000000000")
	insertKVs := map[string][]byte{
		string(zeroKeyTest):  fourtyKeyTest,
		string(key1):         fourtyKeyTest,
		string(ffx32KeyTest): fourtyKeyTest,
	}
	proveKeys := Keylist{zeroKeyTest, key1}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestProofVerificationThreeStemsInSameExtensionStatus(t *testing.T) {
	t.Parallel()

	key2_0, _ := hex.DecodeString("0002000000000000000000000000000000000000000000000000000000000000")
	key3_0, _ := hex.DecodeString("0003000000000000000000000000000000000000000000000000000000000000")
	key3_1, _ := hex.DecodeString("0003000000000000000000000000000000000000000000000000000000000001")
	key4_0, _ := hex.DecodeString("0004000000000000000000000000000000000000000000000000000000000000")

	insertKVs := map[string][]byte{
		string(key3_0): fourtyKeyTest,
		string(key3_1): fourtyKeyTest,
	}
	proveKeys := Keylist{zeroKeyTest, key2_0, key3_0, key3_1, key4_0}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestProofVerificationTwoLeavesWithDifferentValues(t *testing.T) {
	t.Parallel()

	key2, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")

	insertKVs := map[string][]byte{
		string(zeroKeyTest): fourtyKeyTest,
		string(key2):        forkOneKeyTest,
	}
	proveKeys := Keylist{zeroKeyTest, key2}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestProofOfAbsenceBorderCase(t *testing.T) {
	t.Parallel()

	key1, _ := hex.DecodeString("0001000000000000000000000000000000000000000000000000000000000001")

	insertKVs := map[string][]byte{
		string(oneKeyTest): fourtyKeyTest,
	}
	proveKeys := Keylist{oneKeyTest, key1}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func TestProofOfAbsenceBorderCaseReversed(t *testing.T) {
	t.Parallel()

	key1, _ := hex.DecodeString("0001000000000000000000000000000000000000000000000000000000000001")

	insertKVs := map[string][]byte{
		string(key1): fourtyKeyTest,
	}
	proveKeys := Keylist{oneKeyTest, key1}

	testSerializeDeserializeProof(t, insertKVs, proveKeys)
}

func testSerializeDeserializeProof(t *testing.T, insertKVs map[string][]byte, proveKeys Keylist) {
	t.Helper()

	root := New()

	for k, v := range insertKVs {
		if err := root.Insert([]byte(k), v, nil); err != nil {
			t.Fatalf("could not insert key: %v", err)
		}
	}
	root.Commit()

	absentKeys := map[string]struct{}{}
	proveKVs := map[string][]byte{}
	for _, key := range proveKeys {
		value, ok := insertKVs[string(key)]
		if !ok {
			// Trying to prove an absent key, skip it.
			// Note that it *will* be considering for the proof generation, but
			// doesn't make sense for `proveKVs`.
			absentKeys[string(key)] = struct{}{}
			continue
		}
		proveKVs[string(key)] = value
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, proveKeys, nil)

	serialized, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}
	dproof, err := DeserializeProof(serialized, statediff)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}
	droot, err := PreStateTreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	// For each proving key-value, each branch in the original and reconstructed tree nodes
	// should match their commitments and values.
	for _, key := range proveKeys {
		originalPath := getKeyFullPath(root, key)
		reconstructedPath := getKeyFullPath(droot, key)

		// Original and reconstructed path lengths must match.
		if len(originalPath) != len(reconstructedPath) {
			t.Fatalf("key %x: original path has %d nodes, reconstructed path has %d nodes", key, len(originalPath), len(reconstructedPath))
		}

		// Each node commitment in the original and reconstructed path must match.
		for i := range originalPath {
			if !originalPath[i].Commit().Equal(reconstructedPath[i].Commit()) {
				t.Fatalf("key %x: node %d: original path node commitment %x, reconstructed path node commitment %x", key, i, originalPath[i].Commit().Bytes(), reconstructedPath[i].Commit().Bytes())
			}
		}

		// If this proved key isn't absent, check that the last element is a leaf node, and that the value matches.
		if value, ok := proveKVs[string(key)]; ok {
			reconstructedLeafNode := reconstructedPath[len(reconstructedPath)-1].(*LeafNode)
			if !bytes.Equal(reconstructedLeafNode.values[key[31]], value) {
				t.Fatalf("value for key %x does not match", key)
			}
		}

		// If the key should be absent, check that the last element of the path is effectively:
		// - An empty node, or
		// - A leaf node with unmatching stem.
		if _, ok := absentKeys[string(key)]; ok {
			lastNode := reconstructedPath[len(reconstructedPath)-1]
			switch lastNode := lastNode.(type) {
			case Empty:
				// There's "nothing" in the tree, so it's fine.
			case *LeafNode:
				// If there's a LeafNode, it must **not** be one with a matching stem.
				if bytes.Equal(lastNode.stem, key) {
					t.Fatalf("key %x: last node is a leaf node with matching stem", key)
				}
			default:
				// We can't find any other node type, so it's an error.
				t.Fatalf("key %x: last node is neither an empty node nor a leaf node", key)
			}
		}
	}
}

func getKeyFullPath(node VerkleNode, key []byte) []VerkleNode {
	switch node := node.(type) {
	case *InternalNode:
		return append([]VerkleNode{node}, getKeyFullPath(node.children[offset2key(key, node.depth)], key)...)
	case *LeafNode:
		return []VerkleNode{node}
	case Empty:
		return []VerkleNode{node}
	default:
		panic(fmt.Sprintf("unknown node type: %T", node))
	}
}

func TestProofVerificationWithPostState(t *testing.T) { // skipcq: GO-R1005
	t.Parallel()

	testlist := []struct {
		name                                                string
		keys, values, keystoprove, updatekeys, updatevalues [][]byte
	}{
		{
			// overwrite a key
			name:         "update_in_leaf_node",
			keys:         [][]byte{zeroKeyTest, oneKeyTest, ffx32KeyTest},
			values:       [][]byte{zeroKeyTest, zeroKeyTest, zeroKeyTest},
			keystoprove:  [][]byte{zeroKeyTest},
			updatekeys:   [][]byte{zeroKeyTest},
			updatevalues: [][]byte{fourtyKeyTest},
		},
		{
			// check for a key present at the root level
			name:         "new_key_in_internal_node",
			keys:         [][]byte{zeroKeyTest, oneKeyTest, ffx32KeyTest},
			values:       [][]byte{zeroKeyTest, zeroKeyTest, zeroKeyTest},
			keystoprove:  [][]byte{ffx32KeyTest, zeroKeyTest, fourtyKeyTest}, // all modified values must be proven
			updatekeys:   [][]byte{zeroKeyTest, fourtyKeyTest},
			updatevalues: [][]byte{fourtyKeyTest, fourtyKeyTest},
		},
		{
			// prove an absent key at the root level
			name:         "absent_in_internal_node",
			keys:         [][]byte{zeroKeyTest, oneKeyTest, ffx32KeyTest},
			values:       [][]byte{zeroKeyTest, zeroKeyTest, zeroKeyTest},
			keystoprove:  [][]byte{zeroKeyTest, fourtyKeyTest},
			updatekeys:   [][]byte{zeroKeyTest, fourtyKeyTest},
			updatevalues: [][]byte{fourtyKeyTest, fourtyKeyTest},
		},
		{
			// prove an absent key at the leaf level
			name:         "absent_in_leaf_node",
			keys:         [][]byte{zeroKeyTest, fourtyKeyTest, ffx32KeyTest},
			values:       [][]byte{zeroKeyTest, zeroKeyTest, zeroKeyTest},
			keystoprove:  [][]byte{oneKeyTest, zeroKeyTest, fourtyKeyTest}, // all modified values must be proven
			updatekeys:   [][]byte{zeroKeyTest, fourtyKeyTest},
			updatevalues: [][]byte{oneKeyTest, fourtyKeyTest},
		},
	}
	for _, data := range testlist {
		data := data // make linter happy by not capturing the loop variable

		t.Run(fmt.Sprintf("verification_with_post_state/%s", data.name), func(t *testing.T) {
			t.Parallel()

			if len(data.keys) != len(data.values) {
				t.Fatalf("incompatible number of keys and values: %d != %d", len(data.keys), len(data.values))
			}

			if len(data.updatekeys) != len(data.updatevalues) {
				t.Fatalf("incompatible number of post-state keys and values: %d != %d", len(data.updatekeys), len(data.updatevalues))
			}

			root := New()
			for i := range data.keys {
				if err := root.Insert(data.keys[i], data.values[i], nil); err != nil {
					t.Fatalf("could not insert key: %v", err)
				}
			}
			rootC := root.Commit()

			postroot := root.Copy()
			for i := range data.updatekeys {
				if err := postroot.Insert(data.updatekeys[i], data.updatevalues[i], nil); err != nil {
					t.Fatalf("could not insert key: %v", err)
				}
			}
			postroot.Commit()

			proof, _, _, _, _ := MakeVerkleMultiProof(root, postroot, data.keystoprove, nil)

		keys:
			for i := range proof.Keys {
				// Check that the pre-state value is the one that we originally inserted.
				for j := range data.keys {
					if bytes.Equal(proof.Keys[i], data.keys[j]) {
						if !bytes.Equal(proof.PreValues[i], data.values[j]) {
							t.Fatalf("pre-state value mismatch for key %x: %x != %x", data.keys[j], proof.PreValues[i], data.values[j])
						}
						break
					}
				}

				for j := range data.updatekeys {
					// The the key was updated then check that the post-state value is the updated value.
					if bytes.Equal(proof.Keys[i], data.updatekeys[j]) {
						if !bytes.Equal(proof.PostValues[i], data.updatevalues[j]) {
							t.Fatalf("post-state value mismatch for key %x: %x != %x", data.updatekeys[j], proof.PostValues[i], data.updatevalues[j])
						}
						continue keys
					}
				}
				// If the key was not updated then check that the post-state value is null.
				if proof.PostValues[i] != nil {
					t.Fatalf("post-state value mismatch for key %x: %x != nil", proof.Keys[i], proof.PostValues[i])
				}
			}

			p, diff, err := SerializeProof(proof)
			if err != nil {
				t.Fatalf("error serializing proof: %v", err)
			}

			dproof, err := DeserializeProof(p, diff)
			if err != nil {
				t.Fatalf("error deserializing proof: %v", err)
			}

			if err = verifyVerkleProofWithPreState(dproof, root); err != nil {
				t.Fatalf("could not verify verkle proof: %v, original: %s reconstructed: %s", err, ToDot(root), ToDot(postroot))
			}

			dpreroot, err := PreStateTreeFromProof(dproof, rootC)
			if err != nil {
				t.Fatalf("error recreating pre tree: %v", err)
			}

			dpostroot, err := PostStateTreeFromStateDiff(dpreroot, diff)
			if err != nil {
				t.Fatalf("error recreating post tree: %v", err)
			}
			// Check that the reconstructed post-state tree root matches the real tree.
			if !postroot.Commitment().Equal(dpostroot.Commitment()) {
				t.Fatalf("differing root commitments %x != %x", dpostroot.Commitment().Bytes(), postroot.Commitment().Bytes())
			}

			if err = verifyVerkleProofWithPreState(dproof, dpreroot); err != nil {
				t.Fatalf("could not verify verkle proof: %v, original: %s reconstructed: %s", err, ToDot(dpreroot), ToDot(dpostroot))
			}
		})
	}
}

func TestGenerateProofWithOnlyAbsentKeys(t *testing.T) {
	t.Parallel()

	// Create a tree with only one key.
	root := New()
	presentKey, _ := hex.DecodeString("4000000000000000000000000000000000000000000000000000000000000000")
	if err := root.Insert(presentKey, zeroKeyTest, nil); err != nil {
		t.Fatalf("inserting into the original failed: %v", err)
	}
	root.Commit()

	// Create a proof with a key with the same first byte, but different second byte (i.e: absent).
	absentKey, _ := hex.DecodeString("4010000000000000000000000000000000000000000000000000000000000000")
	proof, cis, zis, yis, err := MakeVerkleMultiProof(root, nil, Keylist{absentKey}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// It must pass.
	if ok, err := verifyVerkleProof(proof, cis, zis, yis, cfg); !ok || err != nil {
		t.Fatalf("original proof didn't verify: %v", err)
	}

	// Serialize + Deserialize + build tree from proof.
	vp, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	dproof, err := DeserializeProof(vp, statediff)
	if err != nil {
		t.Fatal(err)
	}
	droot, err := PreStateTreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	// From the rebuilt tree, validate the proof.
	pe, _, _, err := GetCommitmentsForMultiproof(droot, Keylist{absentKey}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// It must pass.
	if ok, err := verifyVerkleProof(dproof, pe.Cis, pe.Zis, pe.Yis, cfg); !ok || err != nil {
		t.Fatalf("reconstructed proof didn't verify: %v", err)
	}

	// Double-check that if we try to access any key in 40000000000000000000000000000000000000000000000000000000000000{XX}
	// in the reconstructed tree, we get an error. This LeafNode is only supposed to prove
	// the absence of 40100000000000000000000000000000000000000000000000000000000000{YY}, so
	// we don't know anything about any value for slots XX.
	for i := 0; i < common.VectorLength; i++ {
		var key [32]byte
		copy(key[:], presentKey)
		key[StemSize] = byte(i)
		if _, err := droot.Get(key[:], nil); err != errIsPOAStub {
			t.Fatalf("expected ErrPOALeafValue, got %v", err)
		}
	}

	// The same applies to trying to insert values in this LeafNode, this shouldn't be allowed since we don't know
	// anything about C1 or C2 to do a proper updating.
	for i := 0; i < common.VectorLength; i++ {
		var key [32]byte
		copy(key[:], presentKey)
		key[StemSize] = byte(i)
		if err := droot.Insert(key[:], zeroKeyTest, nil); err != errIsPOAStub {
			t.Fatalf("expected ErrPOALeafValue, got %v", err)
		}
	}
}

func TestDoubleProofOfAbsence(t *testing.T) {
	t.Parallel()

	root := New()

	// Insert some keys.
	key11, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	key12, _ := hex.DecodeString("0003000000000000000000000000000000000000000000000000000000000001")

	if err := root.Insert(key11, fourtyKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	if err := root.Insert(key12, fourtyKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}

	// Try to prove to different stems that end up in the same LeafNode without any other proof of presence
	// in that leaf node. i.e: two proof of absence in the same leaf node with no proof of presence.
	key2, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000100")
	key3, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000200")
	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, Keylist{key2, key3}, nil)

	serialized, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, statediff)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := PreStateTreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	if !droot.Commit().Equal(root.Commit()) {
		t.Fatal("differing root commitments")
	}

	// Depite we have two proof of absences for different steams, we should only have one
	// stem in `others`. i.e: we only need one for both steams.
	if len(proof.PoaStems) != 1 {
		t.Fatalf("invalid number of proof-of-absence stems: %d", len(proof.PoaStems))
	}

	// We need one extension status for each stem.
	if len(proof.ExtStatus) != 2 {
		t.Fatalf("invalid number of extension status: %d", len(proof.PoaStems))
	}
}

func TestProveAbsenceInEmptyHalf(t *testing.T) {
	t.Parallel()

	root := New()

	key1, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000FF")

	if err := root.Insert(key1, fourtyKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}
	if err := root.Insert(key1, fourtyKeyTest, nil); err != nil {
		t.Fatalf("could not insert key: %v", err)
	}

	key2, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000100")
	key3, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	proof, _, _, _, _ := MakeVerkleMultiProof(root, nil, Keylist{key2, key3}, nil)

	serialized, statediff, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, statediff)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := PreStateTreeFromProof(dproof, root.Commit())
	if err != nil {
		t.Fatal(err)
	}

	if !droot.Commit().Equal(root.Commit()) {
		t.Fatal("differing root commitments")
	}

	if len(proof.PoaStems) != 0 {
		t.Fatalf("invalid number of proof-of-absence stems: %d", len(proof.PoaStems))
	}

	if len(proof.ExtStatus) != 2 {
		t.Fatalf("invalid number of extension status: %d", len(proof.ExtStatus))
	}
}
