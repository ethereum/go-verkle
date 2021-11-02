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
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestProofVerifyTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	proof := MakeVerkleProofOneLeaf(root, ffx32KeyTest)

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(ffx32KeyTest)
	if !VerifyVerkleProof(proof, comms, zis, yis, GetConfig()) {
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

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(keys[0])
	if !VerifyVerkleProof(proof, comms, zis, yis, GetConfig()) {
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

	comms, zis, yis, _ := GetCommitmentsForMultiproof(root, keys[0:2])
	if !VerifyVerkleProof(proof, comms, zis, yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofOfAbsenceLeafVerify(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	proof := MakeVerkleProofOneLeaf(root, oneKeyTest)

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(oneKeyTest)
	if !VerifyVerkleProof(proof, comms, zis, yis, GetConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}
func BenchmarkProofCalculation(b *testing.B) {
	value := []byte("value")
	keys := make([][]byte, 100000)
	root := New()
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, value, nil)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		MakeVerkleProofOneLeaf(root, keys[len(keys)/2])
	}
}

func BenchmarkProofVerification(b *testing.B) {
	value := []byte("value")
	keys := make([][]byte, 100000)
	root := New()
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, value, nil)
	}

	root.ComputeCommitment()
	comms, zis, yis, _ := root.GetCommitmentsAlongPath(keys[len(keys)/2])
	proof := MakeVerkleProofOneLeaf(root, keys[len(keys)/2])

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		VerifyVerkleProof(proof, comms, zis, yis, GetConfig())
	}
}
