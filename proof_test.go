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
	"testing"

	"github.com/protolambda/go-kzg/bls"
)

func TestProofGenerationTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(ffx32KeyTest, testValue, nil)

	var s bls.Fr
	bls.SetFr(&s, "8927347823478352432985")
	d, y, sigma := MakeVerkleProofOneLeaf(root, zeroKeyTest)

	expectedD := hex2Bytes("8447f1ef334970e0d08d2cdad6548580572d85c40a58860c3c414bd3cea98ee658e2ee4417e46c634703256e1e7b69d6")

	if !bytes.Equal(expectedD, bls.ToCompressedG1(d)) {
		t.Fatalf("invalid D commitment, expected %x, got %x", expectedD, bls.ToCompressedG1(d))
	}

	expectedY := "40177438954719495123245064484577777862352110120190834584872037449357612852120"
	gotY := bls.FrStr(y)
	if expectedY != gotY {
		t.Fatalf("invalid y, expected %s != %s", expectedY, gotY)
	}

	expectedSigma := hex2Bytes("987467e96b8ac71f99b1d92402bf4bb7b8a1ddba25531de0d8eeb9a1519501f7888f4561dae08dc206472b094dc291f5")
	if !bytes.Equal(expectedSigma, bls.ToCompressedG1(sigma)) {
		t.Fatalf("invalid sigma, expected %x, got %x", expectedSigma, bls.ToCompressedG1(sigma))
	}
}

func TestProofVerifyTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(hex2Bytes("0100000000000000000000000000000000000000000000000000000000000000"), zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	d, y, sigma := MakeVerkleProofOneLeaf(root, ffx32KeyTest)

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(ffx32KeyTest)
	if !VerifyVerkleProof(d, sigma, y, comms, zis, yis, GetKZGConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestProofVerifyMultipleLeaves(t *testing.T) {
	const leafCount = 1000

	value := []byte("value")
	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, value, nil)
	}

	d, y, sigma := MakeVerkleProofOneLeaf(root, keys[0])

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(keys[0])
	if !VerifyVerkleProof(d, sigma, y, comms, zis, yis, GetKZGConfig()) {
		t.Fatal("could not verify verkle proof")
	}
}

func TestMultiProofVerifyMultipleLeaves(t *testing.T) {
	const leafCount = 1000

	value := []byte("value")
	keys := make([][]byte, leafCount)
	root := New()
	for i := 0; i < leafCount; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, value, nil)
	}

	d, y, sigma, _, _, _ := MakeVerkleMultiProof(root, keys[0:2])

	comms, zis, yis, _ := GetCommitmentsForMultiproof(root, keys[0:2])
	if !VerifyVerkleProof(d, sigma, y, comms, zis, yis, GetKZGConfig()) {
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
	d, y, sigma := MakeVerkleProofOneLeaf(root, keys[len(keys)/2])

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		VerifyVerkleProof(d, sigma, y, comms, zis, yis, GetKZGConfig())
	}
}
