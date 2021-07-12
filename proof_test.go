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
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

func TestProofGenerationTwoLeaves(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	// Calculate all commitments
	_ = root.ComputeCommitment()

	var s bls.Fr
	bls.SetFr(&s, "1927409816240961209460912649124")
	d, y, sigma := MakeVerkleProofOneLeaf(root, zeroKeyTest)

	expectedD := common.Hex2Bytes("91f4e5143a09ca7790b4f53c935373b1c6d1937ef2fdf6977e89ab0bfb8b73bfce43bce0fe984f7ec947316a5b34dad1")

	if !bytes.Equal(expectedD, bls.ToCompressedG1(d)) {
		t.Fatalf("invalid D commitment, expected %x, got %x", expectedD, bls.ToCompressedG1(d))
	}

	expectedY := "7618404032391274417229384113230716900497840028846036015530027196456445077944"
	gotY := bls.FrStr(y)
	if expectedY != gotY {
		t.Fatalf("invalid y, expected %s != %s", expectedY, gotY)
	}

	expectedSigma := common.Hex2Bytes("83b4086446466bcda2464bfa5ec058a9873206c10402afc0735a6ff91a770329617aa65693358fde7ad5400538d56df3")
	if !bytes.Equal(expectedSigma, bls.ToCompressedG1(sigma)) {
		t.Fatalf("invalid sigma, expected %x, got %x", expectedSigma, bls.ToCompressedG1(sigma))
	}
}

func TestProofVerifyTwoLeaves(t *testing.T) {
	s1, s2 := kzg.GenerateTestingSetup("8927347823478352432985", 1024)
	fftCfg := kzg.NewFFTSettings(10)
	ks := kzg.NewKZGSettings(fftCfg, s1, s2)
	var err error
	lg1, err = fftCfg.FFTG1(s1, true)
	if err != nil {
		panic(err)
	}

	var tc *TreeConfig
	root := New(10)
	if root, ok := root.(*InternalNode); !ok {
		t.Fatal("root node isn't an *InternalNode")
	} else {
		tc = root.treeConfig
	}
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	// Calculate all commitments
	root.ComputeCommitment()

	d, y, sigma := MakeVerkleProofOneLeaf(root, zeroKeyTest)

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(zeroKeyTest)
	if !VerifyVerkleProof(ks, d, sigma, y, comms, zis, yis, tc) {
		t.Fatal("could not verify verkle proof")
	}
}

func BenchmarkProofCalculation(b *testing.B) {
	rand.Seed(time.Now().UnixNano())

	s1, _ := kzg.GenerateTestingSetup("1927409816240961209460912649124", 1024)
	fftCfg := kzg.NewFFTSettings(10)
	var err error
	lg1, err = fftCfg.FFTG1(s1, true)
	if err != nil {
		panic(err)
	}

	value := []byte("value")
	keys := make([][]byte, 100000)
	root := New(10)
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, value)
	}

	// Calculate all commitments
	root.ComputeCommitment()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		MakeVerkleProofOneLeaf(root, keys[len(keys)/2])
	}
}

func BenchmarkProofVerification(b *testing.B) {
	rand.Seed(time.Now().UnixNano())

	s1, s2 := kzg.GenerateTestingSetup("1927409816240961209460912649124", 1024)
	fftCfg := kzg.NewFFTSettings(10)
	ks := kzg.NewKZGSettings(fftCfg, s1, s2)
	var err error
	lg1, err = fftCfg.FFTG1(s1, true)
	if err != nil {
		panic(err)
	}

	value := []byte("value")
	keys := make([][]byte, 100000)
	root := New(10)
	var tc *TreeConfig
	if root, ok := root.(*InternalNode); !ok {
		b.Fatal("root node isn't an *InternalNode")
	} else {
		tc = root.treeConfig
	}
	for i := 0; i < 100000; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, value)
	}

	// Calculate all commitments
	root.ComputeCommitment()

	comms, zis, yis, _ := root.GetCommitmentsAlongPath(keys[len(keys)/2])
	d, y, sigma := MakeVerkleProofOneLeaf(root, keys[len(keys)/2])

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		VerifyVerkleProof(ks, d, sigma, y, comms, zis, yis, tc)
	}
}
