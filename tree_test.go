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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

var testValue = []byte("hello")

var (
	zeroKeyTest   = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")
	oneKeyTest    = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001")
	fourtyKeyTest = common.Hex2Bytes("4000000000000000000000000000000000000000000000000000000000000000")
	ffx32KeyTest  = common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
)

var s1, lg1 []bls.G1Point
var s2 []bls.G2Point
var ks *kzg.KZGSettings

func init() {
	s1, s2 = kzg.GenerateTestingSetup("1927409816240961209460912649124", 1024)
	fftCfg := kzg.NewFFTSettings(10)
	ks = kzg.NewKZGSettings(fftCfg, s1, s2)

	var err error
	lg1, err = fftCfg.FFTG1(s1, true)
	if err != nil {
		panic(err)
	}
}

func TestInsertIntoRoot(t *testing.T) {
	root := New()
	err := root.Insert(zeroKeyTest, testValue)
	if err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*internalNode).children[0].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*internalNode).children[0])
	}

	if !bytes.Equal(leaf.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.value[:])
	}
}

func TestInsertTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	leaf0, ok := root.(*internalNode).children[0].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*internalNode).children[0])
	}

	leaff, ok := root.(*internalNode).children[1023].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*internalNode).children[1023])
	}

	if !bytes.Equal(leaf0.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf0.value[:])
	}

	if !bytes.Equal(leaff.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaff.value[:])
	}
}

func TestGetTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	val, err := root.Get(zeroKeyTest)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("got a different value from the tree than expected %x != %x", val, testValue)
	}

	val, err = root.Get(oneKeyTest)
	if err != errValueNotPresent {
		t.Fatalf("wrong error type, expected %v, got %v", errValueNotPresent, err)
	}

	if val != nil {
		t.Fatalf("got a different value from the tree than expected %x != nil", val)
	}
}

func TestTreeHashing(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	root.Hash()
}
func TestComputeRootCommitmentThreeLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(fourtyKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	expected := []byte{137, 46, 141, 157, 55, 243, 191, 123, 197, 83, 9, 229, 155, 145, 185, 155, 171, 133, 195, 118, 100, 193, 107, 202, 170, 6, 51, 189, 99, 62, 244, 70, 199, 253, 80, 218, 171, 68, 89, 136, 222, 166, 5, 209, 92, 255, 140, 164}

	comm := root.ComputeCommitment(ks, lg1)
	got := compressG1Point(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentThreeLeavesDeep(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(oneKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	expected := []byte{180, 224, 116, 69, 8, 16, 10, 46, 12, 87, 199, 139, 17, 157, 123, 95, 113, 9, 180, 227, 72, 13, 125, 20, 35, 52, 98, 119, 121, 181, 253, 151, 253, 0, 62, 206, 64, 49, 8, 93, 140, 128, 232, 208, 102, 248, 81, 206}

	comm := root.ComputeCommitment(ks, lg1)
	got := compressG1Point(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)
	expected := []byte{178, 195, 197, 132, 158, 141, 115, 80, 222, 187, 37, 145, 15, 184, 242, 86, 101, 164, 144, 51, 239, 90, 232, 100, 78, 178, 253, 145, 36, 168, 30, 75, 100, 185, 100, 14, 198, 48, 14, 95, 3, 252, 185, 73, 183, 195, 153, 44}

	comm := root.ComputeCommitment(ks, lg1)
	got := compressG1Point(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
