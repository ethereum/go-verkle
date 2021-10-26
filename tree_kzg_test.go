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

// +build kzg

package verkle

import (
	"crypto/rand"
	"testing"

	"github.com/protolambda/go-kzg/bls"
)

func TestHashToFrTrailingZeroBytes(t *testing.T) {
	h := hexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var out bls.Fr
	hashToFr(&out, h[:])

	h2 := hexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var expected bls.Fr
	bls.FrFrom32(&expected, h2)

	if !bls.EqualFr(&out, &expected) {
		t.Fatalf("incorrect value received, got %x != %x", out, expected)
	}
}

func TestConcurrentMulG1(t *testing.T) {
	var fr bls.Fr
	bls.AsFr(&fr, 2)
	expected := new(bls.G1Point)
	bls.MulG1(expected, &bls.GenG1, &fr)

	threads := 10
	ch := make(chan *bls.G1Point)
	builder := func() {
		var fr bls.Fr
		bls.AsFr(&fr, 2)
		dst := new(bls.G1Point)
		bls.MulG1(dst, &bls.GenG1, &fr)
		ch <- dst
	}

	for i := 0; i < threads; i++ {
		go builder()
	}

	for i := 0; i < threads; i++ {
		res := <-ch
		if res.String() != expected.String() {
			t.Error("Incorrect fr")
		}
	}
}

func TestTreeHashingPython(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)

	rootcomm := to32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("e43eedf125a98aadded6d4e2522936cb6469cfb0e65a2aa529b1058b9018e34b")

	if !bytes.Equal(rootcomm[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", rootcomm, expected)
	}

}

// Test root commitment calculation when two keys are in the same LeafNode and
// a third one in a different leaf node, at the same root branch node.
func TestTreeHashingPython2(t *testing.T) {
	root := New()

	x, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")

	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(x, zeroKeyTest, nil)

	got := to32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("0d7348e435f0064279359f82e568702c2ac328b3f0f96b080026a760ffc7bf00")

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

// Test root commitment calculation when two keys are in the same LeafNode and
// a third one in a different leaf node, with two levels of branch nodes.
func TestTreeHashingPython3(t *testing.T) {
	root := New()

	x, _ := hex.DecodeString("0001000000000000000000000000000000000000000000000000000000000000")

	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(x, zeroKeyTest, nil)

	got := to32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("67750288c4ae494c96c19327f42ca2ebafb58e7dd3f10b6265be8a091af67c09")

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

// Test root commitment calculation when two keys are in the same LeafNode and
// a third one in a different leaf node, with 31 levels of branch nodes.
func TestTreeHashingPython4(t *testing.T) {
	root := New()

	x, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000100")

	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(x, zeroKeyTest, nil)

	got := to32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("c12fd7ded4eb4e7a71a2b2bc4d04ba1d91373e58ab7694b572a13f46941f5772")
	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
