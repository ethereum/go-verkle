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

func TestMainnetStart(t *testing.T) {
	tree := New()
	type KV struct {
		key   string
		value string
	}

	kvs := []KV{
		{
			"00000013653234c2d78dcdc645c5141e358ef2e590fe5278778ba729ff5ffd95",
			"f84b01871c2decb3cd3400a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"0000008c38d769d75c1ad1de6660da51edc10394c11c50ff9a0ca9e8b8b35dc2",
			"f84a0986825807966613a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"000000a55a3faa6b402bf3ac46a382c003ca1f9d21177dc31008bab92bdf1529",
			"f8440180a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a01d93f60f105899172f7255c030301c3af4564edd4a48577dbdc448aec7ddb0ac",
		},
		{
			"000000cd919b672081922775cc5884e4e1cd795a2bbbd9473f16c7a44ad98b40",
			"f84c808802069e3c5b1d6800a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"000000d88546b028daa8674473bb11f665ee45f3962d4887bbce611f5d9f2edf", "f84b0387023a8ff9da7800a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
	}

	for _, kv := range kvs {
		key, _ := hex.DecodeString(kv.key)
		value, _ := hex.DecodeString(kv.value)
		tree.InsertOrdered(key, value, nil)
	}

	h := to32(tree.ComputeCommitment())
	expected, _ := hex.DecodeString("e30755d01dd41efcde937ccb3bc1d6b9fc02750d5fa01b9f72bfae08272e3c15")
	if !bytes.Equal(h[:], expected) {
		t.Fatalf("invalid hash: %x != %x", h, expected)
	}
}

func TestComputeRootCommitmentThreeLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(fourtyKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	expected, _ := hex.DecodeString("ce0d500278c74d9f1037110c6850bab98b25411480835827773655a0fb99ba31")

	got := to32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment hash %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeaves(t *testing.T) {
	root := New()
	root.InsertOrdered(zeroKeyTest, zeroKeyTest, nil)
	root.InsertOrdered(fourtyKeyTest, zeroKeyTest, nil)
	root.InsertOrdered(ffx32KeyTest, zeroKeyTest, nil)

	// This still needs to be called, so that the root
	// commitment is calculated.
	got := to32(root.ComputeCommitment())

	expected, _ := hex.DecodeString("ce0d500278c74d9f1037110c6850bab98b25411480835827773655a0fb99ba31")

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentThreeLeavesDeep(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	expected, _ := hex.DecodeString("a903c65734f8c8e8713de096a9cd02d11b302a7cf32d9c533d390ce247a5ce2e")

	got := to32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
func TestComputeRootCommitmentOneLeaf(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)

	expected, _ := hex.DecodeString("e43eedf125a98aadded6d4e2522936cb6469cfb0e65a2aa529b1058b9018e34b")

	got := to32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment hash %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentTwoLeavesLastLevel(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(oneKeyTest, testValue, nil)

	expected, _ := hex.DecodeString("27227aba0a5a1f6a03f171c27684442fe5b0c71e1a50705bcbd3816628a6a733")

	got := to32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentTwoLeaves256(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(ffx32KeyTest, testValue, nil)
	expected, _ := hex.DecodeString("ab4feb82e38b3e447eb14129f33f9be27ecb8938b0f6f4e2e6ff50984d547420")

	got := to32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
