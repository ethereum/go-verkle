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
	"encoding/hex"
	"fmt"
	"testing"
)

var identity *Point

func init() {
	var id Point
	id.Identity()
	identity = &id
}

func extensionAndSuffixOneKey(key, value []byte, ret *Point) {
	var (
		v, v1, v2                       Fr
		srs                             = GetConfig().conf.SRS
		stemComm1, stemComm3, stemComm2 Point
		zero, t1, t2, c1                Point
	)
	stemComm0 := srs[0]
	fromBytes(&v, key[:31])
	stemComm1.ScalarMul(&srs[1], &v)

	fromBytes(&v1, value[:16])
	fromBytes(&v2, value[16:])
	c1.Add(t1.ScalarMul(&srs[2*key[31]], &v1), t2.ScalarMul(&srs[2*key[31]+1], &v2))
	toFr(&v, &c1)
	stemComm2.ScalarMul(&srs[2], &v)

	(&zero).Identity()
	toFr(&v, &zero)
	stemComm3.ScalarMul(&srs[3], &v)

	t1.Add(&stemComm0, &stemComm1)
	t2.Add(&stemComm2, &stemComm3)
	ret.Add(&t1, &t2)
}

func TestInsertKey0Value0(t *testing.T) {
	var (
		expected  Fr
		root      = New()
		expectedP Point
		srs       = GetConfig().conf.SRS
	)

	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	comm := root.ComputeCommitment()

	extensionAndSuffixOneKey(zeroKeyTest, zeroKeyTest, &expectedP)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	toFr(&expected, &expectedP)
	expectedP.ScalarMul(&srs[0], &expected)
	toFr(&expected, &expectedP)

	if !Equal(comm, &expected) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestInsertKey1Value1(t *testing.T) {
	var (
		v, expected Fr
		root        = New()
		expectedP   Point
		srs         = GetConfig().conf.SRS
	)
	key := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	root.Insert(key, key, nil)
	comm := root.ComputeCommitment()

	extensionAndSuffixOneKey(key, key, &expectedP)
	toFr(&v, &expectedP)
	expectedP.ScalarMul(&srs[1], &v)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	toFr(&expected, &expectedP)

	if !Equal(comm, &expected) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestInsertSameStemTwoLeaves(t *testing.T) {
	var (
		v, v1, v2, expected             Fr
		root                            = New()
		expectedP, c1, c2, t1, t2       Point
		stemComm1, stemComm3, stemComm2 Point
		srs                             = GetConfig().conf.SRS
	)
	key_a := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	key_b := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 128,
	}
	root.Insert(key_a, key_a, nil)
	root.Insert(key_b, key_b, nil)
	comm := root.ComputeCommitment()

	stemComm0 := GetConfig().conf.SRS[0]
	fromBytes(&v, key_a[:31])
	stemComm1.ScalarMul(&srs[1], &v)

	fromBytes(&v1, key_a[:16])
	fromBytes(&v2, key_a[16:])
	c1.Add(t1.ScalarMul(&srs[64], &v1), t2.ScalarMul(&srs[65], &v2))
	toFr(&v, &c1)
	stemComm2.ScalarMul(&srs[2], &v)

	fromBytes(&v1, key_b[:16])
	fromBytes(&v2, key_b[16:])
	c2.Add(t1.ScalarMul(&srs[0], &v1), t2.ScalarMul(&srs[1], &v2))
	toFr(&v, &c2)
	stemComm3.ScalarMul(&srs[3], &v)

	t1.Add(&stemComm0, &stemComm1)
	t2.Add(&stemComm2, &stemComm3)
	expectedP.Add(&t1, &t2)
	toFr(&v, &expectedP)
	expectedP.ScalarMul(&srs[1], &v)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	toFr(&expected, &expectedP)

	if !Equal(comm, &expected) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestInsertKey1Val1Key2Val2(t *testing.T) {
	var (
		v, v1, v2, expected Fr
		root                = New()
		expectedP, t1, t2   Point
		srs                 = GetConfig().conf.SRS
	)
	key_b, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(key_b, key_b, nil)
	comm := root.ComputeCommitment()
	fmt.Println(root.toDot("", ""))

	extensionAndSuffixOneKey(zeroKeyTest, zeroKeyTest, &t1)
	toFr(&v1, &t1)

	extensionAndSuffixOneKey(key_b, key_b, &t2)
	toFr(&v2, &t2)

	expectedP.Add(t1.ScalarMul(&srs[0], &v1), t2.ScalarMul(&srs[1], &v2))
	toFr(&v, &expectedP)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	toFr(&expected, &expectedP)

	if !Equal(comm, &expected) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}
