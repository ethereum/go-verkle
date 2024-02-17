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
	"strconv"
	"testing"
	"time"

	"github.com/crate-crypto/go-ipa/banderwagon"
)

var identity *Point

func init() {
	var id Point
	id.SetIdentity()
	identity = &id
}

func extensionAndSuffixOneKey(t *testing.T, key, value []byte, ret *Point) {
	var (
		v                               Fr
		vs                              [2]Fr
		cfg                             = GetConfig()
		srs                             = cfg.conf.SRS
		stemComm1, stemComm3, stemComm2 Point
		t1, t2, c1                      Point
	)
	stemComm0 := srs[0]
	err := StemFromLEBytes(&v, KeyToStem(key))
	if err != nil {
		panic(err)
	}
	stemComm1.ScalarMul(&srs[1], &v)

	if err := leafToComms(vs[:], value); err != nil {
		t.Fatalf("leafToComms failed: %s", err)
	}
	c1.Add(t1.ScalarMul(&srs[2*key[StemSize]], &vs[0]), t2.ScalarMul(&srs[2*key[StemSize]+1], &vs[1]))
	c1.MapToScalarField(&v)
	stemComm2.ScalarMul(&srs[2], &v)

	v.SetZero()
	stemComm3.ScalarMul(&srs[3], &v)

	t1.Add(&stemComm0, &stemComm1)
	t2.Add(&stemComm2, &stemComm3)
	ret.Add(&t1, &t2)
}

func TestInsertKey0Value0(t *testing.T) {
	t.Parallel()

	var (
		expected  Fr
		root      = New()
		expectedP Point
		cfg       = GetConfig()
		srs       = cfg.conf.SRS
	)

	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("insert failed: %s", err)
	}
	comm := root.Commit()

	extensionAndSuffixOneKey(t, zeroKeyTest, zeroKeyTest, &expectedP)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	expectedP.MapToScalarField(&expected)
	expectedP.ScalarMul(&srs[0], &expected)

	if !comm.Equal(&expectedP) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestInsertKey1Value1(t *testing.T) {
	t.Parallel()

	var (
		v, expected Fr
		root        = New()
		expectedP   Point
		cfg         = GetConfig()
		srs         = cfg.conf.SRS
	)
	key := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	if err := root.Insert(key, key, nil); err != nil {
		t.Fatalf("insert failed: %s", err)
	}
	comm := root.Commit()

	extensionAndSuffixOneKey(t, key, key, &expectedP)
	expectedP.MapToScalarField(&v)
	expectedP.ScalarMul(&srs[1], &v)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	if !comm.Equal(&expectedP) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestInsertSameStemTwoLeaves(t *testing.T) {
	t.Parallel()

	var (
		v, expected                     Fr
		vs                              [2]Fr
		root                            = New()
		expectedP, c1, c2, t1, t2       Point
		stemComm1, stemComm3, stemComm2 Point
		cfg                             = GetConfig()
		srs                             = cfg.conf.SRS
	)
	key_a := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	key_b := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 128,
	}
	if err := root.Insert(key_a, key_a, nil); err != nil {
		t.Fatalf("insert failed: %s", err)
	}
	if err := root.Insert(key_b, key_b, nil); err != nil {
		t.Fatalf("insert failed: %s", err)
	}
	comm := root.Commit()

	stemComm0 := srs[0]
	err := StemFromLEBytes(&v, KeyToStem(key_a))
	if err != nil {
		t.Fatal(err)
	}
	stemComm1.ScalarMul(&srs[1], &v)

	if err := leafToComms(vs[:], key_a); err != nil {
		t.Fatalf("leafToComms failed: %s", err)
	}
	c1.Add(t1.ScalarMul(&srs[64], &vs[0]), t2.ScalarMul(&srs[65], &vs[1]))
	c1.MapToScalarField(&v)
	stemComm2.ScalarMul(&srs[2], &v)

	if err := leafToComms(vs[:], key_b); err != nil {
		t.Fatalf("leafToComms failed: %s", err)
	}
	c2.Add(t1.ScalarMul(&srs[0], &vs[0]), t2.ScalarMul(&srs[1], &vs[1]))
	c2.MapToScalarField(&v)
	stemComm3.ScalarMul(&srs[3], &v)

	t1.Add(&stemComm0, &stemComm1)
	t2.Add(&stemComm2, &stemComm3)
	expectedP.Add(&t1, &t2)
	expectedP.MapToScalarField(&v)
	expectedP.ScalarMul(&srs[1], &v)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	if !comm.Equal(&expectedP) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestInsertKey1Val1Key2Val2(t *testing.T) {
	t.Parallel()

	var (
		v, v1, v2, expected Fr
		root                = New()
		expectedP, t1, t2   Point
		cfg                 = GetConfig()
		srs                 = cfg.conf.SRS
	)
	key_b, _ := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != nil {
		t.Fatalf("insert failed: %s", err)
	}
	if err := root.Insert(key_b, key_b, nil); err != nil {
		t.Fatalf("insert failed: %s", err)
	}
	comm := root.Commit()
	fmt.Println(root.toDot("", ""))

	extensionAndSuffixOneKey(t, zeroKeyTest, zeroKeyTest, &t1)
	t1.MapToScalarField(&v1)

	extensionAndSuffixOneKey(t, key_b, key_b, &t2)
	t2.MapToScalarField(&v2)

	expectedP.Add(t1.ScalarMul(&srs[0], &v1), t2.ScalarMul(&srs[1], &v2))
	expectedP.MapToScalarField(&v)

	if expectedP.Equal(identity) {
		t.Fatal("commitment is identity")
	}

	if !comm.Equal(&expectedP) {
		t.Fatalf("invalid root commitment %v != %v", comm, &expected)
	}
}

func TestEmptyTrie(t *testing.T) {
	t.Parallel()

	root := New()
	comm := root.Commit()

	if !comm.Equal(identity) {
		t.Fatalf("invalid root commitment %v != %v", comm, identity)
	}
}

func TestGroupToField(t *testing.T) {
	t.Parallel()

	point := banderwagon.Generator
	var v Fr
	point.MapToScalarField(&v)
	bytes := v.BytesLE()
	hexStr := hex.EncodeToString(bytes[:])
	if hexStr != "d1e7de2aaea9603d5bc6c208d319596376556ecd8336671ba7670c2139772d14" {
		t.Fatalf("group to field not working")
	}
}

func BenchmarkGroupToField(b *testing.B) {
	b.Run("single", func(b *testing.B) {
		point := banderwagon.Generator
		var v Fr
		for i := 0; i < b.N; i++ {
			point.MapToScalarField(&v)
		}
	})

	b.Run("multiple", func(b *testing.B) {
		for i := 1; i <= 256; i *= 2 {
			b.Run(strconv.Itoa(i), func(b *testing.B) {
				// Generate `i` ~distinct points
				points := make([]*Point, i)
				points[0] = &banderwagon.Generator
				for k := 1; k < i; k++ {
					points[k] = &Point{}
					points[k].Add(points[k-1], &banderwagon.Generator)
				}
				sink := make([]Fr, i)
				ptrs := make([]*Fr, i)
				for i := range sink {
					ptrs[i] = &sink[i]
				}
				now := time.Now()
				b.ReportAllocs()
				b.ResetTimer()
				for k := 0; k < b.N; k++ {
					if err := banderwagon.BatchMapToScalarField(ptrs, points); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(time.Since(now).Nanoseconds()/int64(i))/float64(b.N), "ns/value")
				_ = sink
			})
		}
	})
}

func TestPaddingInFromLEBytes(t *testing.T) {
	t.Parallel()

	var fr1, fr2 Fr
	if err := FromLEBytes(&fr1, ffx32KeyTest[:16]); err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")
	err := StemFromLEBytes(&fr2, KeyToStem(key))
	if err != nil {
		t.Fatal(err)
	}

	if !fr1.Equal(&fr2) {
		t.Fatal("byte alignment")
	}
}
