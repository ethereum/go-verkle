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
	"encoding/binary"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"

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

// GenerateTestingSetupWithLagrange creates a setup of n values from the given secret,
// along with the  **for testing purposes only**
func GenerateTestingSetupWithLagrange(secret string, n uint64, fftCfg *kzg.FFTSettings) ([]bls.G1Point, []bls.G2Point, []bls.G1Point, error) {
	var s bls.Fr
	bls.SetFr(&s, secret)

	var sPow bls.Fr
	bls.CopyFr(&sPow, &bls.ONE)

	s1Out := make([]bls.G1Point, n, n)
	s2Out := make([]bls.G2Point, n, n)
	for i := uint64(0); i < n; i++ {
		bls.MulG1(&s1Out[i], &bls.GenG1, &sPow)
		bls.MulG2(&s2Out[i], &bls.GenG2, &sPow)
		var tmp bls.Fr
		bls.CopyFr(&tmp, &sPow)
		bls.MulModFr(&sPow, &tmp, &s)
	}

	s1Lagrange, err := fftCfg.FFTG1(s1Out, true)

	return s1Out, s2Out, s1Lagrange, err
}

func init() {
	var err error
	fftCfg := kzg.NewFFTSettings(10)
	s1, s2, lg1, err = GenerateTestingSetupWithLagrange("1927409816240961209460912649124", 1024, fftCfg)
	if err != nil {
		panic(err)
	}
}

func TestInsertIntoRoot(t *testing.T) {
	root := New(10, lg1)
	err := root.Insert(zeroKeyTest, testValue)
	if err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.value[:])
	}
}

func TestInsertTwoLeaves(t *testing.T) {
	root := New(10, lg1)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	leaf0, ok := root.(*InternalNode).children[0].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	leaff, ok := root.(*InternalNode).children[1023].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[1023])
	}

	if !bytes.Equal(leaf0.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf0.value[:])
	}

	if !bytes.Equal(leaff.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaff.value[:])
	}
}

func TestGetTwoLeaves(t *testing.T) {
	root := New(10, lg1)
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
	root := New(10, lg1)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	root.Hash()
}

func TestComputeRootCommitmentThreeLeaves(t *testing.T) {
	root := New(10, lg1)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(fourtyKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	expected := []byte{137, 46, 141, 157, 55, 243, 191, 123, 197, 83, 9, 229, 155, 145, 185, 155, 171, 133, 195, 118, 100, 193, 107, 202, 170, 6, 51, 189, 99, 62, 244, 70, 199, 253, 80, 218, 171, 68, 89, 136, 222, 166, 5, 209, 92, 255, 140, 164}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeaves(t *testing.T) {
	root := New(10, lg1)
	root.InsertOrdered(zeroKeyTest, testValue, nil)
	root.InsertOrdered(fourtyKeyTest, testValue, nil)
	root.InsertOrdered(ffx32KeyTest, testValue, nil)

	// This still needs to be called, so that the root
	// commitment is calculated.
	comm := root.ComputeCommitment()

	expected := []byte{137, 46, 141, 157, 55, 243, 191, 123, 197, 83, 9, 229, 155, 145, 185, 155, 171, 133, 195, 118, 100, 193, 107, 202, 170, 6, 51, 189, 99, 62, 244, 70, 199, 253, 80, 218, 171, 68, 89, 136, 222, 166, 5, 209, 92, 255, 140, 164}

	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentThreeLeavesDeep(t *testing.T) {
	root := New(10, lg1)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(oneKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	expected := []byte{180, 224, 116, 69, 8, 16, 10, 46, 12, 87, 199, 139, 17, 157, 123, 95, 113, 9, 180, 227, 72, 13, 125, 20, 35, 52, 98, 119, 121, 181, 253, 151, 253, 0, 62, 206, 64, 49, 8, 93, 140, 128, 232, 208, 102, 248, 81, 206}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeavesDeep(t *testing.T) {
	root := New(10, lg1)
	root.InsertOrdered(zeroKeyTest, testValue, nil)
	root.InsertOrdered(oneKeyTest, testValue, nil)
	root.InsertOrdered(ffx32KeyTest, testValue, nil)

	expected := []byte{180, 224, 116, 69, 8, 16, 10, 46, 12, 87, 199, 139, 17, 157, 123, 95, 113, 9, 180, 227, 72, 13, 125, 20, 35, 52, 98, 119, 121, 181, 253, 151, 253, 0, 62, 206, 64, 49, 8, 93, 140, 128, 232, 208, 102, 248, 81, 206}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeavesFlush(t *testing.T) {
	flush := make(chan FlushableNode)
	go func() {
		root := New(10, lg1)
		root.InsertOrdered(zeroKeyTest, testValue, flush)
		root.InsertOrdered(fourtyKeyTest, testValue, flush)
		root.InsertOrdered(ffx32KeyTest, testValue, flush)
		root.(*InternalNode).Flush(flush)
		close(flush)
	}()

	count := 0
	for f := range flush {
		_, isLeaf := f.Node.(*leafNode)
		_, isInternal := f.Node.(*InternalNode)
		if !isLeaf && !isInternal {
			t.Fatal("invalid node type received, expected leaf")
		}
		count++
	}

	if count != 4 {
		t.Fatalf("incorrect number of flushed leaves 4 != %d", count)
	}
}

func TestComputeRootCommitmentTwoLeaves(t *testing.T) {
	root := New(10, lg1)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)
	expected := []byte{178, 195, 197, 132, 158, 141, 115, 80, 222, 187, 37, 145, 15, 184, 242, 86, 101, 164, 144, 51, 239, 90, 232, 100, 78, 178, 253, 145, 36, 168, 30, 75, 100, 185, 100, 14, 198, 48, 14, 95, 3, 252, 185, 73, 183, 195, 153, 44}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestHashToFrTrailingZeroBytes(t *testing.T) {
	modulus, ok := big.NewInt(0).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	if !ok {
		panic("could not get modulus")
	}

	h := common.HexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var out bls.Fr
	hashToFr(&out, h, modulus)

	h2 := common.HexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var expected bls.Fr
	bls.FrFrom32(&expected, h2)

	if !bls.EqualFr(&out, &expected) {
		t.Fatalf("incorrect value received, got %x != %x", out, expected)
	}
}

func TestOffset2Key8BitsWide(t *testing.T) {
	key := common.Hex2Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for i := 0; i < 32; i++ {
		childId := offset2Key(key, i*8, 8)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}
}

func TestOffset2Key10BitsWide(t *testing.T) {
	key := common.Hex2Bytes("00001008030100501807020090280b0300d0380f040110481305015058170601")
	for i := 0; i < 25; i++ {
		childId := offset2Key(key, i*10, 10)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}

	if childIdx := offset2Key(key, 250, 10); childIdx != 16 {
		t.Fatalf("error getting last child number in key %d != %d", childIdx, 16)
	}
}

func TestComputeRootCommitmentTwoLeaves256(t *testing.T) {
	root := New(8, lg1)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)
	expected := []byte{172, 200, 249, 78, 103, 164, 197, 58, 186, 184, 184, 29, 119, 156, 10, 208, 76, 97, 227, 180, 156, 86, 37, 19, 13, 133, 10, 37, 51, 57, 110, 14, 49, 24, 89, 163, 164, 88, 162, 55, 72, 19, 234, 219, 139, 132, 81, 199}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func BenchmarkCommit1kLeaves(b *testing.B) {
	benchmarkCommitNLeaves(b, 1000)
}

func BenchmarkCommit10kLeaves(b *testing.B) {
	benchmarkCommitNLeaves(b, 10000)
}

func BenchmarkCommitFullNode(b *testing.B) {
	value := []byte("value")
	keys := make([][]byte, 1024)
	for i := 0; i < 1024; i++ {
		key := make([]byte, 32)
		binary.BigEndian.PutUint16(key[:2], uint16(i)<<6)
		keys[i] = key
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		root := New(10, lg1)
		for _, k := range keys {
			if err := root.Insert(k, value); err != nil {
				b.Fatal(err)
			}
		}
		root.ComputeCommitment()
	}
}

func benchmarkCommitNLeaves(b *testing.B, n int) {
	type kv struct {
		k []byte
		v []byte
	}
	kvs := make([]kv, n)
	sortedKVs := make([]kv, n)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		val := make([]byte, 32)
		rand.Read(key)
		rand.Read(val)
		kvs[i] = kv{k: key, v: val}
		sortedKVs[i] = kv{k: key, v: val}
	}

	// InsertOrder assumes keys are sorted
	sortKVs := func(src []kv) {
		sort.Slice(src, func(i, j int) bool { return bytes.Compare(src[i].k, src[j].k) < 0 })
	}
	sortKVs(sortedKVs)

	b.Run("insert", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New(10, lg1)
			for _, el := range kvs {
				if err := root.Insert(el.k, el.v); err != nil {
					b.Error(err)
				}
			}
			root.ComputeCommitment()
		}
	})

	b.Run("insertOrdered", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New(10, lg1)
			for _, el := range sortedKVs {
				if err := root.InsertOrdered(el.k, el.v, nil); err != nil {
					b.Fatal(err)
				}
			}
			root.ComputeCommitment()
		}
	})
}

func BenchmarkModifyLeaves(b *testing.B) {
	rand.Seed(time.Now().UnixNano())

	n := 1000000
	toEdit := 10000
	val := []byte{0}
	keys := make([][]byte, n)
	root := New(10, lg1)
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, val)
	}
	root.ComputeCommitment()

	b.ResetTimer()
	b.ReportAllocs()

	val = make([]byte, 4)
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(val, uint32(i))
		for j := 0; j < toEdit; j++ {
			k := keys[rand.Intn(n)]
			if err := root.Insert(k, val); err != nil {
				b.Error(err)
			}
		}
		root.ComputeCommitment()
	}
}
