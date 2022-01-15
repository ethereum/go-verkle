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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	mRand "math/rand"
	"sort"
	"testing"
	"time"
)

// a 32 byte value, as expected in the tree structure
var testValue = []byte("0123456789abcdef0123456789abcdef")

var (
	zeroKeyTest, _   = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	oneKeyTest, _    = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	fourtyKeyTest, _ = hex.DecodeString("4000000000000000000000000000000000000000000000000000000000000000")
	ffx32KeyTest, _  = hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
)

func TestInsertIntoRoot(t *testing.T) {
	root := New()
	err := root.Insert(zeroKeyTest, testValue, nil)
	if err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.values[zeroKeyTest[31]], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.values[zeroKeyTest[31]])
	}
}

func TestInsertTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(ffx32KeyTest, testValue, nil)

	leaf0, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	leaff, ok := root.(*InternalNode).children[255].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[255])
	}

	if !bytes.Equal(leaf0.values[zeroKeyTest[31]], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf0.values[zeroKeyTest[31]])
	}

	if !bytes.Equal(leaff.values[255], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaff.values[ffx32KeyTest[31]])
	}
}

func TestInsertTwoLeavesLastLevel(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(oneKeyTest, testValue, nil)

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.values[1], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.values[1])
	}
	if !bytes.Equal(leaf.values[0], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.values[0])
	}

}

func TestGetTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(ffx32KeyTest, testValue, nil)

	val, err := root.Get(zeroKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("got a different value from the tree than expected %x != %x", val, testValue)
	}

	val, err = root.Get(oneKeyTest, nil)
	if err != nil {
		t.Fatalf("wrong error type, expected %v, got %v", nil, err)
	}
	if val != nil {
		t.Fatalf("Get returned value %x for a non-existing key", val)
	}

	if val != nil {
		t.Fatalf("got a different value from the tree than expected %x != nil", val)
	}
}

func TestComputeRootCommitmentOnlineThreeLeavesFlush(t *testing.T) {
	flushCh := make(chan VerkleNode)
	flush := func(node VerkleNode) {
		flushCh <- node
	}
	go func() {
		root := New()
		root.InsertOrdered(zeroKeyTest, testValue, flush)
		root.InsertOrdered(fourtyKeyTest, testValue, flush)
		root.InsertOrdered(ffx32KeyTest, testValue, flush)
		root.(*InternalNode).Flush(flush)
		close(flushCh)
	}()

	count := 0
	for n := range flushCh {
		_, isLeaf := n.(*LeafNode)
		_, isInternal := n.(*InternalNode)
		if !isLeaf && !isInternal {
			t.Fatal("invalid node type received, expected leaf")
		}
		count++
	}

	if count != 4 {
		t.Fatalf("incorrect number of flushed leaves 4 != %d", count)
	}
}

func TestOffset2key8BitsWide(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for i := byte(0); i < 32; i++ {
		childId := offset2key(key, i*8)
		if childId != i {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}
}

func TestInsertVsOrdered(t *testing.T) {
	n := 10000
	keys := randomKeys(n)
	sortedKeys := make([][]byte, n)
	copy(sortedKeys, keys)
	sort.Slice(sortedKeys, func(i, j int) bool { return bytes.Compare(sortedKeys[i], sortedKeys[j]) < 0 })

	root1 := New()
	for _, k := range keys {
		err := root1.Insert(k, fourtyKeyTest, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	root2 := New()
	for _, k := range sortedKeys {
		err := root2.InsertOrdered(k, fourtyKeyTest, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	h2 := root2.ComputeCommitment().Bytes()
	h1 := root1.ComputeCommitment().Bytes()

	if !bytes.Equal(h1[:], h2[:]) {
		t.Errorf("Insert and InsertOrdered produce different trees %x != %x", h1, h2)
	}
}

func TestFlush1kLeaves(t *testing.T) {
	n := 1000
	keys := randomKeysSorted(n)

	flushCh := make(chan VerkleNode)
	flush := func(node VerkleNode) {
		flushCh <- node
	}
	go func() {
		root := New()
		for _, k := range keys {
			root.InsertOrdered(k, fourtyKeyTest, flush)
		}
		root.(*InternalNode).Flush(flush)
		close(flushCh)
	}()

	count := 0
	leaves := 0
	for n := range flushCh {
		_, isLeaf := n.(*LeafNode)
		_, isInternal := n.(*InternalNode)
		if !isLeaf && !isInternal {
			t.Fatal("invalid node type received, expected leaf")
		}
		if isLeaf {
			leaves++
		}
		count++
	}

	if leaves != n {
		t.Fatalf("number of flushed leaves incorrect. Expected %d got %d\n", n, leaves)
	}
}

func TestCopy(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)
	tree.Insert(key3, fourtyKeyTest, nil)
	tree.ComputeCommitment()

	copied := tree.Copy()
	copied.(*InternalNode).clearCache()

	got1 := copied.ComputeCommitment().Bytes()
	got2 := tree.ComputeCommitment().Bytes()
	if !bytes.Equal(got1[:], got2[:]) {
		t.Fatalf("error copying commitments %x != %x", got1, got2)
	}
	tree.Insert(key2, oneKeyTest, nil)
	tree.ComputeCommitment()
	got2 = tree.ComputeCommitment().Bytes()
	if bytes.Equal(got1[:], got2[:]) {
		t1, _ := tree.Get(key2, nil)
		t2, _ := copied.Get(key2, nil)
		t.Fatalf("error tree and its copy should have a different commitment after the update: %x == %x %s %s", got1, got2, t1, t2)
	}
}

func TestCachedCommitment(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	key4, _ := hex.DecodeString("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)
	tree.Insert(key3, fourtyKeyTest, nil)
	tree.ComputeCommitment()

	if tree.(*InternalNode).commitment == nil {
		t.Error("root has not cached commitment")
	}

	tree.Insert(key4, fourtyKeyTest, nil)

	if tree.(*InternalNode).commitment != nil {
		t.Error("root has stale commitment")
	}
	if tree.(*InternalNode).children[4].(*InternalNode).commitment != nil {
		t.Error("internal node has stale commitment")
	}
	if tree.(*InternalNode).children[1].(*InternalNode).commitment == nil {
		t.Error("internal node has mistakenly cleared cached commitment")
	}
}

func TestClearCache(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)
	tree.Insert(key3, fourtyKeyTest, nil)
	tree.ComputeCommitment()

	root := tree.(*InternalNode)
	root.clearCache()

	if root.commitment != nil {
		t.Error("root cached commitment should have been cleared")
	}

	if root.children[1].(*InternalNode).commitment != nil {
		t.Error("internal child's cached commitment should have been cleared")
	}
}

func TestDelLeaf(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)
	hash := tree.ComputeCommitment()

	tree.Insert(key3, fourtyKeyTest, nil)
	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}

	postHash := tree.ComputeCommitment()
	if Equal(hash, postHash) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	res, err := tree.Get(key3, nil)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(res, zeroKeyTest) {
		t.Error("leaf hasnt been deleted")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)
	if err := tree.Delete(key3); err != errDeleteNonExistent {
		t.Error("should fail to delete non-existent key")
	}
}

func TestDeletePrune(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	key4, _ := hex.DecodeString("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)

	hash1 := tree.ComputeCommitment()
	tree.Insert(key3, fourtyKeyTest, nil)
	hash2 := tree.ComputeCommitment()
	tree.Insert(key4, fourtyKeyTest, nil)

	if err := tree.Delete(key4); err != nil {
		t.Error(err)
	}
	postHash := tree.ComputeCommitment()
	if Equal(hash2, postHash) {
		t.Error("deleting leaf #4 resulted in unexpected tree")
	}
	res, err := tree.Get(key4, nil)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(res, zeroKeyTest) {
		t.Error("leaf hasnt been deleted")
	}

	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}
	postHash = tree.ComputeCommitment()
	if Equal(hash1, postHash) {
		t.Error("deleting leaf #3 resulted in unexpected tree")
	}
	res, err = tree.Get(key3, nil)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(res, zeroKeyTest) {
		t.Error("leaf hasnt been deleted")
	}
}

func TestDeleteHash(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.InsertOrdered(key2, fourtyKeyTest, nil)
	tree.InsertOrdered(key3, fourtyKeyTest, nil)
	tree.ComputeCommitment()
	if err := tree.Delete(key2); err != errDeleteHash {
		t.Fatalf("did not report the correct error while deleting from a hash: %v", err)
	}
}

func TestDeleteUnequalPath(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key3, fourtyKeyTest, nil)
	tree.ComputeCommitment()

	if err := tree.Delete(key2); err != errDeleteNonExistent {
		t.Fatalf("didn't catch the deletion of non-existing key, err =%v", err)
	}
}

func TestConcurrentTrees(t *testing.T) {
	tree := New()
	err := tree.Insert(zeroKeyTest, fourtyKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := tree.ComputeCommitment()

	threads := 2
	ch := make(chan *Fr)
	builder := func() {
		tree := New()
		tree.Insert(zeroKeyTest, fourtyKeyTest, nil)
		ch <- tree.ComputeCommitment()
	}

	for i := 0; i < threads; i++ {
		go builder()
	}

	for i := 0; i < threads; i++ {
		root := <-ch
		if !Equal(root, expected) {
			t.Error("Incorrect root")
		}
	}
}

func BenchmarkCommitLeaves(b *testing.B) {
	benchmarkCommitNLeaves(b, 1000)
	benchmarkCommitNLeaves(b, 10000)
}

func BenchmarkCommitFullNode(b *testing.B) {
	nChildren := 256
	keys := make([][]byte, nChildren)
	for i := 0; i < nChildren; i++ {
		key := make([]byte, 32)
		key[0] = uint8(i)
		keys[i] = key
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		root := New()
		for _, k := range keys {
			if err := root.Insert(k, fourtyKeyTest, nil); err != nil {
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

	b.Run(fmt.Sprintf("insert/leaves/%d", n), func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New()
			for _, el := range kvs {
				if err := root.Insert(el.k, el.v, nil); err != nil {
					b.Error(err)
				}
			}
			root.ComputeCommitment()
		}
	})

	b.Run(fmt.Sprintf("insertOrdered/leaves/%d", n), func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New()
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
	mRand.Seed(time.Now().UnixNano())

	n := 200000
	toEdit := 10000
	val := []byte{0}
	keys := make([][]byte, n)
	root := New()
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, val, nil)
	}
	root.ComputeCommitment()

	b.ResetTimer()
	b.ReportAllocs()

	val = make([]byte, 4)
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(val, uint32(i))
		for j := 0; j < toEdit; j++ {
			k := keys[mRand.Intn(n)]
			if err := root.Insert(k, val, nil); err != nil {
				b.Error(err)
			}
		}
		root.ComputeCommitment()
	}
}

func randomKeys(n int) [][]byte {
	keys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
	}
	return keys
}

func randomKeysSorted(n int) [][]byte {
	keys := randomKeys(n)
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys
}

func TestNodeSerde(t *testing.T) {
	tree := New()
	tree.Insert(zeroKeyTest, testValue, nil)
	tree.Insert(fourtyKeyTest, testValue, nil)
	root := tree.(*InternalNode)

	// Serialize all the nodes
	leaf0 := (root.children[0]).(*LeafNode)
	ls0, err := leaf0.Serialize()
	if err != nil {
		t.Error(err)
	}

	leaf64 := (root.children[64]).(*LeafNode)
	ls64, err := leaf64.Serialize()
	if err != nil {
		t.Error(err)
	}

	rs, err := root.Serialize()
	if err != nil {
		t.Error(err)
	}

	// Now deserialize and re-construct tree
	res, err := ParseNode(ls0, 1)
	if err != nil {
		t.Error(err)
	}
	resLeaf0 := res.(*LeafNode)

	res, err = ParseNode(ls64, 1)
	if err != nil {
		t.Error(err)
	}
	resLeaf64 := res.(*LeafNode)

	res, err = ParseNode(rs, 0)
	if err != nil {
		t.Error(err)
	}
	resRoot := res.(*InternalNode)

	resRoot.children[0] = resLeaf0
	resRoot.children[64] = resLeaf64

	if !isInternalEqual(root, resRoot) {
		t.Errorf("parsed node not equal, %x != %x", root.hash, resRoot.hash)
	}
}

func isInternalEqual(a, b *InternalNode) bool {
	for i := 0; i < NodeWidth; i++ {
		c := a.children[i]
		switch c.(type) {
		case Empty:
			if _, ok := b.children[i].(Empty); !ok {
				return false
			}
		case *HashedNode:
			hn, ok := b.children[i].(*HashedNode)
			if !ok {
				return false
			}
			if !Equal(c.(*HashedNode).hash, hn.hash) {
				return false
			}
		case *LeafNode:
			ln, ok := b.children[i].(*LeafNode)
			if !ok {
				return false
			}
			if !isLeafEqual(c.(*LeafNode), ln) {
				return false
			}
		case *InternalNode:
			in, ok := b.children[i].(*InternalNode)
			if !ok {
				return false
			}
			if !isInternalEqual(c.(*InternalNode), in) {
				return false
			}
		}
	}

	return true
}

func isLeafEqual(a, b *LeafNode) bool {
	if !bytes.Equal(a.stem, b.stem) {
		return false
	}

	for i, v := range a.values {
		if !bytes.Equal(v, b.values[i]) {
			return false
		}
	}

	return true
}

func TestGetResolveFromHash(t *testing.T) {
	var count uint
	var dummyError = errors.New("dummy")
	var serialized []byte
	getter := func([]byte) ([]byte, error) {
		count++

		return serialized, nil
	}
	failingGetter := func([]byte) ([]byte, error) {
		return nil, dummyError
	}
	flush := func(n VerkleNode) {
		s, err := n.Serialize()
		if err != nil {
			panic(err)
		}
		serialized = append(serialized, s...)
	}
	root := New()
	root.InsertOrdered(zeroKeyTest, zeroKeyTest, flush)
	root.InsertOrdered(fourtyKeyTest, zeroKeyTest, flush)
	err := root.InsertOrdered(oneKeyTest, zeroKeyTest, flush)
	if err != errInsertIntoHash {
		t.Fatal(err)
	}

	data, err := root.Get(zeroKeyTest, nil)
	if err != errReadFromInvalid || len(data) != 0 {
		t.Fatal(err)
	}

	data, err = root.Get(zeroKeyTest, failingGetter)
	if err != dummyError || len(data) != 0 {
		t.Fatal(err)
	}

	data, err = root.Get(zeroKeyTest, getter)
	if err != nil {
		t.Fatalf("error resolving hash: %v", err)
	}
	if count != 1 {
		t.Fatalf("error getting the correct number of nodes: 1 != %d", count)
	}
	if !bytes.Equal(data, zeroKeyTest) {
		t.Fatalf("invalid result: %x != %x", zeroKeyTest, len(data))
	}
}

func TestGetKey(t *testing.T) {
	root := &LeafNode{stem: fourtyKeyTest}
	for i := 0; i < NodeWidth; i++ {
		k := root.Key(i)
		if !bytes.Equal(k[:31], fourtyKeyTest[:31]) {
			t.Fatal("invalid stem")
		}
		if int(k[31]) != i {
			t.Fatal("invalid selector")
		}
	}
}

func TestInsertIntoHashedNode(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.InsertOrdered(fourtyKeyTest, zeroKeyTest, nil)

	if err := root.Insert(zeroKeyTest, zeroKeyTest, nil); err != errInsertIntoHash {
		t.Fatalf("incorrect error type: %v", err)
	}

	resolver := func(h []byte) ([]byte, error) {
		node := &LeafNode{stem: zeroKeyTest, values: make([][]byte, NodeWidth)}
		node.values[0] = zeroKeyTest

		return node.Serialize()
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, resolver); err != nil {
		t.Fatalf("error in node resolution: %v", err)
	}

	// Check that the proper error is raised if the RLP data is invalid and the
	// node can not be parsed.
	invalidRLPResolver := func(h []byte) ([]byte, error) {
		node := &LeafNode{stem: zeroKeyTest, values: make([][]byte, NodeWidth)}
		node.values[0] = zeroKeyTest

		rlp, _ := node.Serialize()
		return rlp[:len(rlp)-10], nil
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, invalidRLPResolver); !errors.Is(err, serializedPayloadTooShort) {
		t.Fatalf("error detecting a decoding error after resolution: %v", err)
	}

	var randomResolverError = errors.New("'clef' was mispronounced")
	// Check that the proper error is raised if the resolver returns an error
	erroringResolver := func(h []byte) ([]byte, error) {
		return nil, randomResolverError
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, erroringResolver); !errors.Is(err, randomResolverError) {
		t.Fatalf("error detecting a resolution error: %v", err)
	}
}

func TestToDot(*testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.InsertOrdered(fourtyKeyTest, zeroKeyTest, nil)
	fourtytwoKeyTest, _ := hex.DecodeString("4020000000000000000000000000000000000000000000000000000000000000")
	root.Insert(fourtytwoKeyTest, zeroKeyTest, nil)

	fmt.Println(root.toDot("", ""))
}

func TestEmptyCommitment(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.ComputeCommitment()
	pe := root.GetCommitmentsAlongPath(ffx32KeyTest)
	if len(pe.Cis) != 1 || len(pe.Zis) != 1 || len(pe.Yis) != 1 || len(pe.Fis) != 1 {
		t.Fatalf("invalid parameter list length")
	}

	if !pe.Cis[0].Equal(root.(*InternalNode).commitment) {
		t.Fatalf("invalid commitment %x %x", pe.Cis[0], root.(*InternalNode).commitment)
	}

	zero := new(Fr)
	if !pe.Yis[0].Equal(zero) {
		t.Fatalf("invalid yi %v %v", zero, pe.Yis[0])
	}
}

func TestLeafToCommsMoreThan32(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("didn't catch length error")
		}
	}()
	var value [33]byte
	leafToComms([]Fr{}, value[:])
}

func TestLeafToCommsLessThan32(*testing.T) {
	var (
		value [16]byte
		p     [2]Fr
	)
	leafToComms(p[:], value[:])
}

func TestLeafToCommsLessThan16(*testing.T) {
	var (
		value [4]byte
		p     [2]Fr
	)
	leafToComms(p[:], value[:])
}
