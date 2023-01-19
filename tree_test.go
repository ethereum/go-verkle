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
	"os"
	"sort"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	_ = GetConfig()
	os.Exit(m.Run())
}

// a 32 byte value, as expected in the tree structure
var testValue = []byte("0123456789abcdef0123456789abcdef")

var (
	zeroKeyTest, _   = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	oneKeyTest, _    = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	splitKeyTest, _  = hex.DecodeString("0000000000720000000000000000000000000000000000000000000000000000")
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
		childId := offset2key(key, i)
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

	h2 := root2.Commit().Bytes()
	h1 := root1.Commit().Bytes()

	if !bytes.Equal(h1[:], h2[:]) {
		t.Errorf("Insert and InsertOrdered produce different trees %x != %x %s %s", h1, h2, ToDot(root1), ToDot(root2))
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
	tree.Commit()

	copied := tree.Copy()

	tree.Insert(key3, fourtyKeyTest, nil)

	if Equal(tree.Commit(), copied.Commit()) {
		t.Fatal("inserting the copy into the original tree updated the copy's commitment")
	}

	copied.Insert(key3, fourtyKeyTest, nil)

	if !Equal(tree.Commitment(), copied.Commit()) {
		t.Fatalf("differing final commitments %x != %x", tree.Commitment().Bytes(), copied.Commitment().Bytes())
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
	oldRoot := tree.Commit().Bytes()
	oldInternal := tree.(*InternalNode).children[4].(*LeafNode).commitment.Bytes()

	if tree.(*InternalNode).commitment == nil {
		t.Error("root has not cached commitment")
	}

	tree.Insert(key4, fourtyKeyTest, nil)
	tree.Commit()

	if tree.(*InternalNode).Commitment().Bytes() == oldRoot {
		t.Error("root has stale commitment")
	}
	if tree.(*InternalNode).children[4].(*InternalNode).commitment.Bytes() == oldInternal {
		t.Error("internal node has stale commitment")
	}
	if tree.(*InternalNode).children[1].(*InternalNode).commitment == nil {
		t.Error("internal node has mistakenly cleared cached commitment")
	}
}

func TestDelLeaf(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, fourtyKeyTest, nil)
	tree.Insert(key2, fourtyKeyTest, nil)
	var init Point
	CopyPoint(&init, tree.Commit())

	tree.Insert(key3, fourtyKeyTest, nil)
	if err := tree.Delete(key3, nil); err != nil {
		t.Error(err)
	}

	// the pre and post deletion hashes should be different,
	// as deleting a value means replacing it with a 0 in verkle
	// trees.
	postHash := tree.Commit()
	if Equal(&init, postHash) {
		t.Errorf("deleting leaf resulted in unexpected tree %x %x", init.Bytes(), postHash.Bytes())
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
	if err := tree.Delete(key3, nil); err != errDeleteNonExistent {
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

	var hash1, hash2 Point
	CopyPoint(&hash1, tree.Commit())
	tree.Insert(key3, fourtyKeyTest, nil)
	CopyPoint(&hash2, tree.Commit())
	tree.Insert(key4, fourtyKeyTest, nil)
	tree.Commit()

	if err := tree.Delete(key4, nil); err != nil {
		t.Error(err)
	}
	postHash := tree.Commit()
	if Equal(&hash2, postHash) {
		t.Error("deleting leaf #4 resulted in unexpected tree")
	}
	res, err := tree.Get(key4, nil)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(res, zeroKeyTest) {
		t.Error("leaf hasnt been deleted")
	}

	if err := tree.Delete(key3, nil); err != nil {
		t.Error(err)
	}
	postHash = tree.Commit()
	if Equal(&hash1, postHash) {
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
	tree.Commit()
	if err := tree.Delete(key2, nil); err != errDeleteHash {
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
	tree.Commit()

	if err := tree.Delete(key2, nil); err != errDeleteNonExistent {
		t.Fatalf("didn't catch the deletion of non-existing key, err =%v", err)
	}
}

func TestDeleteResolve(t *testing.T) {
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	var savedNodes []VerkleNode
	saveNode := func(node VerkleNode) {
		savedNodes = append(savedNodes, node)
	}
	tree.InsertOrdered(key1, fourtyKeyTest, saveNode)
	tree.InsertOrdered(key2, fourtyKeyTest, saveNode)
	tree.InsertOrdered(key3, fourtyKeyTest, saveNode)
	tree.Commit()

	var called bool
	err := tree.Delete(key2, func(comm []byte) ([]byte, error) {
		called = true
		for _, node := range savedNodes {
			c := node.Commit().Bytes()
			if bytes.Equal(comm, c[:]) {
				return node.Serialize()
			}
		}
		t.Fatal("could not find node")
		return nil, fmt.Errorf("node not found")
	})
	if !called {
		t.Fatal("should have called the resolve function")
	}
	if err != nil {
		t.Fatalf("error deleting key: %v", err)
	}
}

func TestConcurrentTrees(t *testing.T) {
	tree := New()
	err := tree.Insert(zeroKeyTest, fourtyKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := tree.Commit()

	threads := 2
	ch := make(chan *Point)
	builder := func() {
		tree := New()
		tree.Insert(zeroKeyTest, fourtyKeyTest, nil)
		ch <- tree.Commit()
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
		root.Commit()
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
		rand.Read(key) // skipcq: GSC-G404
		rand.Read(val) // skipcq: GSC-G404
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
			root.Commit()
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
			root.Commit()
		}
	})
}

func BenchmarkModifyLeaves(b *testing.B) {
	mRand.Seed(time.Now().UnixNano()) // skipcq: GO-S1033

	n := 200000
	toEdit := 10000
	val := []byte{0}
	keys := make([][]byte, n)
	root := New()
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key) // skipcq: GSC-G404
		keys[i] = key
		root.Insert(key, val, nil)
	}
	root.Commit()

	b.ResetTimer()
	b.ReportAllocs()

	val = make([]byte, 4)
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(val, uint32(i))
		for j := 0; j < toEdit; j++ {
			// skipcq: GSC-G404
			k := keys[mRand.Intn(n)]
			if err := root.Insert(k, val, nil); err != nil {
				b.Error(err)
			}
		}
		root.Commit()
	}
}

func randomKeys(n int) [][]byte {
	keys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key) // skipcq: GSC-G404
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
	origComm := tree.Commit().Bytes()
	root := tree.(*InternalNode)

	// Serialize all the nodes
	leaf0 := (root.children[0]).(*LeafNode)
	ls0, err := leaf0.Serialize()
	if err != nil {
		t.Error(err)
	}
	l0c := leaf0.commitment.Bytes()

	leaf64 := (root.children[64]).(*LeafNode)
	ls64, err := leaf64.Serialize()
	if err != nil {
		t.Error(err)
	}
	l64c := leaf64.commitment.Bytes()

	rs, err := root.Serialize()
	if err != nil {
		t.Error(err)
	}
	rc := root.commitment.Bytes()

	// Now deserialize and re-construct tree
	res, err := ParseNode(ls0, 1, l0c[:])
	if err != nil {
		t.Error(err)
	}
	resLeaf0 := res.(*LeafNode)

	res, err = ParseNode(ls64, 1, l64c[:])
	if err != nil {
		t.Error(err)
	}
	resLeaf64 := res.(*LeafNode)

	res, err = ParseNode(rs, 0, rc[:])
	if err != nil {
		t.Error(err)
	}
	resRoot := res.(*InternalNode)

	resRoot.children[0] = resLeaf0
	resRoot.children[64] = resLeaf64

	if !isInternalEqual(root, resRoot) {
		t.Errorf("parsed node not equal, %x != %x", root.commitment.Bytes(), resRoot.commitment.Bytes())
	}

	if resRoot.Commitment().Bytes() != origComm {
		t.Fatal("invalid deserialized commitment")
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
			if !Equal(c.(*HashedNode).Commitment(), hn.Commitment()) {
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
	dummyError := errors.New("dummy")
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
		values := make([][]byte, NodeWidth)
		values[0] = zeroKeyTest
		node := NewLeafNode(zeroKeyTest[:31], values)

		return node.Serialize()
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, resolver); err != nil {
		t.Fatalf("error in node resolution: %v", err)
	}

	// Check that the proper error is raised if the RLP data is invalid and the
	// node can not be parsed.
	invalidRLPResolver := func(h []byte) ([]byte, error) {
		values := make([][]byte, NodeWidth)
		values[0] = zeroKeyTest
		node := NewLeafNode(zeroKeyTest[:31], values)

		rlp, _ := node.Serialize()
		return rlp[:len(rlp)-10], nil
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, invalidRLPResolver); !errors.Is(err, serializedPayloadTooShort) {
		t.Fatalf("error detecting a decoding error after resolution: %v", err)
	}

	randomResolverError := errors.New("'clef' was mispronounced")
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

	fmt.Println(ToDot(root))
}

func TestEmptyCommitment(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Commit()
	pe, _, _ := root.GetProofItems(keylist{ffx32KeyTest})
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

func TestGetProofItemsNoPoaIfStemPresent(t *testing.T) {
	root := New()
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)
	root.Commit()

	// insert two keys that differ from the inserted stem
	// by one byte.
	key1, _ := hex.DecodeString("ffff00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	key2, _ := hex.DecodeString("ffffff00ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	_, esses, poas := root.GetProofItems(keylist{key1, key2, ffx32KeyTest})
	if len(poas) != 0 {
		t.Fatalf("returned %d poas instead of 0", len(poas))
	}
	if len(esses) != 1 {
		t.Fatalf("returned %d extension statuses instead of the expected 1", len(esses))
	}
}

var (
	testAccountKeys = [][]byte{
		{245, 110, 100, 66, 36, 244, 87, 100, 144, 207, 224, 222, 20, 36, 164, 83, 34, 18, 82, 155, 254, 55, 71, 19, 216, 78, 125, 126, 142, 146, 114, 0},
		{245, 110, 100, 66, 36, 244, 87, 100, 144, 207, 224, 222, 20, 36, 164, 83, 34, 18, 82, 155, 254, 55, 71, 19, 216, 78, 125, 126, 142, 146, 114, 1},
		{245, 110, 100, 66, 36, 244, 87, 100, 144, 207, 224, 222, 20, 36, 164, 83, 34, 18, 82, 155, 254, 55, 71, 19, 216, 78, 125, 126, 142, 146, 114, 2},
		{245, 110, 100, 66, 36, 244, 87, 100, 144, 207, 224, 222, 20, 36, 164, 83, 34, 18, 82, 155, 254, 55, 71, 19, 216, 78, 125, 126, 142, 146, 114, 3},
		{245, 110, 100, 66, 36, 244, 87, 100, 144, 207, 224, 222, 20, 36, 164, 83, 34, 18, 82, 155, 254, 55, 71, 19, 216, 78, 125, 126, 142, 146, 114, 4},
	}

	testAccountValues = [][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 100, 167, 179, 182, 224, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	testAccountRootCommRust, _ = hex.DecodeString("10ed89d89047bb168baa4e69b8607e260049e928ddbcb2fdd23ea0f4182b1f8a")
)

func TestWithRustCompatibility(t *testing.T) {
	root := New()
	for i, key := range testAccountKeys {
		err := root.Insert(key, testAccountValues[i], nil)
		if err != nil {
			t.Fatalf("error inserting: %v", err)
		}
	}

	commBytes := root.Commit().Bytes()
	if !bytes.Equal(commBytes[:], testAccountRootCommRust) {
		t.Fatalf("rust and golang impl are not compatible rust=%x, go=%x", testAccountRootCommRust, commBytes)
	}
}

func TestInsertStem(t *testing.T) {
	root1 := New()
	root2 := New()

	values := make([][]byte, 256)
	values[5] = zeroKeyTest
	values[192] = fourtyKeyTest

	root1.(*InternalNode).InsertStem(fourtyKeyTest[:31], values, nil)
	r1c := root1.Commit()

	var key5, key192 [32]byte
	copy(key5[:], fourtyKeyTest[:31])
	copy(key192[:], fourtyKeyTest[:31])
	key5[31] = 5
	key192[31] = 192
	root2.Insert(key5[:], zeroKeyTest, nil)
	root2.Insert(key192[:], fourtyKeyTest, nil)
	r2c := root2.Commit()

	if !Equal(r1c, r2c) {
		t.Fatalf("differing commitments %x != %x %s %s", r1c.Bytes(), r2c.Bytes(), ToDot(root1), ToDot(root2))
	}
}

func TestInsertResolveSplitLeaf(t *testing.T) {
	var leaf *LeafNode

	// Insert a unique leaf and flush it
	root := New()
	root.Insert(zeroKeyTest, ffx32KeyTest, nil)
	root.(*InternalNode).Flush(func(node VerkleNode) {
		l, ok := node.(*LeafNode)
		if !ok {
			return
		}

		if leaf != nil {
			t.Fatal("there should only be one leaf")
		}
		leaf = l
	})

	// check that the leafnode is now a hashed node
	if _, ok := root.(*InternalNode).children[0].(*HashedNode); !ok {
		t.Fatal("flush didn't produce a hashed node")
	}

	// Now insert another leaf, with a resolver function
	key, _ := hex.DecodeString("0000100000000000000000000000000000000000000000000000000000000000")
	if err := root.Insert(key, ffx32KeyTest, func(comm []byte) ([]byte, error) {
		leafcomm := leaf.Commitment().Bytes()
		if bytes.Equal(comm, leafcomm[:]) {
			ls, err := leaf.Serialize()
			if err != nil {
				return nil, err
			}
			return ls, nil
		}

		return nil, fmt.Errorf("asked for %x, expected %x", comm, leafcomm)
	}); err != nil {
		t.Fatal(err)
	}

	if _, ok := root.(*InternalNode).children[0].(*InternalNode); !ok {
		t.Fatal("resolution didn't produce and intermediate, intermediate node")
	}
	l, ok := root.(*InternalNode).children[0].(*InternalNode).children[0].(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatal("resolve with resolver didn't produce a leaf node where expected")
	}
	if !bytes.Equal(l.stem, zeroKeyTest[:31]) && !bytes.Equal(l.values[0], ffx32KeyTest) {
		t.Fatal("didn't find the resolved leaf where expected")
	}
}

func TestInsertStemOrdered(t *testing.T) {
	root1 := New()
	root2 := New()

	values1 := make([][]byte, 256)
	values1[5] = zeroKeyTest
	values1[192] = fourtyKeyTest
	values2 := make([][]byte, 256)
	values2[0] = ffx32KeyTest
	values3 := make([][]byte, 256)
	values3[64] = zeroKeyTest

	flushCount := 0
	flush := func(VerkleNode) {
		flushCount++
	}

	var keysplit [32]byte // a key to check stem splitting in insert
	copy(keysplit[:], fourtyKeyTest)
	keysplit[24] = 72
	root1.(*InternalNode).Insert(zeroKeyTest, ffx32KeyTest, nil)
	root1.(*InternalNode).InsertStemOrdered(fourtyKeyTest[:31], values1, flush)
	root1.(*InternalNode).InsertStemOrdered(keysplit[:31], values2, flush)
	root1.(*InternalNode).InsertStemOrdered(ffx32KeyTest[:31], values3, flush)
	r1c := root1.Commit()

	// 26 for fourtyKeyTest + 2 children, 1 for zeroKeyTest,
	if flushCount != 27 {
		t.Fatalf("incorrect number of flushes %d != 27", flushCount)
	}

	var key5, key32, key64, key192 [32]byte
	copy(key5[:], fourtyKeyTest[:31])
	copy(key192[:], fourtyKeyTest[:31])
	copy(key64[:], ffx32KeyTest[:31])
	key5[31] = 5
	key192[31] = 192
	key64[31] = 64
	key32[31] = 32
	root2.Insert(zeroKeyTest, ffx32KeyTest, nil)
	root2.Insert(key5[:], zeroKeyTest, nil)
	root2.Insert(key192[:], fourtyKeyTest, nil)
	root2.Insert(key192[:], fourtyKeyTest, nil)
	root2.Insert(key64[:], zeroKeyTest, nil)
	root2.Insert(keysplit[:], ffx32KeyTest, nil)
	r2c := root2.Commit()

	if !Equal(r1c, r2c) {
		t.Fatalf("differing commitments %x != %x", r1c.Bytes(), r2c.Bytes())
	}

	// Check that a previous key was flushed and hashed, and that one can no
	// longer insert in it.
	err := root1.(*InternalNode).InsertStemOrdered(fourtyKeyTest[:31], values1, nil)
	if err != errInsertIntoHash {
		t.Fatalf("received wrong error %v != %v", err, errInsertIntoHash)
	}
}

func TestRustBanderwagonBlock48(t *testing.T) {
	keyStrings := []string{
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352600",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352601",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352602",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352603",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352604",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352640",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352680",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352681",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352682",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352683",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352684",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352685",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352686",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352687",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352688",
		"744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe1593352689",
		"9661ae0db10ecdb9bea3ef0c5fb46bb233cb6ed7404b77e7b0732512ecc60100",
		"9661ae0db10ecdb9bea3ef0c5fb46bb233cb6ed7404b77e7b0732512ecc60101",
		"9661ae0db10ecdb9bea3ef0c5fb46bb233cb6ed7404b77e7b0732512ecc60102",
		"9661ae0db10ecdb9bea3ef0c5fb46bb233cb6ed7404b77e7b0732512ecc60103",
		"9661ae0db10ecdb9bea3ef0c5fb46bb233cb6ed7404b77e7b0732512ecc60104",
	}

	var keys [][]byte
	for _, s := range keyStrings {
		k, _ := hex.DecodeString(s)
		keys = append(keys, k)
	}
	tree := New()

	valStrings := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"f8811a5ee0d54eca4880eaee7b102eae4b3963ff343f50a024c0fd3d367cb8cc",
		"5001000000000000000000000000000000000000000000000000000000000000",
		"",
		"00608060405234801561001057600080fd5b50600436106100365760003560e0",
		"001c80632e64cec11461003b5780636057361d14610059575b600080fd5b6100",
		"0143610075565b60405161005091906100d9565b60405180910390f35b610073",
		"00600480360381019061006e919061009d565b61007e565b005b600080549050",
		"0090565b8060008190555050565b60008135905061009781610103565b929150",
		"0050565b6000602082840312156100b3576100b26100fe565b5b60006100c184",
		"00828501610088565b91505092915050565b6100d3816100f4565b8252505056",
		"005b60006020820190506100ee60008301846100ca565b92915050565b600081",
		"009050919050565b600080fd5b61010c816100f4565b811461011757600080fd",
		"005b5056fea2646970667358221220404e37f487a89a932dca5e77faaf6ca2de",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"507a878a1965b9e2ce3f00000000000000000000000000000000000000000000",
		"0200000000000000000000000000000000000000000000000000000000000000",
		"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"0000000000000000000000000000000000000000000000000000000000000000",
	}
	var (
		vals        [][]byte
		initialVals = map[string][]byte{}
	)

	for i, s := range valStrings {
		if s == "" {
			vals = append(vals, nil)
			continue
		}

		v, _ := hex.DecodeString(s)
		vals = append(vals, v)
		tree.Insert(keys[i], v, nil)

		initialVals[string(keys[i])] = v
	}

	// Insert the code chunk that isn't part of the proof
	missingKey, _ := hex.DecodeString("744f493648c83c5ede1726a0cfbe36d3830fd5b64a820b79ca77fe159335268a")
	missingVal, _ := hex.DecodeString("133b991f93d230604b1b8daaef64766264736f6c634300080700330000000000")
	tree.Insert(missingKey, missingVal, nil)

	r := tree.Commit()

	proof, cis, zis, yis, _ := MakeVerkleMultiProof(tree, keys, initialVals)
	serialized, _, err := SerializeProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("serialized proof=%x", serialized)

	cfg := GetConfig()
	if !VerifyVerkleProof(proof, cis, zis, yis, cfg) {
		t.Fatal("proof didn't verify")
	}

	var kvp []KeyValuePair
	for i := range keys {
		kvp = append(kvp, KeyValuePair{Key: keys[i], Value: vals[i]})
	}
	dproof, err := DeserializeProof(serialized, kvp)
	if err != nil {
		t.Fatal(err)
	}

	droot, err := TreeFromProof(dproof, r)
	if err != nil {
		t.Fatal(err)
	}
	pe, _, _ := droot.GetProofItems(keys)

	if !VerifyVerkleProof(dproof, pe.Cis, pe.Zis, pe.Yis, cfg) {
		t.Fatal("deserialized proof didn't verify")
	}
}
