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
	"math/big"
	mRand "math/rand"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/protolambda/go-kzg/bls"
)

var testValue = []byte("hello")

var (
	zeroKeyTest, _   = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	oneKeyTest, _    = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	fourtyKeyTest, _ = hex.DecodeString("4000000000000000000000000000000000000000000000000000000000000000")
	ffx32KeyTest, _  = hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
)

func hexToHash(str string) [32]byte {
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	var ret [32]byte
	copy(ret[:], b)
	return ret
}

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

func TestComputeRootCommitmentThreeLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(fourtyKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	expected, _ := hex.DecodeString("26664ee4292cccea11c029f1c833e6a2115490bf586a8189d7f6ef8e5a825204")

	got := bls.FrTo32(root.ComputeCommitment())

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
	got := bls.FrTo32(root.ComputeCommitment())

	expected, _ := hex.DecodeString("26664ee4292cccea11c029f1c833e6a2115490bf586a8189d7f6ef8e5a825204")

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentThreeLeavesDeep(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)
	root.Insert(ffx32KeyTest, zeroKeyTest, nil)

	expected, _ := hex.DecodeString("e7f96777a5425495f93dfb43960d39be2d5e97a86de2dd1bf2566032a478345f")

	got := bls.FrTo32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
func TestComputeRootCommitmentOneLeaf(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)

	expected, _ := hex.DecodeString("c65416142a960718ce12cc5ac11bb75b71dda1547bb3585a48e691286ba01200")

	got := bls.FrTo32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment hash %x != %x", got, expected)
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

func TestComputeRootCommitmentTwoLeavesLastLevel(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(oneKeyTest, testValue, nil)

	expected, _ := hex.DecodeString("31a811b612e6946bcfbc54e6ee053f2f1797857eea8fd35eb07a6445b8127d53")

	got := bls.FrTo32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

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

func TestOffset2key8BitsWide(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for i := 0; i < 32; i++ {
		childId := offset2key(key, i*8)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}
}

func TestComputeRootCommitmentTwoLeaves256(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue, nil)
	root.Insert(ffx32KeyTest, testValue, nil)
	expected, _ := hex.DecodeString("f58c3e4b1bcbe877759674f63cf0c4a0c9487bf89bbbea94ea87ce6ac2ad9b71")

	got := bls.FrTo32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestInsertVsOrdered(t *testing.T) {
	n := 10000
	value := []byte("value")
	keys := randomKeys(n)
	sortedKeys := make([][]byte, n)
	copy(sortedKeys, keys)
	sort.Slice(sortedKeys, func(i, j int) bool { return bytes.Compare(sortedKeys[i], sortedKeys[j]) < 0 })

	root1 := New()
	for _, k := range keys {
		err := root1.Insert(k, value, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	root2 := New()
	for _, k := range sortedKeys {
		err := root2.InsertOrdered(k, value, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	h2 := bls.FrTo32(root2.ComputeCommitment())
	h1 := bls.FrTo32(root1.ComputeCommitment())

	if !bytes.Equal(h1[:], h2[:]) {
		t.Errorf("Insert and InsertOrdered produce different trees %x != %x", h1, h2)
	}
}

func TestFlush1kLeaves(t *testing.T) {
	n := 1000
	keys := randomKeysSorted(n)
	value := []byte("value")

	flushCh := make(chan VerkleNode)
	flush := func(node VerkleNode) {
		flushCh <- node
	}
	go func() {
		root := New()
		for _, k := range keys {
			root.InsertOrdered(k, value, flush)
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
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)
	tree.Insert(key3, value, nil)
	tree.ComputeCommitment()

	copied := tree.Copy()
	copied.(*InternalNode).clearCache()

	got1 := bls.FrTo32(copied.ComputeCommitment())
	got2 := bls.FrTo32(tree.ComputeCommitment())
	if !bytes.Equal(got1[:], got2[:]) {
		t.Fatalf("error copying commitments %x != %x", got1, got2)
	}
	tree.Insert(key2, []byte("changed"), nil)
	tree.ComputeCommitment()
	got2 = bls.FrTo32(tree.ComputeCommitment())
	if bytes.Equal(got1[:], got2[:]) {
		t1, _ := tree.Get(key2, nil)
		t2, _ := copied.Get(key2, nil)
		t.Fatalf("error tree and its copy should have a different commitment after the update: %x == %x %s %s", got1, got2, t1, t2)
	}
}

func TestCachedCommitment(t *testing.T) {
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	key4, _ := hex.DecodeString("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)
	tree.Insert(key3, value, nil)
	tree.ComputeCommitment()

	if tree.(*InternalNode).commitment == nil {
		t.Error("root has not cached commitment")
	}

	tree.Insert(key4, value, nil)

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
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)
	tree.Insert(key3, value, nil)
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
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)
	hash := tree.ComputeCommitment()

	tree.Insert(key3, value, nil)
	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}

	postHash := tree.ComputeCommitment()
	if !bls.EqualFr(hash, postHash) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	res, err := tree.Get(key3, nil)
	if err != nil {
		t.Error(err)
	}
	if res != nil {
		t.Error("leaf hasnt been deleted")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)
	if err := tree.Delete(key3); err != errDeleteNonExistent {
		t.Error("should fail to delete non-existent key")
	}
}

func TestDeletePrune(t *testing.T) {
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	key4, _ := hex.DecodeString("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)

	hash1 := tree.ComputeCommitment()
	tree.Insert(key3, value, nil)
	hash2 := tree.ComputeCommitment()
	tree.Insert(key4, value, nil)

	if err := tree.Delete(key4); err != nil {
		t.Error(err)
	}
	postHash := tree.ComputeCommitment()
	if !bls.EqualFr(hash2, postHash) {
		t.Error("deleting leaf #4 resulted in unexpected tree")
	}

	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}
	postHash = tree.ComputeCommitment()
	if !bls.EqualFr(hash1, postHash) {
		t.Error("deleting leaf #3 resulted in unexpected tree")
	}
}

func TestDeletePruneMultipleLevels(t *testing.T) {
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	key4, _ := hex.DecodeString("0405010000000000000000000000000000000000000000000000000000000000")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)

	hash1 := tree.ComputeCommitment()
	tree.Insert(key3, value, nil)
	hash2 := tree.ComputeCommitment()
	tree.Insert(key4, value, nil)

	if err := tree.Delete(key4); err != nil {
		t.Error(err)
	}
	postHash := tree.ComputeCommitment()
	if !bls.EqualFr(hash2, postHash) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	tempNode := tree.(*InternalNode).children[4]
	if _, ok := tempNode.(*LeafNode); !ok {
		t.Fatal("did not collapse extension for 450")
	}

	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}
	postHash = tree.ComputeCommitment()
	if !bls.EqualFr(hash1, postHash) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	if _, ok := tree.(*InternalNode).children[4].(Empty); !ok {
		t.Fatal("did not delete the right node")
	}
}

func TestDeletePruneExtensions(t *testing.T) {
	value := []byte("value")
	key1, _ := hex.DecodeString("0105000000000000000000000000000000000000000000000000000000000000")
	key2, _ := hex.DecodeString("0107000000000000000000000000000000000000000000000000000000000000")
	key3, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000000")
	key4, _ := hex.DecodeString("0405000000000000000000000000000000000000000000000000000000000001")
	tree := New()
	tree.Insert(key1, value, nil)
	tree.Insert(key2, value, nil)

	hash1 := tree.ComputeCommitment()
	tree.Insert(key3, value, nil)
	hash2 := tree.ComputeCommitment()
	tree.Insert(key4, value, nil)

	node4 := tree.(*InternalNode).children[4]
	leaf, ok := node4.(*LeafNode)
	if !ok {
		t.Fatal("could not find expected leaf node")
	}

	if leaf.values[0] == nil || leaf.values[1] == nil {
		t.Fatal("value isn't present where expected")
	}
	for i := 2; i < 256; i++ {
		if leaf.values[i] != nil {
			t.Fatalf("unexpected value at %d", i)
		}
	}

	if err := tree.Delete(key4); err != nil {
		t.Error(err)
	}
	postHash := tree.ComputeCommitment()
	if !bls.EqualFr(hash2, postHash) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	if leaf.values[0] == nil {
		t.Fatal("value isn't present where expected")
	}
	for i := 1; i < 256; i++ {
		if leaf.values[i] != nil {
			t.Fatalf("unexpected value at %d", i)
		}
	}

	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}
	postHash = tree.ComputeCommitment()
	if !bls.EqualFr(hash1, postHash) {
		t.Error("deleting leaf resulted in unexpected tree")
	}
}

var (
	emptyCodeHash, _ = hex.DecodeString("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	emptyRootHash    = hexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     [32]byte // merkle root of the storage trie
	CodeHash []byte
}

func TestDevnet0PostMortem(t *testing.T) {
	t.Skip()
	addr1, _ := hex.DecodeString("3e47cd08ea12b4dfcf5210e3ef3827471994d49b")
	addr2, _ := hex.DecodeString("617661d148a52bef51a268c728b3a21b58f94306")
	balance1, _ := big.NewInt(0).SetString("100000000000000000000", 10)
	balance2, _ := big.NewInt(0).SetString("1000003506000000000000000000", 10)
	account1 := Account{
		Nonce:    0,
		Balance:  balance1,
		Root:     emptyRootHash,
		CodeHash: emptyCodeHash,
	}
	account2 := Account{
		Nonce:    1,
		Balance:  balance2,
		Root:     emptyRootHash,
		CodeHash: emptyCodeHash,
	}

	var buf1, buf2 bytes.Buffer
	tree := New()
	rlp.Encode(&buf1, &account1)

	tree.Insert(addr1, buf1.Bytes(), nil)
	rlp.Encode(&buf2, &account2)
	tree.Insert(addr2, buf2.Bytes(), nil)

	tree.ComputeCommitment()

	block1803Hash := bls.FrTo32(tree.ComputeCommitment())
	expected, _ := hex.DecodeString("74eb37a063c4c8806716d59816487c32315861d32f5f7697a9aaef5cfe964b9c")
	if !bytes.Equal(block1803Hash[:], expected) {
		t.Fatalf("error, got %x != 74eb37a063c4c8806716d59816487c32315861d32f5f7697a9aaef5cfe964b9c", block1803Hash)
	}

	buf1.Reset()
	account1.Balance.SetString("199000000000000000000", 10)
	rlp.Encode(&buf1, &account1)
	tree.Insert(addr1, buf1.Bytes(), nil)
	buf2.Reset()
	account2.Nonce = 4
	account2.Balance.SetString("1000003587000000000000000000", 10)
	rlp.Encode(&buf2, &account2)
	tree.Insert(addr2, buf2.Bytes(), nil)

	tree.ComputeCommitment()

	block1893Hash := bls.FrTo32(tree.ComputeCommitment())
	expected, _ = hex.DecodeString("55938f57d4211b306eb3a1404d4784b2e0a8fdb254f284834b3ccf74791e54ee")
	if !bytes.Equal(block1893Hash[:], expected) {
		t.Fatalf("error, got %x != 55938f57d4211b306eb3a1404d4784b2e0a8fdb254f284834b3ccf74791e54ee", block1803Hash)
	}
}

func TestConcurrentTrees(t *testing.T) {
	value := []byte("value")
	tree := New()
	err := tree.Insert(zeroKeyTest, value, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := tree.ComputeCommitment()

	threads := 2
	ch := make(chan *bls.Fr)
	builder := func() {
		tree := New()
		tree.Insert(zeroKeyTest, value, nil)
		ch <- tree.ComputeCommitment()
	}

	for i := 0; i < threads; i++ {
		go builder()
	}

	for i := 0; i < threads; i++ {
		root := <-ch
		if !bls.EqualFr(root, expected) {
			t.Error("Incorrect root")
		}
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

func BenchmarkCommitLeaves(b *testing.B) {
	benchmarkCommitNLeaves(b, 1000)
	benchmarkCommitNLeaves(b, 10000)
}

func BenchmarkCommitFullNode(b *testing.B) {
	nChildren := 256
	value := []byte("value")
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
			if err := root.Insert(k, value, nil); err != nil {
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

	h := bls.FrTo32(tree.ComputeCommitment())
	expected, _ := hex.DecodeString("61f23b37d460d8f3aee9d3a0b55c16194703de82ee971c9778ef6748df6ab42e")
	if !bytes.Equal(h[:], expected) {
		t.Fatalf("invalid hash: %x", h)
	}
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
		t.Error("parsed node not equal")
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
			if !bls.EqualFr(c.(*HashedNode).hash, hn.hash) {
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
	if !bytes.Equal(a.key, b.key) {
		return false
	}

	for i, v := range a.values {
		if !bytes.Equal(v, b.values[i]) {
			return false
		}
	}

	return true
}

func TestTreeHashingPython(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, zeroKeyTest, nil)
	root.Insert(oneKeyTest, zeroKeyTest, nil)

	rootcomm := bls.FrTo32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("5d2a77f5ab0ed54f61a1df01c01af3202f6975c4d071e4c0d04b3c1fe8126656")

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

	got := bls.FrTo32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("fd45a2b008eb4c973c6959656e9699d8a0c4b42004ee3e4bfd255637a0ca7142")

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

	got := bls.FrTo32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("9cc14a1a355b1d8012332773213e3448514ceae65a689546d78e7ab9aa34826f")

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

	got := bls.FrTo32(root.ComputeCommitment())
	expected, _ := hex.DecodeString("8755ef6cbe3392c6b646313c1566a41c67b90a40b45d9990965549ef5958d846")

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
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
		t.Fatalf("invalid result: %x != %x", zeroKeyTest, data)
	}
}

func TestGetKey(t *testing.T) {
	root := &LeafNode{key: fourtyKeyTest}
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
		node := &LeafNode{key: zeroKeyTest, values: make([][]byte, NodeWidth)}
		node.values[0] = zeroKeyTest

		return node.Serialize()
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, resolver); err != nil {
		t.Fatalf("error in node resolution: %v", err)
	}

	// Check that the proper error is raised if the RLP data is invalid and the
	// node can not be parsed.
	invalidRLPResolver := func(h []byte) ([]byte, error) {
		node := &LeafNode{key: zeroKeyTest, values: make([][]byte, NodeWidth)}
		node.values[0] = zeroKeyTest

		rlp, _ := node.Serialize()
		return rlp[:len(rlp)-10], nil
	}
	if err := root.Copy().Insert(zeroKeyTest, zeroKeyTest, invalidRLPResolver); !errors.Is(err, rlp.ErrValueTooLarge) {
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
