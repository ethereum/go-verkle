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
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"testing"
)

func TestStatelessChildren(t *testing.T) {
	c2key, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000085")

	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	root.Insert(c2key, fourtyKeyTest, nil)
	root.Commit()

	list := root.Children()
	if len(list) != NodeWidth {
		t.Fatal("invalid list length")
	}

	var emptycount = 0
	for _, v := range list {
		if _, ok := v.(Empty); ok {
			emptycount++
		}
	}
	if emptycount != NodeWidth-1 {
		t.Fatal("invalid number of children")
	}

	if err := root.SetChild(72, Empty{}); !errors.Is(err, errStatelessAndStatefulMix) {
		t.Fatal("didn't catch a stateful node being inserted in a stateless node")
	}
	if err := root.SetChild(512, Empty{}); err == nil {
		t.Fatal("didn't catch a node being inserted at an invalid index in a stateless node")
	}

	// Adds a node that isn't in the tree, but since its commitmenht will be 0,
	// it shouldn't have an impact.
	if err := root.SetChild(3, &StatelessNode{commitment: Generator()}); err != nil {
		t.Fatal("error inserting stateless node")
	}

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(c2key, fourtyKeyTest, nil)

	if !Equal(rootRef.Commit(), root.commitment) {
		t.Fatalf("differing state(less|ful) roots %x != %x %s %s", rootRef.Commitment().Bytes(), root.Commit().Bytes(), ToDot(rootRef), ToDot(root))
	}
}

func TestStatelessDelete(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	var single Point
	CopyPoint(&single, root.Commit())

	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	if root.Commit().Equal(&single) {
		t.Fatal("second insert didn't update")
	}

	root.Delete(oneKeyTest, nil)

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Commit()
	rootRef.Delete(oneKeyTest, nil)

	if !Equal(rootRef.Commit(), root.Commit()) {
		t.Fatal("error in delete", rootRef.Commit(), root.hash)
	}
}

func TestStatelessInsertLeafIntoRoot(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Commit()

	rootRef := New().(*InternalNode)
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Commit()

	if !Equal(rootRef.commitment, root.commitment) {
		t.Fatalf("hashes differ after insertion %x %x", rootRef.commitment.Bytes(), root.commitment.Bytes())
	}

	// Overwrite one leaf and check that the update
	// is what is expected.
	rootRef = New().(*InternalNode)
	rootRef.Insert(zeroKeyTest, oneKeyTest, nil)
	rootRef.Commit()

	root.Insert(zeroKeyTest, oneKeyTest, nil)

	if !Equal(rootRef.commitment, root.Commit()) {
		t.Fatalf("hashes differ after update %x %x", rootRef.commitment.Bytes(), root.commitment.Bytes())
	}
}

func TestStatelessInsertLeafIntoLeaf(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	hash := rootRef.Commit()

	if !Equal(hash, root.Commit()) {
		t.Fatalf("hashes differ after insertion %v %v", hash, root.hash)
	}

	rootRef = New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, oneKeyTest, nil)
	hash = rootRef.Commit()

	root.Insert(oneKeyTest, oneKeyTest, nil)

	if !Equal(hash, root.Commit()) {
		t.Fatalf("hashes differ after update %v %v", hash, root.hash)
	}
}

func TestStatelessInsertLeafIntoInternal(t *testing.T) {
	key1, _ := hex.DecodeString("0000100000000000000000000000000000000000000000000000000000000000")
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(key1, fourtyKeyTest, nil)
	rootRef := New().(*InternalNode)
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(key1, fourtyKeyTest, nil)
	rootRef.Commit()

	if !Equal(rootRef.commitment, root.Commit()) {
		t.Fatalf("hashes differ after insertion %x %x %s %s", rootRef.commitment.Bytes(), root.commitment.Bytes(), ToDot(rootRef), ToDot(root))
	}
}

func TestStatelessCopy(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootCopy := root.Copy()
	if !Equal(rootCopy.Commit(), root.Commit()) {
		t.Fatalf("copy produced the wrong hash: %x != %x", rootCopy.Commitment().Bytes(), root.commitment.Bytes())
	}
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	if Equal(rootCopy.Commit(), root.Commit()) {
		t.Fatal("copy did not update the hash")
	}
}

func TestStatelessGet(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	data, err := root.Get(zeroKeyTest, nil)
	if err != nil {
		t.Fatalf("error while getting existing value %v", err)
	}
	if !bytes.Equal(data, fourtyKeyTest) {
		t.Fatalf("error getting value, expected %x, got %x", fourtyKeyTest, data)
	}

	data, err = root.Get(oneKeyTest, nil)
	if err != nil {
		t.Fatalf("error while getting non-existing value %v", err)
	}
	if data != nil {
		t.Fatalf("error: got value %x, expected nil", data)
	}
}

func TestStatelessComputeCommitmentEmptyRoot(t *testing.T) {
	root := NewStateless()
	if !root.hash.Equal(&FrZero) {
		t.Fatal("invalid commitment for the empty root")
	}
}

func TestStatelessToDot(t *testing.T) {
	key1, _ := hex.DecodeString("0000100000000000000000000000000000000000000000000000000000000000")
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	root.Insert(key1, fourtyKeyTest, nil)
	root.Commit()
	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(key1, fourtyKeyTest, nil)
	rootRef.Commit()

	var stl []string
	for _, str := range strings.Split(root.toDot("", ""), "\n") {
		if str == "" {
			continue
		}
		stl = append(stl, strings.ReplaceAll(str, " ", ""))
	}

	var stf []string
	for _, str := range strings.Split(rootRef.toDot("", ""), "\n") {
		if str == "" {
			continue
		}
		stf = append(stf, strings.ReplaceAll(str, " ", ""))
	}
	sort.Strings(stl)
	sort.Strings(stf)
	stfJ := strings.Join(stf, "\n")
	stlJ := strings.Join(stl, "\n")

	if stfJ != stlJ {
		t.Fatalf("hashes differ after insertion %v ||| %v %s %s", stf, stl, ToDot(rootRef), ToDot(root))
	}
}

// This test checks that node resolution works for StatelessNode
func TestStatelessInsertIntoHash(t *testing.T) {
	root := NewStateless()
	root.Insert(fourtyKeyTest, ffx32KeyTest, nil)

	saved := root.children[fourtyKeyTest[0]].(*LeafNode)
	root.children[fourtyKeyTest[0]] = saved.ToHashedNode()

	// overwrite the value that has been hashed
	root.Insert(fourtyKeyTest, zeroKeyTest, func(b []byte) ([]byte, error) {
		// Since the root is a stateless node, so is the leaf. And stateless
		// leaves can not currently be serialized. Create a stateful version
		// of that key.
		leaf := NewLeafNode(fourtyKeyTest[:31], make([][]byte, NodeWidth))
		leaf.Insert(fourtyKeyTest, ffx32KeyTest, nil)
		return leaf.Serialize()
	})

	recovered, err := root.Get(fourtyKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(recovered, zeroKeyTest) {
		t.Fatalf("incorrect value found: %x != %x", recovered, zeroKeyTest)
	}

	if _, ok := root.children[fourtyKeyTest[0]].(*LeafNode); !ok {
		t.Fatalf("invalid node type %v isn't a LeafNode", root.children[fourtyKeyTest[0]])
	}
}

// This test checks that a serialized node will be deserialized before
// being inserted into, during leaf insertion.
func TestStatelessInsertIntoSerialized(t *testing.T) {
	flushed := map[string][]byte{}
	rootF := New()
	rootF.Insert(fourtyKeyTest, ffx32KeyTest, nil)
	rootc := rootF.Commit().Bytes()
	rootF.(*InternalNode).Flush(func(vn VerkleNode) {
		ser, err := vn.Serialize()
		if err != nil {
			panic(err)
		}
		comm := vn.Commit().Bytes()
		flushed[string(comm[:])] = ser
	})

	root, err := ParseStatelessNode(flushed[string(rootc[:])], 0, rootc[:])
	if err != nil {
		t.Fatal(err)
	}

	// overwrite the value that has been hashed
	root.Insert(fourtyKeyTest, zeroKeyTest, func(b []byte) ([]byte, error) {
		return flushed[string(b)], nil
	})

	recovered, err := root.Get(fourtyKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(recovered, zeroKeyTest) {
		t.Fatalf("incorrect value found: %x != %x", recovered, zeroKeyTest)
	}

	if _, ok := root.(*StatelessNode).children[fourtyKeyTest[0]].(*LeafNode); !ok {
		t.Fatalf("invalid node type %v isn't a LeafNode", root.(*StatelessNode).children[fourtyKeyTest[0]])
	}
}

func TestStatelessInsertAtStem(t *testing.T) {
	root := NewStateless()
	values := [256][]byte{ffx32KeyTest, fourtyKeyTest, zeroKeyTest, oneKeyTest}
	root.InsertAtStem(zeroKeyTest[:31], values[:], nil, false)

	out, err := root.Get(zeroKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, ffx32KeyTest) {
		t.Fatalf("invalid valud %x != %x\n", out, ffx32KeyTest)
	}
	out, err = root.Get(oneKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, fourtyKeyTest) {
		t.Fatalf("invalid valud %x != %x\n", out, fourtyKeyTest)
	}

	root.InsertAtStem(zeroKeyTest[:31], [][]byte{nil, ffx32KeyTest, nil, nil, oneKeyTest}, nil, false)

	out, err = root.Get(oneKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, ffx32KeyTest) {
		t.Fatalf("invalid value %x != %x\n", out, fourtyKeyTest)
	}
}

func TestStatelessInsertIntoLeaf(t *testing.T) {
	flushed := map[string][]byte{}
	rootF := New()
	rootF.Insert(zeroKeyTest, ffx32KeyTest, nil)
	rootc := rootF.Commit().Bytes()
	rootF.(*InternalNode).Flush(func(vn VerkleNode) {
		ser, err := vn.Serialize()
		if err != nil {
			panic(err)
		}
		comm := vn.Commit().Bytes()
		flushed[string(comm[:])] = ser
	})

	root, err := ParseStatelessNode(flushed[string(rootc[:])], 0, rootc[:])
	if err != nil {
		t.Fatal(err)
	}
	root.Insert(splitKeyTest, zeroKeyTest, func(b []byte) ([]byte, error) {
		return flushed[string(b)], nil
	})
}

func TestStatelessInsertAtStemIntoLeaf(t *testing.T) {
	flushed := map[string][]byte{}
	rootF := New()
	rootF.Insert(zeroKeyTest, ffx32KeyTest, nil)
	rootc := rootF.Commit().Bytes()
	rootF.(*InternalNode).Flush(func(vn VerkleNode) {
		ser, err := vn.Serialize()
		if err != nil {
			panic(err)
		}
		comm := vn.Commit().Bytes()
		flushed[string(comm[:])] = ser
	})

	root, err := ParseStatelessNode(flushed[string(rootc[:])], 0, rootc[:])
	if err != nil {
		t.Fatal(err)
	}

	values := [256][]byte{nil, ffx32KeyTest, nil, nil, oneKeyTest}
	// test updating an existing key
	root.(*StatelessNode).InsertAtStem(zeroKeyTest[:31], values[:], func(b []byte) ([]byte, error) {
		return flushed[string(b)], nil
	}, false)

	// test inserting a new key
	root.(*StatelessNode).InsertAtStem(splitKeyTest[:31], values[:], func(b []byte) ([]byte, error) {
		return flushed[string(b)], nil
	}, false)

	out, err := root.Get(splitKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("got %x, expected nil", out)
	}
	out, err = root.Get(zeroKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ffx32KeyTest, out) {
		t.Fatalf("got %x, expected %x", out, ffx32KeyTest)
	}
	var key1 [32]byte
	copy(key1[:], splitKeyTest)
	key1[31] = 1
	out, err = root.Get(key1[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ffx32KeyTest, out) {
		t.Fatalf("got %x, expected %x", out, ffx32KeyTest)
	}
}

func TestSerialization(t *testing.T) {
	rootf := New()
	roots := NewStateless()

	rootf.Insert(zeroKeyTest, ffx32KeyTest, nil)
	roots.Insert(zeroKeyTest, ffx32KeyTest, nil)
	rootf.Commit()

	serf, _ := rootf.Serialize()
	sers, _ := roots.Serialize()

	if !bytes.Equal(serf, sers) {
		t.Fatalf("invalid serialization: %x != %x", sers, serf)
	}
}
