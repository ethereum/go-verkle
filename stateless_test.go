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
	"sort"
	"strings"
	"testing"
)

func TestStatelessChildren(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)

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

	if err := root.SetChild(72, Empty{}); err == nil {
		t.Fatal("didn't catch a stateful node being inserted in a stateless node")
	}
	if err := root.SetChild(512, Empty{}); err == nil {
		t.Fatal("didn't catch a node being inserted at an invalid index in a stateless node")
	}

	if err := root.SetChild(3, &StatelessNode{}); err != nil {
		t.Fatal("error inserting stateless node")
	}
}

func TestStatelessDelete(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	var single Point
	CopyPoint(&single, root.commitment)

	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	if root.commitment.Equal(&single) {
		t.Fatal("second insert didn't update")
	}

	root.Delete(oneKeyTest)

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Delete(oneKeyTest)

	if !Equal(rootRef.ComputeCommitment(), root.commitment) {
		t.Fatal("error in delete", rootRef.ComputeCommitment(), root.hash)
	}
}

func TestStatelessInsertLeafIntoRoot(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	hash := rootRef.ComputeCommitment()

	if !Equal(hash, root.commitment) {
		t.Fatalf("hashes differ after insertion %v %v", hash, root.hash)
	}

	// Overwrite one leaf and check that the update
	// is what is expected.
	rootRef = New()
	rootRef.Insert(zeroKeyTest, oneKeyTest, nil)
	hash = rootRef.ComputeCommitment()

	root.Insert(zeroKeyTest, oneKeyTest, nil)

	if !Equal(hash, root.commitment) {
		t.Fatalf("hashes differ after update %v %v", hash, root.hash)
	}
}

func TestStatelessInsertLeafIntoLeaf(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	hash := rootRef.ComputeCommitment()

	if !Equal(hash, root.commitment) {
		t.Fatalf("hashes differ after insertion %v %v", hash, root.hash)
	}

	rootRef = New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, oneKeyTest, nil)
	hash = rootRef.ComputeCommitment()

	root.Insert(oneKeyTest, oneKeyTest, nil)

	if !Equal(hash, root.commitment) {
		t.Fatalf("hashes differ after update %v %v", hash, root.hash)
	}
}

func TestStatelessInsertLeafIntoInternal(t *testing.T) {
	key1, _ := hex.DecodeString("0000100000000000000000000000000000000000000000000000000000000000")
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(key1, fourtyKeyTest, nil)
	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(key1, fourtyKeyTest, nil)
	hash := rootRef.ComputeCommitment()

	if !Equal(hash, root.commitment) {
		t.Fatalf("hashes differ after insertion %v %v", hash, root.hash)
	}
}

func TestStatelessInsertOrdered(t *testing.T) {
	root := NewStateless()
	err := root.InsertOrdered(zeroKeyTest, fourtyKeyTest, nil)
	if err != errNotSupportedInStateless {
		t.Fatalf("got the wrong error: expected %v, got %v", errNotSupportedInStateless, err)
	}
}

func TestStatelessCopy(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootCopy := root.Copy()
	if !Equal(rootCopy.ComputeCommitment(), root.commitment) {
		t.Fatal("copy produced the wrong hash")
	}
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	if Equal(rootCopy.ComputeCommitment(), root.commitment) {
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
	root := &StatelessNode{}
	root.ComputeCommitment()
	if !root.hash.Equal(&FrZero) {
		t.Fatal("invalid commitment for the empty root")
	}

	root.depth = 10
	root.hash = nil
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("should have caught the computation of an invalid node")
		}
	}()
	root.ComputeCommitment()

	t.Fatal("should have panicked before")
}

func TestStatelessToDot(t *testing.T) {
	key1, _ := hex.DecodeString("0000100000000000000000000000000000000000000000000000000000000000")
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	root.Insert(key1, fourtyKeyTest, nil)
	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(key1, fourtyKeyTest, nil)
	rootRef.ComputeCommitment()

	stl := strings.Split(root.toDot("", ""), "\n")
	stf := strings.Split(rootRef.toDot("", ""), "\n")
	sort.Strings(stl)
	sort.Strings(stf)
	stfJ := strings.Join(stf, "\n")
	stlJ := strings.Join(stl, "\n")

	if stfJ != stlJ {
		t.Fatalf("hashes differ after insertion %v ||| %v", stf, stl)
	}
}

func TestStatelessDeserialize(t *testing.T) {
	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	root.Insert(fourtyKeyTest, fourtyKeyTest, nil)
	root.Insert(ffx32KeyTest, fourtyKeyTest, nil)

	proof, _, _, _ := MakeVerkleMultiProof(root, keylist{zeroKeyTest, fourtyKeyTest}, map[string][]byte{string(zeroKeyTest): fourtyKeyTest, string(fourtyKeyTest): fourtyKeyTest})

	serialized, _, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, keyvals)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof)
	if err != nil {
	}

	if droot.ComputeCommitment() != root.ComputeCommitment() {
		t.Fatal("differing root commitments")
	}
}
