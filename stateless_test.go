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
	c2key, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000085")

	root := NewStateless()
	root.Insert(zeroKeyTest, fourtyKeyTest, nil)
	root.Insert(oneKeyTest, fourtyKeyTest, nil)
	root.Insert(c2key, fourtyKeyTest, nil)

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

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(c2key, fourtyKeyTest, nil)

	if !Equal(rootRef.ComputeCommitment(), root.commitment) {
		t.Fatalf("differing state(less|ful) roots %x != %x", rootRef.ComputeCommitment(), root.commitment)
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

	root.Delete(oneKeyTest, nil)

	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Delete(oneKeyTest, nil)

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
	rootRef := New()
	rootRef.Insert(zeroKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(oneKeyTest, fourtyKeyTest, nil)
	rootRef.Insert(key1, fourtyKeyTest, nil)
	rootRef.ComputeCommitment()

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
		t.Fatalf("hashes differ after insertion %v ||| %v", stf, stl)
	}
}

func TestStatelessDeserialize(t *testing.T) {
	root := New()
	for _, k := range [][]byte{zeroKeyTest, oneKeyTest, fourtyKeyTest, ffx32KeyTest} {
		root.Insert(k, fourtyKeyTest, nil)
	}
	keyvals := []KeyValuePair{
		{zeroKeyTest, fourtyKeyTest},
		{fourtyKeyTest, fourtyKeyTest},
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, keylist{zeroKeyTest, fourtyKeyTest}, map[string][]byte{string(zeroKeyTest): fourtyKeyTest, string(fourtyKeyTest): fourtyKeyTest})

	serialized, _, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, keyvals)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.ComputeCommitment())
	if err != nil {
		t.Fatal(err)
	}

	if droot.ComputeCommitment() != root.ComputeCommitment() {
		t.Fatal("differing root commitments")
	}

	if !Equal(droot.(*StatelessNode).children[0].(*StatelessNode).commitment, root.(*InternalNode).children[0].ComputeCommitment()) {
		t.Fatal("differing commitment for child #0")
	}

	if !Equal(droot.(*StatelessNode).children[64].ComputeCommitment(), root.(*InternalNode).children[64].ComputeCommitment()) {
		t.Fatal("differing commitment for child #64")
	}
}

func TestStatelessDeserializeMissginChildNode(t *testing.T) {
	root := New()
	for _, k := range [][]byte{zeroKeyTest, oneKeyTest, ffx32KeyTest} {
		root.Insert(k, fourtyKeyTest, nil)
	}
	keyvals := []KeyValuePair{
		{zeroKeyTest, fourtyKeyTest},
		{fourtyKeyTest, nil},
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, keylist{zeroKeyTest, fourtyKeyTest}, map[string][]byte{string(zeroKeyTest): fourtyKeyTest, string(fourtyKeyTest): nil})

	serialized, _, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, keyvals)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.ComputeCommitment())
	if err != nil {
		t.Fatal(err)
	}

	if droot.ComputeCommitment() != root.ComputeCommitment() {
		t.Fatal("differing root commitments")
	}

	if !Equal(droot.(*StatelessNode).children[0].ComputeCommitment(), root.(*InternalNode).children[0].ComputeCommitment()) {
		t.Fatal("differing commitment for child #0")
	}

	if droot.(*StatelessNode).children[64] != nil {
		t.Fatal("non-nil child #64")
	}
}

func TestStatelessDeserializeDepth2(t *testing.T) {
	root := New()
	key1, _ := hex.DecodeString("0000010000000000000000000000000000000000000000000000000000000000")
	for _, k := range [][]byte{zeroKeyTest, key1} {
		root.Insert(k, fourtyKeyTest, nil)
	}
	keyvals := []KeyValuePair{
		{zeroKeyTest, fourtyKeyTest},
		{key1, nil},
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, keylist{zeroKeyTest, key1}, map[string][]byte{string(zeroKeyTest): fourtyKeyTest, string(key1): nil})

	serialized, _, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, keyvals)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.ComputeCommitment())
	if err != nil {
		t.Fatal(err)
	}

	if droot.ComputeCommitment() != root.ComputeCommitment() {
		t.Fatal("differing root commitments")
	}

	if !Equal(droot.(*StatelessNode).children[0].ComputeCommitment(), root.(*InternalNode).children[0].ComputeCommitment()) {
		t.Fatal("differing commitment for child #0")
	}
}

func TestStatelessGetProofItems(t *testing.T) {
	insertedKeys := [][]byte{zeroKeyTest, oneKeyTest, ffx32KeyTest}
	provenKeys := [][]byte{zeroKeyTest, fourtyKeyTest}

	root := New()
	for _, k := range insertedKeys {
		root.Insert(k, fourtyKeyTest, nil)
	}
	keyvals := []KeyValuePair{
		{zeroKeyTest, fourtyKeyTest},
		{fourtyKeyTest, nil},
	}

	proof, _, _, _, _ := MakeVerkleMultiProof(root, keylist(provenKeys), map[string][]byte{string(zeroKeyTest): fourtyKeyTest, string(fourtyKeyTest): nil})

	serialized, _, err := SerializeProof(proof)
	if err != nil {
		t.Fatalf("could not serialize proof: %v", err)
	}

	dproof, err := DeserializeProof(serialized, keyvals)
	if err != nil {
		t.Fatalf("error deserializing proof: %v", err)
	}

	droot, err := TreeFromProof(dproof, root.ComputeCommitment())
	if err != nil {
		t.Fatal(err)
	}

	pel, _, _ := droot.GetProofItems(keylist(provenKeys))
	pef, _, _ := root.GetProofItems(keylist(provenKeys))

	for i, c := range pel.Cis {
		if !Equal(c, pef.Cis[i]) {
			t.Fatalf("differing commitment at %d: %x != %x", i, c.Bytes(), pef.Cis[i].Bytes())
		}
	}
	if len(pel.Cis) != len(pef.Cis) {
		t.Fatal("commitments have different length")
	}

	if !bytes.Equal(pel.Zis, pef.Zis) {
		t.Fatalf("differing index list %v != %v", pel.Zis, pef.Zis)
	}
	if len(pel.Zis) != len(pef.Zis) {
		t.Fatal("indices have different length")
	}

	for i, y := range pel.Yis {
		l := y.Bytes()
		f := pef.Yis[i].Bytes()
		if !bytes.Equal(l[:], f[:]) {
			t.Fatalf("differing eval #%d %x != %x", i, l, f)
		}
	}
	if len(pel.Yis) != len(pef.Yis) {
		t.Fatal("evaluations have different length")
	}
}

// This test check that node resolution works for StatelessNode
func TestStatelessInsertIntoHash(t *testing.T) {
	root := NewStateless()
	root.Insert(fourtyKeyTest, ffx32KeyTest, nil)

	saved := root.children[fourtyKeyTest[0]].(*StatelessNode)
	root.children[fourtyKeyTest[0]] = saved.toHashedNode()

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
	rootc := rootF.ComputeCommitment().Bytes()
	rootF.(*InternalNode).Flush(func(vn VerkleNode) {
		ser, err := vn.Serialize()
		if err != nil {
			panic(err)
		}
		comm := vn.ComputeCommitment().Bytes()
		flushed[string(comm[:])] = ser
	})

	root, err := ParseNode(flushed[string(rootc[:])], 0, rootc[:])
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
