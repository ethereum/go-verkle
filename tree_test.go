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
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var testValue = []byte("hello")

func TestInsertIntoRoot(t *testing.T) {
	root := New()
	err := root.Insert(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), testValue)
	if err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	// Check that the value is present in the tree
	node := root
	for i := 0; i < 25; i++ {
		n, ok := node.(*internalNode)
		if !ok {
			t.Fatalf("unexpected node type at level %d", i)
		}
		node = n.children[0]
	}

	child, ok := node.(*lastLevelNode)
	if !ok {
		t.Fatalf("unexpected node type at last level: %v", node)
	}

	leaf, ok := child.children[0].(leafNode)
	if !ok {
		t.Fatal("invalid leaf node type")
	}

	if !bytes.Equal(leaf[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf[:])
	}
}

func TestInsertTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), testValue)
	root.Insert(common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), testValue)

	// Check that the first value is present in the tree
	node := root
	for i := 0; i < 25; i++ {
		n, ok := node.(*internalNode)
		if !ok {
			t.Fatalf("unexpected node type at level %d", i)
		}
		node = n.children[0]
	}

	child, ok := node.(*lastLevelNode)
	if !ok {
		t.Fatalf("unexpected node type at last level: %v", node)
	}

	leaf, ok := child.children[0].(leafNode)
	if !ok {
		t.Fatal("invalid leaf node type")
	}

	if !bytes.Equal(leaf[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf[:])
	}

	// Check that the second value is present in the tree
	node = root
	for i := 0; i < 25; i++ {
		n, ok := node.(*internalNode)
		if !ok {
			t.Fatalf("unexpected node type at level %d", i)
		}
		node = n.children[1023]
	}

	child, ok = node.(*lastLevelNode)
	if !ok {
		t.Fatalf("unexpected node type at last level: %v", node)
	}

	leaf, ok = child.children[63].(leafNode)
	if !ok {
		t.Fatal("invalid leaf node type")
	}

	if !bytes.Equal(leaf[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf[:])
	}
}

func TestGetTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), testValue)
	root.Insert(common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), testValue)

	val, err := root.Get(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("got a different value from the tree than expected %x != %x", val, testValue)
	}

	val, err = root.Get(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	if err != nil {
		t.Fatal(err)
	}

	if val != nil {
		t.Fatalf("got a different value from the tree than expected %x != nil", val)
	}
}

func TestTreeHashing(t *testing.T) {
	root := New()
	root.Insert(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), testValue)
	root.Insert(common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), testValue)

	root.Hash()
}
