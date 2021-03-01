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

var (
	zeroKeyTest  = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")
	ffx32KeyTest = common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
)

func TestInsertIntoRoot(t *testing.T) {
	root := New()
	err := root.Insert(zeroKeyTest, testValue)
	if err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*internalNode).children[0].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*internalNode).children[0])
	}

	if !bytes.Equal(leaf.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.value[:])
	}
}

func TestInsertTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	leaf0, ok := root.(*internalNode).children[0].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*internalNode).children[0])
	}

	leaff, ok := root.(*internalNode).children[1023].(*leafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*internalNode).children[1023])
	}

	if !bytes.Equal(leaf0.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf0.value[:])
	}

	if !bytes.Equal(leaff.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaff.value[:])
	}
}

func TestGetTwoLeaves(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	val, err := root.Get(zeroKeyTest)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("got a different value from the tree than expected %x != %x", val, testValue)
	}

	val, err = root.Get(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001"))
	if err != errValueNotPresent {
		t.Fatalf("wrong error type, expected %v, got %v", errValueNotPresent, err)
	}

	if val != nil {
		t.Fatalf("got a different value from the tree than expected %x != nil", val)
	}
}

func TestTreeHashing(t *testing.T) {
	root := New()
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	root.Hash()
}
