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

	"github.com/protolambda/go-kzg/bls"
)

func TestStatelessInsertLeaf(t *testing.T) {
	root := &StatelessNode{
		commitment: new(bls.G1Point),
		hash:       new(bls.Fr),
		children:   make(map[byte]*StatelessNode),
		depth:      0,
	}

	root.Insert(zeroKeyTest, zeroKeyTest, nil)

	if len(root.children) != 1 {
		t.Fatalf("invalid number of children %d != 1", len(root.children))
	}

	if _, ok := root.children[0]; !ok {
		t.Fatal("child didn't end up in the correct subtree")
	}

	child := root.children[0]
	if len(child.children) != 0 {
		t.Fatalf("expected no children in leaf, got %d of them", len(child.children))
	}
	if len(child.values[0]) != 32 || !bytes.Equal(child.values[0], zeroKeyTest) {
		t.Fatalf("invalid value %x != %x", child.values[0], zeroKeyTest)
	}
	if len(child.key) != 31 || !bytes.Equal(child.key, zeroKeyTest[:31]) {
		t.Fatalf("invalid key %x != %x", child.key, zeroKeyTest[:31])
	}
}
