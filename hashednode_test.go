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

import "testing"

func TestHashedNodeFuncs(t *testing.T) {
	t.Parallel()

	e := HashedNode{}
	err := e.Insert(zeroKeyTest, zeroKeyTest, nil)
	if err != errInsertIntoHash {
		t.Fatal("got nil error when inserting into a hashed node")
	}
	_, err = e.Delete(zeroKeyTest, nil)
	if err == nil {
		t.Fatal("got nil error when deleting from a hashed node")
	}
	v, err := e.Get(zeroKeyTest, nil)
	if err == nil {
		t.Fatal("got nil error when getting from a hashed node")
	}
	if v != nil {
		t.Fatal("non-nil get from a hashed node")
	}
	if _, _, _, err := e.GetProofItems(nil, nil); err == nil {
		t.Fatal("got nil error when getting proof items from a hashed node")
	}
	if _, err := e.Serialize(); err != errSerializeHashedNode {
		t.Fatal("got nil error when serializing a hashed node")
	}
}
