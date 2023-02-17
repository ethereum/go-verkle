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
	"errors"
	"fmt"
)

type HashedNode struct {
	commitment  SerializedPointCompressed
	serialized  SerializedPoint
	cachedPoint *Point
}

func NewHashedNode(buf SerializedPoint) *HashedNode {
	var h HashedNode
	h.serialized = buf

	return &h
}

func (*HashedNode) Insert([]byte, []byte, NodeResolverFn) error {
	return errInsertIntoHash
}

func (h *HashedNode) BytesUncompressed() []byte {
	if h.serialized == nil {
		if h.cachedPoint != nil {
			h.serialized = h.cachedPoint.BytesUncompressed()
			return h.serialized
		}
		h.cachedPoint = new(Point)
		h.cachedPoint.SetBytes(h.commitment, true)
		return h.BytesUncompressed()

	}
	return h.serialized
}

func (h *HashedNode) BytesCompressed() []byte {
	if h.commitment == nil {
		if h.cachedPoint != nil {
			h.commitment = h.cachedPoint.Bytes()
			return h.commitment
		}
		h.commitment = h.serialized.ToCompressed()
	}
	return h.commitment
}

func (*HashedNode) InsertOrdered([]byte, []byte, NodeFlushFn) error {
	return errInsertIntoHash
}

func (*HashedNode) Delete([]byte, NodeResolverFn) error {
	return errors.New("cant delete a hashed node in-place")
}

func (*HashedNode) Get([]byte, NodeResolverFn) ([]byte, error) {
	return nil, errors.New("can not read from a hash node")
}

func (n *HashedNode) Commit() *Point {
	if n.cachedPoint == nil {
		n.cachedPoint = new(Point)
		if n.serialized != nil {
			n.cachedPoint.SetBytesUncompressed(n.serialized, true)
		} else {
			n.cachedPoint.SetBytes(n.commitment, true)
		}
	}
	return n.cachedPoint
}

func (n *HashedNode) Commitment() *Point {
	return n.Commit()
}

func (*HashedNode) GetProofItems(keylist) (*ProofElements, []byte, [][]byte) {
	panic("can not get the full path, and there is no proof of absence")
}

func (*HashedNode) Serialize() ([]byte, error) {
	return nil, errSerializeHashedNode
}

func (n *HashedNode) Copy() VerkleNode {
	if n.serialized == nil {
		panic("invalid hashed node")
	}

	c := &HashedNode{
		serialized: make([]byte, len(n.serialized)),
	}
	copy(c.serialized, n.serialized)

	return c
}

func (n *HashedNode) toDot(parent, path string) string {
	return fmt.Sprintf("hash%s [label=\"H: %x\"]\n%s -> hash%s\n", path, n.commitment, parent, path)
}

func (*HashedNode) setDepth(_ byte) {
	// do nothing
}

func (n *HashedNode) Hash() *Fr {
	comm := n.Commitment()
	hash := new(Fr)
	toFr(hash, comm)
	return hash
}
