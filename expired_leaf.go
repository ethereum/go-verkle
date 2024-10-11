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
)

type ExpiredLeafNode struct {
	stem       Stem
	commitment *Point
}

var errExpiredLeafNode = errors.New("trying to access an expired leaf node")

func (ExpiredLeafNode) Insert([]byte, []byte, StateEpoch, NodeResolverFn) error {
	return errExpiredLeafNode
}

func (ExpiredLeafNode) Delete([]byte, StateEpoch, NodeResolverFn) (bool, error) {
	return false, errExpiredLeafNode
}

func (ExpiredLeafNode) Get([]byte, NodeResolverFn) ([]byte, error) {
	return nil, errExpiredLeafNode
}

func (n ExpiredLeafNode) Commit() *Point {
	if n.commitment == nil {
		panic("nil commitment")
	}
	return n.commitment
}

func (n ExpiredLeafNode) Commitment() *Point {
	return n.commitment
}

func (n ExpiredLeafNode) GetProofItems(keylist, NodeResolverFn) (*ProofElements, []byte, []Stem, error) {
	return nil, nil, nil, errExpiredLeafNode
}

func (n ExpiredLeafNode) Serialize() ([]byte, error) {
	cBytes := n.commitment.Bytes()

	var buf [expiredLeafSize]byte
	result := buf[:]
	result[0] = expiredLeafType
	copy(result[leafStemOffset:], n.stem[:StemSize])
	copy(result[leafStemOffset+StemSize:], cBytes[:])

	return result, nil
}

func (n ExpiredLeafNode) Copy() VerkleNode {
	l := &ExpiredLeafNode{}
	l.stem = make(Stem, len(n.stem))

	if n.commitment != nil {
		l.commitment = new(Point)
		l.commitment.Set(n.commitment)
	}

	return l
}

func (n ExpiredLeafNode) toDot(string, string) string {
	return ""
}

func (n ExpiredLeafNode) setDepth(_ byte) {
	panic("should not be try to set the depth of an ExpiredLeafNode node")
}

func (n ExpiredLeafNode) Hash() *Fr {
	var hash Fr
	n.commitment.MapToScalarField(&hash)
	return &hash
}
