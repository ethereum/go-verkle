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

// StatelessNode represents a node for execution in a stateless context,
// i.e. that its children/values are not all known. It can represent both
// an InternalNode or a LeafNode.
type StatelessNode struct {
	// List of available child nodes of this internal node,
	// nil if this is an extension node.
	children map[byte]*StatelessNode

	// List of values, nil if this is an internal node.
	values map[byte][]byte

	stem []byte

	// node depth in the tree, in bits
	depth int

	// child count, used for the special case in
	// commitment calculations.
	count uint

	// Cache the field representation of the hash
	// of the current node.
	hash *Fr

	// Cache the commitment value
	commitment, c1, c2 *Point

	committer Committer
}

func NewStateless() *StatelessNode {
	return &StatelessNode{
		children:   make(map[byte]*StatelessNode),
		hash:       new(Fr).SetZero(),
		committer:  GetConfig(),
		commitment: Generator(),
	}
}

func (n *StatelessNode) Children() []VerkleNode {
	var children []VerkleNode
	for _, child := range n.children {
		children = append(children, child)
	}
	return children
}

func (n *StatelessNode) SetChild(i int, v VerkleNode) error {
	if i >= NodeWidth-1 {
		return errors.New("child index higher than node width")
	}
	c, ok := v.(*StatelessNode)
	if !ok {
		return errors.New("inserting non-stateless node into a stateless node")
	}
	n.children[byte(i)] = c
	return nil
}

func (n *StatelessNode) Insert(key []byte, value []byte, resolver NodeResolverFn) error {
	// if this is a leaf value and the stems are different, intermediate
	// nodes need to be inserted.
	if n.values != nil {
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if equalPaths(n.stem, key) {
			if n.values[key[31]] == nil {
				// only increase the count if no value is
				// overwritten.
				n.count++
			}
			n.values[key[31]] = value
			// TODO: instead of invalidating the commitment
			// and recalulating it entirely, compute the diff.
			n.hash = nil
			n.ComputeCommitment()
		} else {
			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := offset2key(n.stem, n.depth)
			oldExtNode := &StatelessNode{
				depth:      n.depth + NodeBitWidth,
				committer:  n.committer,
				count:      n.count,
				values:     n.values,
				stem:       n.stem,
				commitment: n.commitment,
				hash:       n.hash,
				c1:         n.c1,
				c2:         n.c2,
			}
			n.children = map[byte]*StatelessNode{
				nextWordInExistingKey: oldExtNode,
			}
			n.values = nil
			n.stem = nil
			n.c1 = nil
			n.c2 = nil
			n.count++

			nextWordInInsertedKey := offset2key(key, n.depth)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Next word differs, so the branching point
				// has been reached. Create the "new" child.
				n.children[nextWordInInsertedKey] = &StatelessNode{
					depth:     n.depth + NodeBitWidth,
					stem:      key[:31],
					values:    map[byte][]byte{key[31]: value},
					committer: n.committer,
					count:     1,
				}
				n.children[nextWordInInsertedKey].ComputeCommitment()
			}

			// recurse into the newly created child
			if err := n.children[nextWordInInsertedKey].Insert(key, value, resolver); err != nil {
				return err
			}

			var poly [NodeWidth]Fr
			CopyFr(&poly[nextWordInExistingKey], oldExtNode.hash)
			if nextWordInExistingKey != nextWordInInsertedKey {
				CopyFr(&poly[nextWordInInsertedKey], n.children[nextWordInInsertedKey].hash)
			}
			n.commitment = n.committer.CommitToPoly(poly[:], NodeWidth-2)
			toFr(n.hash, n.commitment)
		}
	} else {
		// internal node
		nChild := offset2key(key, n.depth)

		// special case: missing child, insert a leaf
		if n.children[nChild] == nil {
			n.children[nChild] = &StatelessNode{
				depth:      n.depth + NodeBitWidth,
				count:      1,
				values:     map[byte][]byte{key[31]: value},
				committer:  n.committer,
				stem:       key[:31],
				commitment: Generator(),
			}
			n.children[nChild].ComputeCommitment()
			var diff Point
			diff.ScalarMul(&GetConfig().conf.SRS[nChild], n.children[nChild].hash)
			n.commitment.Add(n.commitment, &diff)
			toFr(n.hash, n.commitment)
			return nil
		}

		// Save the value of the initial child commitment
		var pre Fr
		CopyFr(&pre, n.children[nChild].hash)

		if err := n.children[nChild].Insert(key, value, resolver); err != nil {
			return err
		}

		// update the commitment
		var diff Point
		diff.ScalarMul(&GetConfig().conf.SRS[nChild], pre.Sub(n.children[nChild].hash, &pre))
		n.commitment.Add(n.commitment, &diff)
	}

	toFr(n.hash, n.commitment)
	return nil
}

func (*StatelessNode) InsertOrdered([]byte, []byte, NodeFlushFn) error {
	return errors.New("not implemented")
}

func (n *StatelessNode) Delete(key []byte) error {
	// Case of an ext node
	if n.values != nil {
		var zero [32]byte
		// Set the value to 0, data can not be deleted
		n.values[key[31]] = zero[:]
		n.hash = nil
		n.ComputeCommitment()
		return nil
	}

	nChild := offset2key(key, n.depth)
	child := n.children[nChild]
	var pre Fr
	CopyFr(&pre, child.hash)
	if err := child.Delete(key); err != nil {
		return err
	}

	pre.Sub(child.hash, &pre)

	var tmp Point
	tmp.ScalarMul(&GetConfig().conf.SRS[nChild], &pre)
	n.commitment.Add(n.commitment, &tmp)
	toFr(n.hash, n.commitment)
	return nil
}

func (n *StatelessNode) Get(k []byte, getter NodeResolverFn) ([]byte, error) {
	if n.values != nil {
		return n.values[k[31]], nil
	}

	nChild := offset2key(k, n.depth)

	child := n.children[nChild]
	if child == nil {
		return nil, nil
	}
	return child.Get(k, getter)
}

func (n *StatelessNode) ComputeCommitment() *Fr {
	if n.hash != nil {
		return n.hash
	}

	if n.count == 0 {
		if n.depth != 0 {
			panic("internal node should be empty node")
		}

		n.commitment = new(Point)
		n.commitment.Identity()
		n.hash = new(Fr)
		toFr(n.hash, n.commitment)
		return n.hash
	}

	n.hash = new(Fr)

	if n.values != nil {
		// leaf node: go over each value, and set them in the
		// polynomial for the corresponding suffix node.
		count1, count2 := 0, 0
		var poly, c1poly, c2poly [256]Fr
		poly[0].SetUint64(1)
		fromBytes(&poly[1], n.stem)

		for idx, val := range n.values {
			if idx < 128 {
				leafToComms(c1poly[idx<<1:], val)
				count1++
			} else {
				leafToComms(c2poly[(idx<<1)&0xFF:], val)
				count2++
			}
		}
		n.c1 = n.committer.CommitToPoly(c1poly[:], 256-count1)
		toFr(&poly[2], n.c1)
		n.c2 = n.committer.CommitToPoly(c2poly[:], 256-count2)
		toFr(&poly[3], n.c2)

		n.commitment = n.committer.CommitToPoly(poly[:], 252)
		toFr(n.hash, n.commitment)
	} else {
		// internal node
		emptyChildren := 0
		poly := make([]Fr, NodeWidth)
		for idx, child := range n.children {
			CopyFr(&poly[idx], child.ComputeCommitment())
		}

		// All the coefficients have been computed, evaluate the polynomial,
		// serialize and hash the resulting point - this is the commitment.
		n.commitment = n.committer.CommitToPoly(poly, emptyChildren)
		toFr(n.hash, n.commitment)
	}

	return n.hash
}

func (n *StatelessNode) GetCommitmentsAlongPath(key []byte) *ProofElements {
	childIdx := offset2key(key, n.depth)

	// Build the list of elements for this level
	var yi Fr
	fi := make([]Fr, NodeWidth)
	for i, child := range n.children {
		CopyFr(&fi[i], child.ComputeCommitment())

		if i == childIdx {
			CopyFr(&yi, &fi[i])
		}
	}

	// The proof elements that are to be added at this level
	pe := &ProofElements{
		Cis: []*Point{n.commitment},
		Zis: []uint8{childIdx},
		Yis: []*Fr{&yi}, // Should be 0
		Fis: [][]Fr{fi},
	}

	// Special case of a proof of absence: no children
	// commitment, as the value is 0.
	if n.children[childIdx] == nil {
		return pe
	}

	pec := n.children[childIdx].GetCommitmentsAlongPath(key)
	pe.Merge(pec)
	return pe
}

func (*StatelessNode) Serialize() ([]byte, error) {
	return nil, errors.New("not supported")
}

func (n *StatelessNode) Copy() VerkleNode {
	ret := &InternalNode{
		children:   make([]VerkleNode, len(n.children)),
		commitment: new(Point),
		depth:      n.depth,
		committer:  n.committer,
		count:      n.count,
	}

	for i, child := range n.children {
		ret.children[i] = child.Copy()
	}

	if n.hash != nil {
		ret.hash = new(Fr)
		CopyFr(ret.hash, n.hash)
	}
	if n.commitment != nil {
		CopyPoint(ret.commitment, n.commitment)
	}

	return ret
}

func (n *StatelessNode) toDot(parent, path string) string {
	n.ComputeCommitment()
	me := fmt.Sprintf("internal%s", path)
	var ret string
	if n.values != nil {
		ret = fmt.Sprintf("leaf%s [label=\"L: %x\nC: %x\nC₁: %x\nC₂:%x\"]\n%s -> leaf%s\n", path, n.hash.Bytes(), n.commitment.Bytes(), n.c1.Bytes(), n.c2.Bytes(), parent, path)
		for i, v := range n.values {
			if v != nil {
				ret = fmt.Sprintf("%sval%s%x [label=\"%x\"]\nleaf%s -> val%s%x\n", ret, path, i, v, path, path, i)
			}
		}
	} else {
		ret = fmt.Sprintf("%s [label=\"I: %x\"]\n", me, n.hash.Bytes())
		if len(parent) > 0 {
			ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
		}

		for i, child := range n.children {
			ret = fmt.Sprintf("%s%s", ret, child.toDot(me, fmt.Sprintf("%s%02x", path, i)))
		}
	}

	return ret
}
