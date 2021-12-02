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

type (
	InternalNodeStateless struct {
		// List of available child nodes of this internal node.
		children map[byte]VerkleNode

		// node depth in the tree, in bits
		depth int

		// child count, used for the special case in
		// commitment calculations.
		count uint

		// Cache the field representation of the hash
		// of the current node.
		hash *Fr

		// Cache the commitment value
		commitment *Point

		committer Committer
	}
)

func (n *InternalNodeStateless) Children() []VerkleNode {
	var children []VerkleNode
	for _, child := range n.children {
		children = append(children, child)
	}
	return children
}

func (n *InternalNodeStateless) SetChild(i int, c VerkleNode) error {
	if i >= NodeWidth-1 {
		return errors.New("child index higher than node width")
	}
	n.children[byte(i)] = c
	return nil
}

func (n *InternalNodeStateless) Insert(key []byte, value []byte, resolver NodeResolverFn) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
		n.hash = nil
	}

	nChild := offset2key(key, n.depth)

	switch child := n.children[nChild].(type) {
	case Empty:
		lastNode := &LeafNode{
			stem:      key[:31],
			values:    make([][]byte, NodeWidth),
			committer: n.committer,
		}
		lastNode.values[key[31]] = value
		n.children[nChild] = lastNode
		n.count++
	case *HashedNode:
		if resolver != nil {
			hash := child.ComputeCommitment().Bytes()
			serialized, err := resolver(hash[:])
			if err != nil {
				return fmt.Errorf("verkle tree: error resolving node %x: %w", key, err)
			}
			resolved, err := ParseNode(serialized, n.depth+NodeBitWidth)
			if err != nil {
				return fmt.Errorf("verkle tree: error parsing resolved node %x: %w", key, err)
			}
			n.children[nChild] = resolved
			return n.children[nChild].Insert(key, value, resolver)
		}
		return errInsertIntoHash
	case *LeafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if equalPaths(child.stem, key) {
			if err := child.Insert(key, value, resolver); err != nil {
				return err
			}
		} else {
			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := offset2key(child.stem, n.depth+NodeBitWidth)
			newBranch := newInternalNode(n.depth+NodeBitWidth, n.committer).(*InternalNodeStateless)
			newBranch.count = 1
			n.children[nChild] = newBranch
			newBranch.children[nextWordInExistingKey] = child

			nextWordInInsertedKey := offset2key(key, n.depth+NodeBitWidth)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				lastNode := &LeafNode{
					stem:      key[:31],
					values:    make([][]byte, NodeWidth),
					committer: n.committer,
				}
				lastNode.values[key[31]] = value
				newBranch.children[nextWordInInsertedKey] = lastNode
				newBranch.count++
			} else if err := newBranch.Insert(key, value, resolver); err != nil {
				return err
			}
		}
	default: // InternalNode
		return child.Insert(key, value, resolver)
	}
	return nil
}

func (n *InternalNodeStateless) toHashedNode() *HashedNode {
	return &HashedNode{n.hash, n.commitment}
}

func (n *InternalNodeStateless) InsertOrdered(key []byte, value []byte, flush NodeFlushFn) error {
	// Clear cached commitment on modification
	//if n.commitment != nil {
	//n.commitment = nil
	//n.hash = nil
	//}

	//nChild := offset2key(key, n.depth)

	//switch child := n.children[nChild].(type) {
	//case Empty:
	// Insert into a new subtrie, which means that the
	// subtree directly preceding this new one, can
	// safely be calculated.
	//searchFirstNonEmptyChild:
	//for i := int(nChild) - 1; i >= 0; i-- {
	//switch child := n.children[i].(type) {
	//case Empty:
	//continue
	//case *LeafNode:
	//child.ComputeCommitment()
	//if flush != nil {
	//flush(child)
	//}
	//n.children[i] = child.toHashedNode()
	//break searchFirstNonEmptyChild
	//case *HashedNode:
	//break searchFirstNonEmptyChild
	//case *InternalNode:
	//n.children[i].ComputeCommitment()
	//if flush != nil {
	//child.Flush(flush)
	//}
	//n.children[i] = child.toHashedNode()
	//break searchFirstNonEmptyChild
	//}
	//}

	// NOTE: these allocations are inducing a noticeable slowdown
	//lastNode := &LeafNode{
	//stem:      key[:31],
	//values:    make([][]byte, NodeWidth),
	//committer: n.committer,
	//}
	//lastNode.values[key[31]] = value
	//n.children[nChild] = lastNode
	//n.count++

	// If the node was already created, then there was at least one
	// child. As a result, inserting this new leaf means there are
	// now more than one child in this node.
	//case *HashedNode:
	//return errInsertIntoHash
	//case *LeafNode:
	// Need to add a new branch node to differentiate
	// between two keys, if the keys are different.
	// Otherwise, just update the key.
	//if equalPaths(child.stem, key) {
	//child.values[key[31]] = value
	//} else {
	// A new branch node has to be inserted. Depending
	// on the next word in both keys, a recursion into
	// the moved leaf node can occur.
	//nextWordInExistingKey := offset2key(child.stem, n.depth+NodeBitWidth)
	//newBranch := newInternalNode(n.depth+NodeBitWidth, n.committer).(*InternalNodeStateless)
	//newBranch.count = 1
	//n.children[nChild] = newBranch

	//nextWordInInsertedKey := offset2key(key, n.depth+NodeBitWidth)
	//if nextWordInInsertedKey != nextWordInExistingKey {
	// Directly hash the (left) node that was already
	// inserted.
	//child.ComputeCommitment()
	//if flush != nil {
	//flush(child)
	//}
	//newBranch.children[nextWordInExistingKey] = child.toHashedNode()
	// Next word differs, so this was the last level.
	// Insert it directly into its final slot.
	//lastNode := &LeafNode{
	//stem:      key[:31],
	//values:    make([][]byte, NodeWidth),
	//committer: n.committer,
	//}
	//lastNode.values[key[31]] = value
	//newBranch.children[nextWordInInsertedKey] = lastNode
	//newBranch.count++
	//} else {
	// Reinsert the leaf in order to recurse
	//newBranch.children[nextWordInExistingKey] = child
	//if err := newBranch.InsertOrdered(key, value, flush); err != nil {
	//return err
	//}
	//}
	//}
	//default: // InternalNode
	//return child.InsertOrdered(key, value, flush)
	//}
	//return nil
	return errors.New("not implemented yet")
}

func (n *InternalNodeStateless) Delete(key []byte) error {
	// Clear cached commitment on modification
	n.commitment = nil
	n.hash = nil

	nChild := offset2key(key, n.depth)
	switch child := n.children[nChild].(type) {
	case Empty:
		return errDeleteNonExistent
	case *HashedNode:
		return errDeleteHash
	default:
		return child.Delete(key)
	}
}

// Flush hashes the children of an internal node and replaces them
// with HashedNode. It also sends the current node on the flush channel.
func (n *InternalNodeStateless) Flush(flush NodeFlushFn) {
	for i, child := range n.children {
		if c, ok := child.(*InternalNodeStateless); ok {
			if c.commitment == nil {
				c.ComputeCommitment()
			}
			c.Flush(flush)
			n.children[i] = c.toHashedNode()
		} else if c, ok := child.(*LeafNode); ok {
			if c.commitment == nil {
				c.ComputeCommitment()
			}
			flush(n.children[i])
			n.children[i] = c.toHashedNode()
		}
	}
	flush(n)
}

func (n *InternalNodeStateless) Get(k []byte, getter NodeResolverFn) ([]byte, error) {
	nChild := offset2key(k, n.depth)

	switch child := n.children[nChild].(type) {
	case Empty, nil:
		// Return nil as a signal that the value isn't
		// present in the tree. This matches the behavior
		// of SecureTrie in Geth.
		return nil, nil
	case *HashedNode:
		// if a resolution function is set, resolve the
		// current hash node.
		if getter == nil {
			return nil, errReadFromInvalid
		}

		commitment := child.hash.Bytes()
		payload, err := getter(commitment[:])
		if err != nil {
			return nil, err
		}

		// deserialize the payload and set it as the child
		c, err := ParseNode(payload, n.depth+NodeWidth)
		if err != nil {
			return nil, err
		}
		c.ComputeCommitment()
		n.children[nChild] = c

		return c.Get(k, getter)
	default: // InternalNode
		return child.Get(k, getter)
	}
}

func (n *InternalNodeStateless) ComputeCommitment() *Fr {
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

	emptyChildren := 0
	poly := make([]Fr, NodeWidth)
	for idx, child := range n.children {
		switch child.(type) {
		case Empty:
			emptyChildren++
		default:
			CopyFr(&poly[idx], child.ComputeCommitment())
		}
	}

	// All the coefficients have been computed, evaluate the polynomial,
	// serialize and hash the resulting point - this is the commitment.
	n.commitment = n.committer.CommitToPoly(poly, emptyChildren)
	toFr(n.hash, n.commitment)

	return n.hash
}

func (n *InternalNodeStateless) GetCommitmentsAlongPath(key []byte) *ProofElements {
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
	if _, ok := n.children[childIdx].(Empty); ok {
		return pe
	}

	pec := n.children[childIdx].GetCommitmentsAlongPath(key)
	pe.Merge(pec)
	return pe
}

func (n *InternalNodeStateless) Serialize() ([]byte, error) {
	var bitlist [32]uint8
	children := make([]byte, 0, NodeWidth*32)
	for i, c := range n.children {
		if _, ok := c.(Empty); !ok {
			setBit(bitlist[:], int(i))
			digits := c.ComputeCommitment().Bytes()
			children = append(children, digits[:]...)
		}
	}
	return append(append([]byte{internalRLPType}, bitlist[:]...), children...), nil
}

func (n *InternalNodeStateless) Copy() VerkleNode {
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

// clearCache sets the commitment field of node
// and all of its children (recursively) to nil.
func (n *InternalNodeStateless) clearCache() {
	for _, c := range n.children {
		in, ok := c.(*InternalNodeStateless)
		if !ok {
			continue
		}
		in.clearCache()
	}
	n.commitment = nil
}

func (n *InternalNodeStateless) toDot(parent, path string) string {
	n.ComputeCommitment()
	me := fmt.Sprintf("internal%s", path)
	ret := fmt.Sprintf("%s [label=\"I: %x\"]\n", me, n.hash.Bytes())
	if len(parent) > 0 {
		ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
	}

	for i, child := range n.children {
		ret = fmt.Sprintf("%s%s", ret, child.toDot(me, fmt.Sprintf("%s%02x", path, i)))
	}

	return ret
}
