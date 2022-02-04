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

type NodeFlushFn func(VerkleNode)
type NodeResolverFn func([]byte) ([]byte, error)

// Committer represents an object that is able to create the
// commitment to a polynomial.
type Committer interface {
	CommitToPoly([]Fr, int) *Point
}

type VerkleNode interface {
	// Insert or Update value into the tree
	Insert([]byte, []byte, NodeResolverFn) error

	// Insert "à la" Stacktrie. Same thing as insert, except that
	// values are expected to be ordered, and the commitments and
	// hashes for each subtrie are computed online, as soon as it
	// is clear that no more values will be inserted in there.
	InsertOrdered([]byte, []byte, NodeFlushFn) error

	// Delete a leaf with the given key
	Delete([]byte) error

	// Get value at a given key
	Get([]byte, NodeResolverFn) ([]byte, error)

	// ComputeCommitment computes the commitment of the node
	// The results (the curve point and the field element
	// representation of its hash) are cached.
	ComputeCommitment() *Fr

	// GetCommitmentsAlongPath follows the path that one key
	// traces through the tree, and collects the various
	// elements needed to build a proof. The order of elements
	// is from the bottom of the tree, up to the root. It also
	// returns the extension status.
	GetCommitmentsAlongPath([]byte) (*ProofElements, byte, []byte)

	// Serialize encodes the node to RLP.
	Serialize() ([]byte, error)

	// Copy a node and its children
	Copy() VerkleNode

	// toDot returns a string representing this subtree in DOT language
	toDot(string, string) string
}

// ProofElements gathers the elements needed to build a proof.
type ProofElements struct {
	Cis    []*Point
	Zis    []byte
	Yis    []*Fr
	Fis    [][]Fr
	ByPath map[string]*Point // Gather commitments by path

	// dedups flags the presence of each (Ci,zi) tuple
	dedups map[*Point]map[byte]struct{}
}

// Merge merges the elements of two proofs and removes duplicates.
func (pe *ProofElements) Merge(other *ProofElements) {
	// Build the local map if it's missing
	if pe.dedups == nil {
		pe.dedups = make(map[*Point]map[byte]struct{})

		for i, ci := range pe.Cis {
			if _, ok := pe.dedups[ci]; !ok {
				pe.dedups[ci] = make(map[byte]struct{})
			}

			pe.dedups[ci][pe.Zis[i]] = struct{}{}
		}
	}

	for i, ci := range other.Cis {
		if _, ok := pe.dedups[ci]; !ok {
			// First time this commitment has been seen, create
			// the map and flatten the zi.
			pe.dedups[ci] = make(map[byte]struct{})
		}

		if _, ok := pe.dedups[ci][other.Zis[i]]; ok {
			// duplicate, skip
			continue
		}

		pe.dedups[ci][other.Zis[i]] = struct{}{}

		pe.Cis = append(pe.Cis, ci)
		pe.Zis = append(pe.Zis, other.Zis[i])
		pe.Yis = append(pe.Yis, other.Yis[i])
		pe.Fis = append(pe.Fis, other.Fis[i])
	}

	for path, C := range other.ByPath {
		if _, ok := pe.ByPath[path]; !ok {
			pe.ByPath[path] = C
		}
	}
}

const (
	// These types will distinguish internal
	// and leaf nodes when decoding from RLP.
	internalRLPType byte = 1
	leafRLPType     byte = 2
)

type (
	// Represents an internal node at any level
	InternalNode struct {
		// List of child nodes of this internal node.
		children []VerkleNode

		// node depth in the tree, in bits
		depth byte

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

	LeafNode struct {
		stem   []byte
		values [][]byte

		commitment *Point
		c1, c2     *Point
		hash       *Fr
		committer  Committer

		depth byte
	}
)

func newInternalNode(depth byte, cmtr Committer) VerkleNode {
	node := new(InternalNode)
	node.children = make([]VerkleNode, NodeWidth)
	for idx := range node.children {
		node.children[idx] = Empty(struct{}{})
	}
	node.depth = depth
	node.committer = cmtr
	node.count = 0
	return node
}

// New creates a new tree root
func New() VerkleNode {
	return newInternalNode(0, GetConfig())
}

func (n *InternalNode) Children() []VerkleNode {
	return n.children
}

func (n *InternalNode) SetChild(i int, c VerkleNode) error {
	if i >= NodeWidth-1 {
		return errors.New("child index higher than node width")
	}
	n.children[i] = c
	return nil
}

func (n *InternalNode) Insert(key []byte, value []byte, resolver NodeResolverFn) error {
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
			depth:     n.depth + 1,
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
			resolved, err := ParseNode(serialized, n.depth+1)
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
			nextWordInExistingKey := offset2key(child.stem, n.depth+1)
			newBranch := newInternalNode(n.depth+1, n.committer).(*InternalNode)
			newBranch.count = 1
			n.count++
			n.children[nChild] = newBranch
			newBranch.children[nextWordInExistingKey] = child
			child.depth += 1

			nextWordInInsertedKey := offset2key(key, n.depth+1)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				lastNode := &LeafNode{
					stem:      key[:31],
					values:    make([][]byte, NodeWidth),
					committer: n.committer,
					depth:     n.depth + 2,
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

func (n *InternalNode) toHashedNode() *HashedNode {
	return &HashedNode{n.hash, n.commitment}
}

func (n *InternalNode) InsertOrdered(key []byte, value []byte, flush NodeFlushFn) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
		n.hash = nil
	}

	nChild := offset2key(key, n.depth)

	switch child := n.children[nChild].(type) {
	case Empty:
		// Insert into a new subtrie, which means that the
		// subtree directly preceding this new one, can
		// safely be calculated.
	searchFirstNonEmptyChild:
		for i := int(nChild) - 1; i >= 0; i-- {
			switch child := n.children[i].(type) {
			case Empty:
				continue
			case *LeafNode:
				child.ComputeCommitment()
				if flush != nil {
					flush(child)
				}
				n.children[i] = child.toHashedNode()
				break searchFirstNonEmptyChild
			case *HashedNode:
				break searchFirstNonEmptyChild
			case *InternalNode:
				n.children[i].ComputeCommitment()
				if flush != nil {
					child.Flush(flush)
				}
				n.children[i] = child.toHashedNode()
				break searchFirstNonEmptyChild
			}
		}

		// NOTE: these allocations are inducing a noticeable slowdown
		lastNode := &LeafNode{
			stem:      key[:31],
			values:    make([][]byte, NodeWidth),
			committer: n.committer,
			depth:     n.depth + 1,
		}
		lastNode.values[key[31]] = value
		n.children[nChild] = lastNode
		n.count++

		// If the node was already created, then there was at least one
		// child. As a result, inserting this new leaf means there are
		// now more than one child in this node.
	case *HashedNode:
		return errInsertIntoHash
	case *LeafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if equalPaths(child.stem, key) {
			child.values[key[31]] = value
		} else {
			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := offset2key(child.stem, n.depth+1)
			newBranch := newInternalNode(n.depth+1, n.committer).(*InternalNode)
			newBranch.count = 1
			n.children[nChild] = newBranch

			nextWordInInsertedKey := offset2key(key, n.depth+1)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Directly hash the (left) node that was already
				// inserted.
				child.ComputeCommitment()
				if flush != nil {
					flush(child)
				}
				newBranch.children[nextWordInExistingKey] = child.toHashedNode()
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				lastNode := &LeafNode{
					stem:      key[:31],
					values:    make([][]byte, NodeWidth),
					committer: n.committer,
					depth:     n.depth + 1,
				}
				lastNode.values[key[31]] = value
				newBranch.children[nextWordInInsertedKey] = lastNode
				newBranch.count++
			} else {
				// Reinsert the leaf in order to recurse
				newBranch.children[nextWordInExistingKey] = child
				if err := newBranch.InsertOrdered(key, value, flush); err != nil {
					return err
				}
			}
		}
	default: // InternalNode
		return child.InsertOrdered(key, value, flush)
	}
	return nil
}

func (n *InternalNode) Delete(key []byte) error {
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
func (n *InternalNode) Flush(flush NodeFlushFn) {
	for i, child := range n.children {
		if c, ok := child.(*InternalNode); ok {
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

func (n *InternalNode) Get(k []byte, getter NodeResolverFn) ([]byte, error) {
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
		c, err := ParseNode(payload, n.depth+1)
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

func (n *InternalNode) ComputeCommitment() *Fr {
	if n.hash != nil {
		return n.hash
	}

	// Special cases of a node with no children: either it's
	// an empty root, or it's an invalid node.
	if n.count == 0 {
		if n.depth != 0 {
			panic("internal node should be empty node")
		}

		// case of an empty root
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

func (n *InternalNode) GetCommitmentsAlongPath(key []byte) (*ProofElements, byte, []byte) {
	childIdx := offset2key(key, n.depth)

	// Build the list of elements for this level
	var yi Fr
	fi := make([]Fr, NodeWidth)
	for i, child := range n.children {
		CopyFr(&fi[i], child.ComputeCommitment())

		if i == int(childIdx) {
			CopyFr(&yi, &fi[i])
		}
	}

	// The proof elements that are to be added at this level
	pe := &ProofElements{
		Cis:    []*Point{n.commitment},
		Zis:    []byte{childIdx},
		Yis:    []*Fr{&yi}, // Should be 0
		Fis:    [][]Fr{fi},
		ByPath: map[string]*Point{string(key[:n.depth]): n.commitment},
	}

	// Special case of a proof of absence: no children
	// commitment, as the value is 0.
	if _, ok := n.children[childIdx].(Empty); ok {
		return pe, extStatusAbsentEmpty | (n.depth << 3), nil
	}

	pec, es, other := n.children[childIdx].GetCommitmentsAlongPath(key)
	pe.Merge(pec)
	return pe, es, other
}

func (n *InternalNode) Serialize() ([]byte, error) {
	var bitlist [32]byte
	children := make([]byte, 0, NodeWidth*32)
	for i, c := range n.children {
		if _, ok := c.(Empty); !ok {
			setBit(bitlist[:], i)
			digits := c.ComputeCommitment().Bytes()
			children = append(children, digits[:]...)
		}
	}
	return append(append([]byte{internalRLPType}, bitlist[:]...), children...), nil
}

func (n *InternalNode) Copy() VerkleNode {
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
func (n *InternalNode) clearCache() {
	for _, c := range n.children {
		in, ok := c.(*InternalNode)
		if !ok {
			continue
		}
		in.clearCache()
	}
	n.commitment = nil
}

func (n *InternalNode) toDot(parent, path string) string {
	n.ComputeCommitment()
	me := fmt.Sprintf("internal%s", path)
	ret := fmt.Sprintf("%s [label=\"I: %x\"]\n", me, n.hash.BytesLE())
	if len(parent) > 0 {
		ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
	}

	for i, child := range n.children {
		ret = fmt.Sprintf("%s%s", ret, child.toDot(me, fmt.Sprintf("%s%02x", path, i)))
	}

	return ret
}

func (n *LeafNode) toHashedNode() *HashedNode {
	return &HashedNode{n.hash, n.commitment}
}

func (n *LeafNode) Insert(k []byte, value []byte, _ NodeResolverFn) error {
	// Sanity check: ensure the key header is the same:
	if !equalPaths(k, n.stem) {
		return errors.New("split should not happen here")
	}
	n.values[k[31]] = value
	n.commitment = nil
	n.hash = nil
	return nil
}

func (n *LeafNode) InsertOrdered(key []byte, value []byte, _ NodeFlushFn) error {
	// In the previous version, this value used to be flushed on insert.
	// This is no longer the case, as all values at the last level get
	// flushed at the same time.
	return n.Insert(key, value, nil)
}

func (n *LeafNode) Delete(k []byte) error {
	// Sanity check: ensure the key header is the same:
	if !equalPaths(k, n.stem) {
		return errDeleteNonExistent
	}

	var zero [32]byte
	n.commitment = nil
	n.hash = nil
	n.values[k[31]] = zero[:]
	return nil
}

func (n *LeafNode) Get(k []byte, _ NodeResolverFn) ([]byte, error) {
	if !equalPaths(k, n.stem) {
		// If keys differ, return nil in order to
		// signal that the key isn't present in the
		// tree. Do not return an error, thus matching
		// the behavior of Geth's SecureTrie.
		return nil, nil
	}
	// value can be nil, as expected by geth
	return n.values[k[31]], nil
}

func (n *LeafNode) ComputeCommitment() *Fr {
	if n.hash != nil {
		return n.hash
	}
	n.hash = new(Fr)

	count := 0
	var poly, c1poly, c2poly [256]Fr
	poly[0].SetUint64(1)
	StemFromBytes(&poly[1], n.stem)

	count = fillSuffixTreePoly(c1poly[:], n.values[:128])
	n.c1 = n.committer.CommitToPoly(c1poly[:], 256-count)
	toFr(&poly[2], n.c1)
	count = fillSuffixTreePoly(c2poly[:], n.values[128:])
	n.c2 = n.committer.CommitToPoly(c2poly[:], 256-count)
	toFr(&poly[3], n.c2)

	n.commitment = n.committer.CommitToPoly(poly[:], 252)
	toFr(n.hash, n.commitment)

	return n.hash
}

// fillSuffixTreePoly takes one of the two suffix tree and
// builds the associated polynomial, to be used to compute
// the corresponding C{1,2} commitment.
func fillSuffixTreePoly(poly []Fr, values [][]byte) int {
	count := 0
	for idx, val := range values {
		if val == nil {
			continue
		}
		count++

		leafToComms(poly[(idx<<1)&0xFF:], val)
	}
	return count
}

// leafToComms turns a leaf into two commitments of the suffix
// and extension tree.
func leafToComms(poly []Fr, val []byte) {
	if len(val) > 32 {
		panic(fmt.Sprintf("invalid leaf length %d, %v", len(val), val))
	}
	var (
		valLoWithMarker [17]byte
		loEnd           = 16
	)
	if len(val) < loEnd {
		loEnd = len(val)
	}
	copy(valLoWithMarker[:loEnd], val[:loEnd])
	valLoWithMarker[16] = 1 // 2**128
	FromLEBytes(&poly[0], valLoWithMarker[:])
	if len(val) >= 16 {
		FromLEBytes(&poly[1], val[16:])
	}
}

func (n *LeafNode) GetCommitmentsAlongPath(key []byte) (*ProofElements, byte, []byte) {
	// Proof of absence: case of a differing stem.
	//
	// Return an unopened stem-level node.
	if !equalPaths(n.stem, key) {
		var poly [256]Fr
		poly[0].SetUint64(1)
		StemFromBytes(&poly[1], n.stem)
		toFr(&poly[2], n.c1)
		toFr(&poly[3], n.c2)
		return &ProofElements{
			Cis:    []*Point{n.commitment, n.commitment},
			Zis:    []byte{0, 1},
			Yis:    []*Fr{&poly[0], &poly[1]},
			Fis:    [][]Fr{poly[:], poly[:]},
			ByPath: map[string]*Point{string(key[:n.depth]): n.commitment},
		}, extStatusAbsentOther | (n.depth << 3), n.stem
	}

	var (
		slot     = key[31]
		suffSlot = 2 + slot/128
		poly     [256]Fr
		count    int
	)

	if slot >= 128 {
		count = fillSuffixTreePoly(poly[:], n.values[128:])
	} else {
		count = fillSuffixTreePoly(poly[:], n.values[:128])
	}

	var extPoly [256]Fr
	extPoly[0].SetUint64(1)
	StemFromBytes(&extPoly[1], n.stem)
	toFr(&extPoly[2], n.c1)
	toFr(&extPoly[3], n.c2)

	// Proof of absence: case of a missing suffix tree.
	//
	// The suffix tree for this value is missing, i.e. all
	// values in the extension-and-suffix tree are grouped
	// in the other suffix tree (e.g. C2 if we are looking
	// at C1).
	if count == 0 {
		// TODO(gballet) maintain a count variable at LeafNode level
		// so that we know not to build the polynomials in this case,
		// as all the information is available before fillSuffixTreePoly
		// has to be called, save the count.
		return &ProofElements{
			// leaf marker, stem, path to child (which is 0)
			Cis:    []*Point{n.commitment, n.commitment, n.commitment},
			Zis:    []byte{0, 1, suffSlot},
			Yis:    []*Fr{&extPoly[0], &extPoly[1], &FrZero},
			Fis:    [][]Fr{extPoly[:], extPoly[:], extPoly[:]},
			ByPath: map[string]*Point{string(key[:n.depth]): n.commitment},
		}, extStatusAbsentEmpty | (n.depth << 3), nil
	}

	var scomm *Point
	if slot < 128 {
		scomm = n.c1
	} else {
		scomm = n.c2
	}

	slotPath := string(key[:n.depth]) + string([]byte{suffSlot})

	// Proof of absence: case of a missing value.
	//
	// Suffix tree is present as a child of the extension,
	// but does not contain the requested suffix. This can
	// only happen when the leaf has never been written to
	// since after deletion the value would be set to zero
	// but still contain the leaf marker 2^128.
	if n.values[slot] == nil {
		return &ProofElements{
				// leaf marker, stem, path to child, missing value (zero)
				Cis:    []*Point{n.commitment, n.commitment, n.commitment, scomm},
				Zis:    []byte{0, 1, suffSlot, slot},
				Yis:    []*Fr{&extPoly[0], &extPoly[1], &extPoly[suffSlot], &FrZero},
				Fis:    [][]Fr{extPoly[:], extPoly[:], extPoly[:], poly[:]},
				ByPath: map[string]*Point{string(key[:n.depth]): n.commitment, slotPath: scomm},
			}, extStatusPresent | (n.depth << 3), // present, since the stem is present
			nil
	}

	// suffix tree is present and contains the key
	var leaves [2]Fr
	leafToComms(leaves[:], n.values[slot])
	return &ProofElements{
		// leaf marker, stem, path to child, C{1,2} lo, C{1,2} hi
		Cis:    []*Point{n.commitment, n.commitment, n.commitment, scomm, scomm},
		Zis:    []byte{0, 1, suffSlot, 2 * slot, 2*slot + 1},
		Yis:    []*Fr{&extPoly[0], &extPoly[1], &extPoly[suffSlot], &leaves[0], &leaves[1]},
		Fis:    [][]Fr{extPoly[:], extPoly[:], extPoly[:], poly[:], poly[:]},
		ByPath: map[string]*Point{string(key[:n.depth]): n.commitment, slotPath: scomm},
	}, extStatusPresent | (n.depth << 3), nil
}

func (n *LeafNode) Serialize() ([]byte, error) {
	var bitlist [32]byte
	children := make([]byte, 0, NodeWidth*32)
	for i, v := range n.values {
		if v != nil {
			setBit(bitlist[:], i)
			children = append(children, v...)
			if len(v) < 32 {
				padding := make([]byte, 32-len(v))
				children = append(children, padding...)
			}
		}
	}
	return append(append(append([]byte{leafRLPType}, n.stem...), bitlist[:]...), children...), nil
}

func (n *LeafNode) Copy() VerkleNode {
	l := &LeafNode{}
	l.stem = make([]byte, len(n.stem))
	l.values = make([][]byte, len(n.values))
	l.committer = n.committer
	l.depth = n.depth
	copy(l.stem, n.stem)
	for i, v := range n.values {
		l.values[i] = make([]byte, len(v))
		copy(l.values[i], v)
	}
	if n.commitment != nil {
		l.commitment = n.commitment
	}
	if l.hash != nil {
		CopyFr(l.hash, n.hash)
	}

	return l
}

func (n *LeafNode) Key(i int) []byte {
	var ret [32]byte
	copy(ret[:], n.stem)
	ret[31] = byte(i)
	return ret[:]
}

func (n *LeafNode) Value(i int) []byte {
	return n.values[i]
}

func (n *LeafNode) toDot(parent, path string) string {
	ret := fmt.Sprintf("leaf%s [label=\"L: %x\nC: %x\nC₁: %x\nC₂:%x\"]\n%s -> leaf%s\n", path, n.hash.Bytes(), n.commitment.Bytes(), n.c1.Bytes(), n.c2.Bytes(), parent, path)
	for i, v := range n.values {
		if v != nil {
			ret = fmt.Sprintf("%sval%s%x [label=\"%x\"]\nleaf%s -> val%s%x\n", ret, path, i, v, path, path, i)
		}
	}
	return ret
}

func setBit(bitlist []byte, index int) {
	bitlist[index/8] |= mask[index%8]
}

func ToDot(root VerkleNode) string {
	return fmt.Sprintf("digraph D {\n%s}", root.toDot("", ""))
}
