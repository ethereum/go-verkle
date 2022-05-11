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

type keylist [][]byte

func (kl keylist) Len() int {
	return len(kl)
}

func (kl keylist) Less(i, j int) bool {
	return bytes.Compare(kl[i], kl[j]) == -1
}

func (kl keylist) Swap(i, j int) {
	kl[i], kl[j] = kl[j], kl[i]
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
	ComputeCommitment() *Point

	// GetProofItems collects the various proof elements, and
	// returns them breadth-first. On top of that, it returns
	// one "extension status" per stem, and an alternate stem
	// if the key is missing but another stem has been found.
	GetProofItems(keylist) (*ProofElements, []byte, [][]byte)

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

		// Cache the commitment value
		commitment *Point

		committer Committer
	}

	LeafNode struct {
		stem   []byte
		values [][]byte

		commitment *Point
		c1, c2     *Point
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
	cfg, _ := GetConfig()
	return newInternalNode(0, cfg)
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
		if resolver == nil {
			return errInsertIntoHash
		}
		hash := child.ComputeCommitment().Bytes()
		serialized, err := resolver(hash[:])
		if err != nil {
			return fmt.Errorf("verkle tree: error resolving node %x: %w", key, err)
		}
		resolved, err := ParseNode(serialized, n.depth+1, hash[:])
		if err != nil {
			return fmt.Errorf("verkle tree: error parsing resolved node %x: %w", key, err)
		}
		n.children[nChild] = resolved
		// the child has been resolved as a LeafNode, so when recursing, the following case will be executed
		return n.Insert(key, value, resolver)
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
	var hash Fr
	toFr(&hash, n.commitment)
	return &HashedNode{&hash, n.commitment}
}

func (n *InternalNode) InsertOrdered(key []byte, value []byte, flush NodeFlushFn) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
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

// FlushStem recurses through the tree until it finds a leaf node,
// and flushes this leaf node to disk. The internal nodes are left
// untouched.
func (n *InternalNode) FlushStem(stem []byte, flush NodeFlushFn) {
	nChild := offset2key(stem, n.depth)
	child := n.children[nChild]
	switch child := child.(type) {
	case *InternalNode:
		if n.depth == 2 {
			child.ComputeCommitment()
			child.Flush(flush)
			n.children[nChild] = child.toHashedNode()
			return
		}

		child.FlushStem(stem, flush)
	case *LeafNode:
		if child.commitment == nil {
			child.ComputeCommitment()
		}
		flush(child)
		n.children[nChild] = child.toHashedNode()

	default:
		// reaching here is probably an error, skip for now
	}
}

// FlushAtDepth goes over all internal nodes of a given depth, and
// flushes them to disk. It's meant to free up some memory when it
// is running scarce.
func (n *InternalNode) FlushAtDepth(depth uint8, flush NodeFlushFn) {
	if n.depth+1 == depth {
		for i, child := range n.children {
			switch c := child.(type) {
			case *LeafNode:
				child.ComputeCommitment()
				flush(child)
				n.children[i] = c.toHashedNode()
			case *InternalNode:
				child.ComputeCommitment()
				flush(child)
				n.children[i] = c.toHashedNode()
			default:
				// skip
			}
		}
	}
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

		commitment := child.commitment.Bytes()
		payload, err := getter(commitment[:])
		if err != nil {
			return nil, err
		}

		// deserialize the payload and set it as the child
		c, err := ParseNode(payload, n.depth+1, commitment[:])
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

func (n *InternalNode) ComputeCommitment() *Point {
	if n.commitment != nil {
		return n.commitment
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
		return n.commitment
	}

	emptyChildren := 0
	poly := make([]Fr, NodeWidth)
	for idx, child := range n.children {
		switch child.(type) {
		case Empty:
			emptyChildren++
		default:
			toFr(&poly[idx], child.ComputeCommitment())
		}
	}

	// All the coefficients have been computed, evaluate the polynomial,
	// serialize and hash the resulting point - this is the commitment.
	n.commitment = n.committer.CommitToPoly(poly, emptyChildren)
	return n.commitment
}

// groupKeys groups a set of keys based on their byte at a given depth.
func groupKeys(keys keylist, depth byte) []keylist {
	// special case: only one key left
	if len(keys) == 1 {
		return []keylist{keys}
	}

	// there are at least two keys left in the list at this depth
	groups := make([]keylist, 0, len(keys))
	firstkey, lastkey := 0, 1
	for ; lastkey < len(keys); lastkey++ {
		key := keys[lastkey]
		keyidx := offset2key(key, depth)
		previdx := offset2key(keys[lastkey-1], depth)

		if keyidx != previdx {
			groups = append(groups, keys[firstkey:lastkey])
			firstkey = lastkey
		}
	}

	groups = append(groups, keys[firstkey:lastkey])

	return groups
}

func (n *InternalNode) GetProofItems(keys keylist) (*ProofElements, []byte, [][]byte) {
	var (
		groups = groupKeys(keys, n.depth)
		pe     = &ProofElements{
			Cis:    []*Point{},
			Zis:    []byte{},
			Yis:    []*Fr{}, // Should be 0
			Fis:    [][]Fr{},
			ByPath: map[string]*Point{},
		}

		esses []byte   = nil // list of extension statuses
		poass [][]byte       // list of proof-of-absence stems
	)

	// fill in the polynomial for this node
	fi := make([]Fr, NodeWidth)
	for i, child := range n.children {
		toFr(&fi[i], child.ComputeCommitment())
	}

	for _, group := range groups {
		childIdx := offset2key(group[0], n.depth)

		// Build the list of elements for this level
		var yi Fr
		CopyFr(&yi, &fi[childIdx])
		pe.Cis = append(pe.Cis, n.commitment)
		pe.Zis = append(pe.Zis, childIdx)
		pe.Yis = append(pe.Yis, &yi)
		pe.Fis = append(pe.Fis, fi)
		pe.ByPath[string(group[0][:n.depth])] = n.commitment
	}

	// Loop over again, collecting the children's proof elements
	// This is because the order is breadth-first.
	for _, group := range groups {
		childIdx := offset2key(group[0], n.depth)

		// Special case of a proof of absence: no children
		// commitment, as the value is 0.
		if _, ok := n.children[childIdx].(Empty); ok {
			// A question arises here: what if this proof of absence
			// corresponds to several stems? Should the ext status be
			// repeated as many times? It would be wasteful, so the
			// decoding code has to be aware of this corner case.
			esses = append(esses, extStatusAbsentEmpty|((n.depth+1)<<3))
			continue
		}

		pec, es, other := n.children[childIdx].GetProofItems(group)
		pe.Merge(pec)
		poass = append(poass, other...)
		esses = append(esses, es...)
	}

	return pe, esses, poass
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
	var hash Fr
	toFr(&hash, n.commitment)
	ret := fmt.Sprintf("%s [label=\"I: %x\"]\n", me, hash.BytesLE())
	if len(parent) > 0 {
		ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
	}

	for i, child := range n.children {
		ret = fmt.Sprintf("%s%s", ret, child.toDot(me, fmt.Sprintf("%s%02x", path, i)))
	}

	return ret
}

func (n *LeafNode) toHashedNode() *HashedNode {
	var hash Fr
	toFr(&hash, n.commitment)
	return &HashedNode{&hash, n.commitment}
}

func (n *LeafNode) Insert(k []byte, value []byte, _ NodeResolverFn) error {
	// Sanity check: ensure the key header is the same:
	if !equalPaths(k, n.stem) {
		return errInsertIntoOtherStem
	}
	n.values[k[31]] = value
	n.commitment = nil
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

func (n *LeafNode) ComputeCommitment() *Point {
	if n.commitment != nil {
		return n.commitment
	}

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
	return n.commitment
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

func (n *LeafNode) GetProofItems(keys keylist) (*ProofElements, []byte, [][]byte) {
	var (
		poly [256]Fr // top-level polynomial
		pe           = &ProofElements{
			Cis:    []*Point{n.commitment, n.commitment},
			Zis:    []byte{0, 1},
			Yis:    []*Fr{&poly[0], &poly[1]}, // Should be 0
			Fis:    [][]Fr{poly[:], poly[:]},
			ByPath: map[string]*Point{},
		}

		esses []byte   = nil // list of extension statuses
		poass [][]byte       // list of proof-of-absence stems
	)

	// Initialize the top-level polynomial with 1 + stem + C1 + C2
	poly[0].SetUint64(1)
	StemFromBytes(&poly[1], n.stem)
	toFr(&poly[2], n.c1)
	toFr(&poly[3], n.c2)

	for _, key := range keys {
		pe.ByPath[string(key[:n.depth])] = n.commitment

		// Proof of absence: case of a differing stem.
		// Add an unopened stem-level node.
		if !equalPaths(n.stem, key) {
			// Corner case: don't add the poa stem if it's
			// already present as a proof-of-absence for a
			// different key, or for the same key (case of
			// multiple missing keys being absent).
			// The list of extension statuses has to be of
			// length 1 at this level, so skip otherwise.
			if len(esses) == 0 {
				esses = append(esses, extStatusAbsentOther|(n.depth<<3))
				poass = append(poass, n.stem)
			}
			continue
		}

		// corner case (see previous corner case): if a proof-of-absence
		// stem was found, and it now turns out the same stem is used as
		// a proof of presence, clear the proof-of-absence list to avoid
		// redundancy.
		if len(poass) > 0 {
			poass = nil
			esses = nil
		}

		var (
			suffix   = key[31]
			suffSlot = 2 + suffix/128 // slot in suffix tree
			suffPoly [256]Fr          // suffix-level polynomial
			count    int
		)

		if suffix >= 128 {
			count = fillSuffixTreePoly(suffPoly[:], n.values[128:])
		} else {
			count = fillSuffixTreePoly(suffPoly[:], n.values[:128])
		}

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
			pe.Cis = append(pe.Cis, n.commitment)
			pe.Zis = append(pe.Zis, suffSlot)
			pe.Yis = append(pe.Yis, &FrZero)
			pe.Fis = append(pe.Fis, poly[:])
			esses = append(esses, extStatusAbsentEmpty|(n.depth<<3))
			continue
		}

		var scomm *Point
		if suffix < 128 {
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
		if n.values[suffix] == nil {
			pe.Cis = append(pe.Cis, n.commitment, scomm, scomm)
			pe.Zis = append(pe.Zis, suffSlot, 2*suffix, 2*suffix+1)
			pe.Yis = append(pe.Yis, &poly[suffSlot], &FrZero, &FrZero)
			pe.Fis = append(pe.Fis, poly[:], suffPoly[:], suffPoly[:])
			if len(esses) == 0 || esses[len(esses)-1] != extStatusPresent|(n.depth<<3) {
				esses = append(esses, extStatusPresent|(n.depth<<3))
			}
			pe.ByPath[slotPath] = scomm
			continue
		}

		// suffix tree is present and contains the key
		var leaves [2]Fr
		leafToComms(leaves[:], n.values[suffix])
		pe.Cis = append(pe.Cis, n.commitment, scomm, scomm)
		pe.Zis = append(pe.Zis, suffSlot, 2*suffix, 2*suffix+1)
		pe.Yis = append(pe.Yis, &poly[suffSlot], &leaves[0], &leaves[1])
		pe.Fis = append(pe.Fis, poly[:], suffPoly[:], suffPoly[:])
		if len(esses) == 0 || esses[len(esses)-1] != extStatusPresent|(n.depth<<3) {
			esses = append(esses, extStatusPresent|(n.depth<<3))
		}
		pe.ByPath[slotPath] = scomm
	}

	return pe, esses, poass
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
	var hash Fr
	toFr(&hash, n.commitment)
	ret := fmt.Sprintf("leaf%s [label=\"L: %x\nC: %x\nC₁: %x\nC₂:%x\"]\n%s -> leaf%s\n", path, hash.Bytes(), n.commitment.Bytes(), n.c1.Bytes(), n.c2.Bytes(), parent, path)
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
