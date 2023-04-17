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

	"github.com/crate-crypto/go-ipa/banderwagon"
)

type (
	NodeFlushFn    func(VerkleNode)
	NodeResolverFn func([]byte) ([]byte, error)
)

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

	// Delete a leaf with the given key
	Delete([]byte, NodeResolverFn) error

	// Get value at a given key
	Get([]byte, NodeResolverFn) ([]byte, error)

	// Commit computes the commitment of the node. The
	// result (the curve point) is cached.
	Commit() *Point

	// Commitment is a getter for the cached commitment
	// to this node.
	Commitment() *Point

	// Hash returns the field representation of the commitment.
	Hash() *Fr

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

	setDepth(depth byte)
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
		if pe.Fis != nil {
			pe.Fis = append(pe.Fis, other.Fis[i])
		}
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

		// Cache the commitment value
		commitment *Point

		cow map[byte]*Point
	}

	LeafNode struct {
		stem   []byte
		values map[byte][]byte

		commitment *Point
		c1, c2     *Point

		depth byte
	}
)

func newInternalNode(depth byte) VerkleNode {
	node := new(InternalNode)
	node.children = make([]VerkleNode, NodeWidth)
	for idx := range node.children {
		node.children[idx] = Empty(struct{}{})
	}
	node.depth = depth
	node.commitment = new(Point).Identity()
	return node
}

// New creates a new tree root
func New() VerkleNode {
	return newInternalNode(0)
}

// New creates a new leaf node
func NewLeafNode(stem []byte, values [][]byte) *LeafNode {
	cfg := GetConfig()

	// C1.
	var c1poly [NodeWidth]Fr
	var c1 *Point
	count := fillSuffixTreePoly(c1poly[:], values[:NodeWidth/2])
	containsEmptyCodeHash := len(c1poly) >= EmptyCodeHashSecondHalfIdx &&
		c1poly[EmptyCodeHashFirstHalfIdx].Equal(&EmptyCodeHashFirstHalfValue) &&
		c1poly[EmptyCodeHashSecondHalfIdx].Equal(&EmptyCodeHashSecondHalfValue)
	if containsEmptyCodeHash {
		// Clear out values of the cached point.
		c1poly[EmptyCodeHashFirstHalfIdx] = FrZero
		c1poly[EmptyCodeHashSecondHalfIdx] = FrZero
		// Calculate the remaining part of c1 and add to the base value.
		partialc1 := cfg.CommitToPoly(c1poly[:], NodeWidth-count-2)
		c1 = new(Point)
		c1.Add(&EmptyCodeHashPoint, partialc1)
	} else {
		c1 = cfg.CommitToPoly(c1poly[:], NodeWidth-count)
	}

	// C2.
	var c2poly [NodeWidth]Fr
	count = fillSuffixTreePoly(c2poly[:], values[NodeWidth/2:])
	c2 := cfg.CommitToPoly(c2poly[:], NodeWidth-count)

	// Root commitment preparation for calculation.
	stem = stem[:StemSize] // enforce a 31-byte length
	var poly [NodeWidth]Fr
	poly[0].SetUint64(1)
	StemFromBytes(&poly[1], stem)
	toFrMultiple([]*Fr{&poly[2], &poly[3]}, []*Point{c1, c2})

	vals := make(map[byte][]byte, len(values))
	for i, v := range values {
		if v != nil {
			vals[byte(i)] = v
		}
	}
	return &LeafNode{
		// depth will be 0, but the commitment calculation
		// does not need it, and so it won't be free.
		values:     vals,
		stem:       stem,
		commitment: cfg.CommitToPoly(poly[:], NodeWidth-4),
		c1:         c1,
		c2:         c2,
	}
}

// NewLeafNodeWithNoComms create a leaf node but does compute its
// commitments. The created node's commitments are intended to be
// initialized with `SetTrustedBytes` in a deserialization context.
func NewLeafNodeWithNoComms(stem []byte, values [][]byte) *LeafNode {
	vals := make(map[byte][]byte, len(values))
	for i, v := range values {
		if v != nil {
			vals[byte(i)] = v
		}
	}
	return &LeafNode{
		// depth will be 0, but the commitment calculation
		// does not need it, and so it won't be free.
		values: vals,
		stem:   stem,
	}
}

func (n *InternalNode) Children() []VerkleNode {
	return n.children
}

func (n *InternalNode) SetChild(i int, c VerkleNode) error {
	if i >= NodeWidth {
		return errors.New("child index higher than node width")
	}
	n.children[i] = c
	return nil
}

// TouchCoW is a helper function that will mark a child as
// "inserted into". It is used by the conversion code to
// mark reconstructed subtrees as 'written to', so that its
// root commitment can be computed.
func (n *InternalNode) TouchCoW(index byte) {
	n.cowChild(index)
}

func (n *InternalNode) cowChild(index byte) {
	if n.cow == nil {
		n.cow = make(map[byte]*Point)
	}

	if n.cow[index] == nil {
		n.cow[index] = new(Point)
		CopyPoint(n.cow[index], n.children[index].Commitment())
	}
}

func (n *InternalNode) Insert(key []byte, value []byte, resolver NodeResolverFn) error {
	values := make([][]byte, NodeWidth)
	values[key[31]] = value
	return n.InsertStem(key[:31], values, resolver)
}

func (n *InternalNode) InsertStem(stem []byte, values [][]byte, resolver NodeResolverFn) error {
	nChild := offset2key(stem, n.depth) // index of the child pointed by the next byte in the key
	n.cowChild(nChild)

	switch child := n.children[nChild].(type) {
	case Empty:
		n.children[nChild] = NewLeafNode(stem, values)
		n.children[nChild].setDepth(n.depth + 1)
	case *HashedNode:
		if resolver == nil {
			return errInsertIntoHash
		}
		hash := child.commitment
		serialized, err := resolver(hash)
		if err != nil {
			return fmt.Errorf("verkle tree: error resolving node %x at depth %d: %w", stem, n.depth, err)
		}
		resolved, err := ParseNode(serialized, n.depth+1, hash)
		if err != nil {
			return fmt.Errorf("verkle tree: error parsing resolved node %x: %w", stem, err)
		}
		n.children[nChild] = resolved
		// recurse to handle the case of a LeafNode child that
		// splits.
		return n.InsertStem(stem, values, resolver)
	case *LeafNode:
		if equalPaths(child.stem, stem) {
			return child.insertMultiple(stem, values)
		}

		// A new branch node has to be inserted. Depending
		// on the next word in both keys, a recursion into
		// the moved leaf node can occur.
		nextWordInExistingKey := offset2key(child.stem, n.depth+1)
		newBranch := newInternalNode(n.depth + 1).(*InternalNode)
		newBranch.cowChild(nextWordInExistingKey)
		n.children[nChild] = newBranch
		newBranch.children[nextWordInExistingKey] = child
		child.depth += 1

		nextWordInInsertedKey := offset2key(stem, n.depth+1)
		if nextWordInInsertedKey == nextWordInExistingKey {
			return newBranch.InsertStem(stem, values, resolver)
		}

		// Next word differs, so this was the last level.
		// Insert it directly into its final slot.
		leaf := NewLeafNode(stem, values)
		leaf.setDepth(n.depth + 2)
		newBranch.cowChild(nextWordInInsertedKey)
		newBranch.children[nextWordInInsertedKey] = leaf
	case *InternalNode:
		return child.InsertStem(stem, values, resolver)
	default: // StatelessNode
		return errStatelessAndStatefulMix
	}

	return nil
}

func (n *InternalNode) GetStem(stem []byte, resolver NodeResolverFn) ([][]byte, error) {
	nchild := offset2key(stem, n.depth) // index of the child pointed by the next byte in the key
	switch child := n.children[nchild].(type) {
	case Empty:
		return nil, nil
	case *HashedNode:
		if resolver == nil {
			return nil, fmt.Errorf("hashed node %x at depth %d along stem %x could not be resolved", child.Commitment().Bytes(), n.depth, stem)
		}
		hash := child.commitment
		serialized, err := resolver(hash)
		if err != nil {
			return nil, fmt.Errorf("verkle tree: error resolving node %x at depth %d: %w", stem, n.depth, err)
		}
		resolved, err := ParseNode(serialized, n.depth+1, hash)
		if err != nil {
			return nil, fmt.Errorf("verkle tree: error parsing resolved node %x: %w", stem, err)
		}
		n.children[nchild] = resolved
		// recurse to handle the case of a LeafNode child that
		// splits.
		return n.GetStem(stem, resolver)
	case *LeafNode:
		if equalPaths(child.stem, stem) {
			values := make([][]byte, NodeWidth)
			for i, v := range child.values {
				values[i] = v
			}
			return values, nil
		}
		return nil, nil
	case *InternalNode:
		return child.GetStem(stem, resolver)
	default: // StatelessNode
		return nil, errStatelessAndStatefulMix
	}
}

func (n *InternalNode) toHashedNode() *HashedNode {
	if n.commitment == nil {
		panic("nil commitment")
	}
	comm := n.commitment.Bytes()
	return &HashedNode{commitment: comm[:]}
}

func (n *InternalNode) Delete(key []byte, resolver NodeResolverFn) error {
	nChild := offset2key(key, n.depth)
	switch child := n.children[nChild].(type) {
	case Empty:
		return errDeleteNonExistent
	case *HashedNode:
		if resolver == nil {
			return errDeleteHash
		}
		comm := child.commitment
		payload, err := resolver(comm)
		if err != nil {
			return err
		}
		// deserialize the payload and set it as the child
		c, err := ParseNode(payload, n.depth+1, comm)
		if err != nil {
			return err
		}
		n.children[nChild] = c
		return n.Delete(key, resolver)
	default:
		n.cowChild(nChild)
		return child.Delete(key, resolver)
	}
}

// Flush hashes the children of an internal node and replaces them
// with HashedNode. It also sends the current node on the flush channel.
func (n *InternalNode) Flush(flush NodeFlushFn) {
	n.Commit()
	for i, child := range n.children {
		if c, ok := child.(*InternalNode); ok {
			c.Commit()
			c.Flush(flush)
			n.children[i] = c.toHashedNode()
		} else if c, ok := child.(*LeafNode); ok {
			c.Commit()
			flush(n.children[i])
			n.children[i] = c.ToHashedNode()
		}
	}
	flush(n)
}

// FlushAtDepth goes over all internal nodes of a given depth, and
// flushes them to disk. Its purpose it to free up space if memory
// is running scarce.
func (n *InternalNode) FlushAtDepth(depth uint8, flush NodeFlushFn) {
	for i, child := range n.children {
		// Skip non-internal nodes
		c, ok := child.(*InternalNode)
		if !ok {
			if c, ok := child.(*LeafNode); ok {
				c.Commit()
				flush(c)
				n.children[i] = c.ToHashedNode()
			}
			continue
		}

		// Not deep enough, recurse
		if n.depth < depth {
			c.FlushAtDepth(depth, flush)
			continue
		}

		child.Commit()
		c.Flush(flush)
		n.children[i] = c.toHashedNode()
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

		payload, err := getter(child.commitment)
		if err != nil {
			return nil, err
		}

		// deserialize the payload and set it as the child
		c, err := ParseNode(payload, n.depth+1, child.commitment)
		if err != nil {
			return nil, err
		}
		n.children[nChild] = c

		return c.Get(k, getter)
	default: // InternalNode
		return child.Get(k, getter)
	}
}

func (n *InternalNode) Hash() *Fr {
	var hash Fr
	toFr(&hash, n.Commitment())
	return &hash
}

func (n *InternalNode) Commitment() *Point {
	if n.commitment == nil {
		panic("nil commitment")
	}
	return n.commitment
}

func (n *InternalNode) fillLevels(levels [][]*InternalNode) {
	levels[int(n.depth)] = append(levels[int(n.depth)], n)
	for idx := range n.cow {
		child := n.children[idx]
		if childInternalNode, ok := child.(*InternalNode); ok && len(childInternalNode.cow) > 0 {
			childInternalNode.fillLevels(levels)
		}
	}
}

func (n *InternalNode) Commit() *Point {
	if len(n.cow) == 0 {
		return n.commitment
	}

	internalNodeLevels := make([][]*InternalNode, StemSize)
	n.fillLevels(internalNodeLevels)

	points := make([]*Point, 0, 1024)
	cowIndexes := make([]int, 0, 1024)
	poly := make([]Fr, NodeWidth)
	for level := len(internalNodeLevels) - 1; level >= 0; level-- {
		nodes := internalNodeLevels[level]
		if len(nodes) == 0 {
			continue
		}
		points = points[:0]
		cowIndexes = cowIndexes[:0]

		// For each internal node, we collect in `points` all the ones we need to map to a field element.
		// That is, for each touched children in a node, we collect the old and new commitment to do the diff updating
		// later.
		for _, node := range nodes {
			for idx, nodeChildComm := range node.cow {
				points = append(points, nodeChildComm)
				points = append(points, node.children[idx].Commitment())
				cowIndexes = append(cowIndexes, int(idx))
			}
		}

		// We generate `frs` which will contain the result for each element in `points`.
		frs := make([]*Fr, len(points))
		for i := range frs {
			frs[i] = &Fr{}
		}

		// Do a single batch calculation for all the points in this level.
		toFrMultiple(frs, points)

		// We calculate the difference between each (new commitment - old commitment) pair, and store it
		// in the same slice to avoid allocations.
		for i := 0; i < len(frs); i += 2 {
			frs[i/2].Sub(frs[i+1], frs[i])
		}
		// Now `frs` have half of the elements, and these are the Frs differences to update commitments.
		frs = frs[:len(frs)/2]

		// Now we iterate on the nodes, and use this calculated differences to update their commitment.
		var frsIdx int
		var cowIndex int
		for _, node := range nodes {
			for i := range poly {
				poly[i].SetZero()
			}
			for i := 0; i < len(node.cow); i++ {
				poly[cowIndexes[cowIndex]] = *frs[frsIdx]
				frsIdx++
				cowIndex++
			}
			node.cow = nil
			node.commitment.Add(node.commitment, cfg.CommitToPoly(poly, 0))
		}
	}
	return n.commitment
}

// groupKeys groups a set of keys based on their byte at a given depth.
func groupKeys(keys keylist, depth byte) []keylist {
	// special case: no key
	if len(keys) == 0 {
		return []keylist{}
	}

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
	var fi [NodeWidth]Fr
	var fiPtrs [NodeWidth]*Fr
	var points [NodeWidth]*Point
	for i, child := range n.children {
		fiPtrs[i] = &fi[i]
		points[i] = child.Commitment()
	}
	toFrMultiple(fiPtrs[:], points[:])

	for _, group := range groups {
		childIdx := offset2key(group[0], n.depth)

		// Build the list of elements for this level
		var yi Fr
		CopyFr(&yi, &fi[childIdx])
		pe.Cis = append(pe.Cis, n.commitment)
		pe.Zis = append(pe.Zis, childIdx)
		pe.Yis = append(pe.Yis, &yi)
		pe.Fis = append(pe.Fis, fi[:])
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
	var (
		bitlist, hashlist [NodeWidth / 8]byte
		nhashed           int // number of children who are hashed nodes
	)
	commitments := make([]*Point, 0, NodeWidth)
	for i, c := range n.children {
		if _, ok := c.(Empty); !ok {
			setBit(bitlist[:], i)
			if _, ok := c.(*HashedNode); ok {
				// don't trigger the commitment on hashed nodes,
				// as they already hold a serialized version of
				// their commitment. Instead, just mark them as
				// hashes so they can be added directly.
				setBit(hashlist[:], i)
				nhashed++
			} else {
				commitments = append(commitments, c.Commitment())
			}
		}
	}

	ret := make([]byte, nodeTypeSize+bitlistSize+(len(commitments)+nhashed)*SerializedPointCompressedSize)

	// We create a children slice from ret ready to start appending children without allocations.
	children := ret[internalNodeChildrenOffset:internalNodeChildrenOffset]
	bytecomms := banderwagon.ElementsToBytes(commitments)
	consumed := 0
	for i := 0; i < NodeWidth; i++ {
		if bit(bitlist[:], i) {
			// if a child is present and is a hash, add its
			// internal, serialized representation directly.
			if bit(hashlist[:], i) {
				children = append(children, n.children[i].(*HashedNode).commitment...)
			} else {
				children = append(children, bytecomms[consumed][:]...)
				consumed++
			}
		}
	}

	// Store in ret the serialized result
	ret[nodeTypeOffset] = internalRLPType
	copy(ret[internalBitlistOffset:], bitlist[:])
	// Note that children were already appended in ret through the children slice.

	return ret, nil
}

func (n *InternalNode) Copy() VerkleNode {
	ret := &InternalNode{
		children:   make([]VerkleNode, len(n.children)),
		commitment: new(Point),
		depth:      n.depth,
	}

	for i, child := range n.children {
		ret.children[i] = child.Copy()
	}

	if n.commitment != nil {
		CopyPoint(ret.commitment, n.commitment)
	}

	if n.cow != nil {
		ret.cow = make(map[byte]*Point)
		for k, v := range n.cow {
			ret.cow[k] = new(Point)
			CopyPoint(ret.cow[k], v)
		}
	}

	return ret
}

func (n *InternalNode) toDot(parent, path string) string {
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

func (n *InternalNode) setDepth(d byte) {
	n.depth = d
}

// MergeTrees takes a series of subtrees that got filled following
// a command-and-conquer method, and merges them into a single tree.
func MergeTrees(subroots []*InternalNode) VerkleNode {
	root := New().(*InternalNode)
	for _, subroot := range subroots {
		for i := 0; i < NodeWidth; i++ {
			if _, ok := subroot.children[i].(Empty); ok {
				continue
			}
			root.TouchCoW(byte(i))
			root.children[i] = subroot.children[i]
		}
	}

	return root
}

func (n *LeafNode) ToHashedNode() *HashedNode {
	if n.commitment == nil {
		panic("nil commitment")
	}
	comm := n.commitment.Bytes()
	return &HashedNode{commitment: comm[:]}
}

func (n *LeafNode) Insert(k []byte, value []byte, _ NodeResolverFn) error {
	values := make([][]byte, NodeWidth)
	values[k[31]] = value
	return n.insertMultiple(k[:31], values)
}

func (n *LeafNode) insertMultiple(k []byte, values [][]byte) error {
	// Sanity check: ensure the key header is the same:
	if !equalPaths(k, n.stem) {
		return errInsertIntoOtherStem
	}

	n.updateMultipleLeaves(values)

	return nil
}

func (n *LeafNode) updateC(cxIndex int, newC Fr, oldC Fr) {
	// Calculate the Fr-delta.
	var deltaC Fr
	deltaC.Sub(&newC, &oldC)

	// Calculate the Point-delta.
	var poly [NodeWidth]Fr
	poly[cxIndex] = deltaC

	// Add delta to the current commitment.
	n.commitment.Add(n.commitment, cfg.CommitToPoly(poly[:], 0))
}

func (n *LeafNode) updateCn(index byte, value []byte, c *Point) {
	var (
		old, newH [2]Fr
		diff      Point
		poly      [NodeWidth]Fr
	)

	// Optimization idea:
	// If the value is created (i.e. not overwritten), the leaf marker
	// is already present in the commitment. In order to save computations,
	// do not include it. The result should be the same,
	// but the computation time should be faster as one doesn't need to
	// compute 1 - 1 mod N.
	leafToComms(old[:], n.values[index])
	leafToComms(newH[:], value)

	newH[0].Sub(&newH[0], &old[0])
	poly[2*(index%128)] = newH[0]
	diff = cfg.conf.Commit(poly[:])
	poly[2*(index%128)].SetZero()
	c.Add(c, &diff)

	newH[1].Sub(&newH[1], &old[1])
	poly[2*(index%128)+1] = newH[1]
	diff = cfg.conf.Commit(poly[:])
	c.Add(c, &diff)
}

func (n *LeafNode) updateLeaf(index byte, value []byte) {
	// Update the corresponding C1 or C2 commitment.
	var c *Point
	var oldC Point
	if index < NodeWidth/2 {
		c = n.c1
		oldC = *n.c1
	} else {
		c = n.c2
		oldC = *n.c2
	}
	n.updateCn(index, value, c)

	// Batch the Fr transformation of the new and old CX.
	var frs [2]Fr
	toFrMultiple([]*Fr{&frs[0], &frs[1]}, []*Point{c, &oldC})

	// If index is in the first NodeWidth/2 elements, we need to update C1. Otherwise, C2.
	cxIndex := 2 + int(index)/(NodeWidth/2) // [1, stem, -> C1, C2 <-]
	n.updateC(cxIndex, frs[0], frs[1])

	n.values[index] = value
}

func (n *LeafNode) updateMultipleLeaves(values [][]byte) {
	var oldC1, oldC2 *Point

	// We iterate the values, and we update the C1 and/or C2 commitments depending on the index.
	// If any of them is touched, we save the original point so we can update the LeafNode root
	// commitment. We copy the original point in oldC1 and oldC2, so we can batch their Fr transformation
	// after this loop.
	for i, v := range values {
		if len(v) != 0 && !bytes.Equal(v, n.values[byte(i)]) {
			if i < NodeWidth/2 {
				// First time we touch C1? Save the original point for later.
				if oldC1 == nil {
					oldC1 = &Point{}
					oldC1.Set(n.c1)
				}
				// We update C1 directly in `n`. We have our original copy in oldC1.
				n.updateCn(byte(i), v, n.c1)
			} else {
				// First time we touch C2? Save the original point for later.
				if oldC2 == nil {
					oldC2 = &Point{}
					oldC2.Set(n.c2)
				}
				// We update C2 directly in `n`. We have our original copy in oldC2.
				n.updateCn(byte(i), v, n.c2)
			}
			n.values[byte(i)] = v
		}
	}

	// We have three potential cases here:
	// 1. We have touched C1 and C2: we Fr-batch old1, old2 and newC1, newC2. (4x gain ratio)
	// 2. We have touched only one CX: we Fr-batch oldX and newCX. (2x gain ratio)
	// 3. No C1 or C2 was touched, this is a noop.
	var frs [4]Fr
	const c1Idx = 2 // [1, stem, ->C1<-, C2]
	const c2Idx = 3 // [1, stem, C1, ->C2<-]

	if oldC1 != nil && oldC2 != nil { // Case 1.
		toFrMultiple([]*Fr{&frs[0], &frs[1], &frs[2], &frs[3]}, []*Point{n.c1, oldC1, n.c2, oldC2})
		n.updateC(c1Idx, frs[0], frs[1])
		n.updateC(c2Idx, frs[2], frs[3])
	} else if oldC1 != nil { // Case 2. (C1 touched)
		toFrMultiple([]*Fr{&frs[0], &frs[1]}, []*Point{n.c1, oldC1})
		n.updateC(c1Idx, frs[0], frs[1])
	} else if oldC2 != nil { // Case 2. (C2 touched)
		toFrMultiple([]*Fr{&frs[0], &frs[1]}, []*Point{n.c2, oldC2})
		n.updateC(c2Idx, frs[0], frs[1])
	}
}

func (n *LeafNode) Delete(k []byte, _ NodeResolverFn) error {
	// Sanity check: ensure the key header is the same:
	if !equalPaths(k, n.stem) {
		return errDeleteNonExistent
	}

	var zero [32]byte
	n.updateLeaf(k[31], zero[:])
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

func (n *LeafNode) Hash() *Fr {
	// TODO cache this in a subsequent PR, not done here
	// to reduce complexity.
	// TODO use n.commitment once all Insert* are diff-inserts
	var hash Fr
	toFr(&hash, n.Commitment())
	return &hash
}

func (n *LeafNode) Commitment() *Point {
	if n.commitment == nil {
		panic("nil commitment")
	}
	return n.commitment
}

func (n *LeafNode) Commit() *Point {
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
	if len(val) == 0 {
		return
	}
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
		poly [NodeWidth]Fr // top-level polynomial
		pe                 = &ProofElements{
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
	toFrMultiple([]*Fr{&poly[2], &poly[3]}, []*Point{n.c1, n.c2})

	// First pass: add top-level elements first
	var hasC1, hasC2 bool
	for _, key := range keys {
		hasC1 = hasC1 || (key[31] < 128)
		hasC2 = hasC2 || (key[31] >= 128)
		if hasC2 {
			break
		}
	}
	if hasC1 {
		pe.Cis = append(pe.Cis, n.commitment)
		pe.Zis = append(pe.Zis, 2)
		pe.Yis = append(pe.Yis, &poly[2])
		pe.Fis = append(pe.Fis, poly[:])
	}
	if hasC2 {
		pe.Cis = append(pe.Cis, n.commitment)
		pe.Zis = append(pe.Zis, 3)
		pe.Yis = append(pe.Yis, &poly[3])
		pe.Fis = append(pe.Fis, poly[:])
	}

	// Second pass: add the cn-level elements
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
			suffPoly [NodeWidth]Fr // suffix-level polynomial
			count    int
		)
		vals := make([][]byte, NodeWidth)
		for idx := range n.values {
			vals[idx] = n.values[idx]
		}
		if suffix >= 128 {
			count = fillSuffixTreePoly(suffPoly[:], vals[128:])
		} else {
			count = fillSuffixTreePoly(suffPoly[:], vals[:128])
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
			esses = append(esses, extStatusAbsentEmpty|(n.depth<<3))
			continue
		}

		var scomm *Point
		if suffix < 128 {
			scomm = n.c1
		} else {
			scomm = n.c2
		}

		slotPath := string(key[:n.depth]) + string([]byte{2 + suffix/128})

		// Proof of absence: case of a missing value.
		//
		// Suffix tree is present as a child of the extension,
		// but does not contain the requested suffix. This can
		// only happen when the leaf has never been written to
		// since after deletion the value would be set to zero
		// but still contain the leaf marker 2^128.
		if n.values[suffix] == nil {
			pe.Cis = append(pe.Cis, scomm, scomm)
			pe.Zis = append(pe.Zis, 2*suffix, 2*suffix+1)
			pe.Yis = append(pe.Yis, &FrZero, &FrZero)
			pe.Fis = append(pe.Fis, suffPoly[:], suffPoly[:])
			if len(esses) == 0 || esses[len(esses)-1] != extStatusPresent|(n.depth<<3) {
				esses = append(esses, extStatusPresent|(n.depth<<3))
			}
			pe.ByPath[slotPath] = scomm
			continue
		}

		// suffix tree is present and contains the key
		var leaves [2]Fr
		leafToComms(leaves[:], n.values[suffix])
		pe.Cis = append(pe.Cis, scomm, scomm)
		pe.Zis = append(pe.Zis, 2*suffix, 2*suffix+1)
		pe.Yis = append(pe.Yis, &leaves[0], &leaves[1])
		pe.Fis = append(pe.Fis, suffPoly[:], suffPoly[:])
		if len(esses) == 0 || esses[len(esses)-1] != extStatusPresent|(n.depth<<3) {
			esses = append(esses, extStatusPresent|(n.depth<<3))
		}
		pe.ByPath[slotPath] = scomm
	}

	return pe, esses, poass
}

// Serialize serializes a LeafNode.
// The format is: <nodeType><stem><bitlist><c1comm><c2comm><children...>
func (n *LeafNode) Serialize() ([]byte, error) {
	cBytes := banderwagon.ElementsToBytes([]*banderwagon.Element{n.c1, n.c2})
	return n.serializeWithCompressedCommitments(cBytes[0], cBytes[1]), nil
}

func (n *LeafNode) Copy() VerkleNode {
	l := &LeafNode{}
	l.stem = make([]byte, len(n.stem))
	l.values = make(map[byte][]byte, len(n.values))

	l.depth = n.depth
	copy(l.stem, n.stem)
	for i, v := range n.values {
		l.values[i] = make([]byte, len(v))
		copy(l.values[i], v)
	}
	if n.commitment != nil {
		l.commitment = new(Point)
		CopyPoint(l.commitment, n.commitment)
	}
	if n.c1 != nil {
		l.c1 = new(Point)
		CopyPoint(l.c1, n.c1)
	}
	if n.c2 != nil {
		l.c2 = new(Point)
		CopyPoint(l.c2, n.c2)
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
	if i >= NodeWidth {
		panic("leaf node index out of range")
	}
	return n.values[byte(i)]
}

func (n *LeafNode) toDot(parent, path string) string {
	var hash Fr
	toFr(&hash, n.Commitment())
	ret := fmt.Sprintf("leaf%s [label=\"L: %x\nC: %x\nC₁: %x\nC₂:%x\"]\n%s -> leaf%s\n", path, hash.Bytes(), n.commitment.Bytes(), n.c1.Bytes(), n.c2.Bytes(), parent, path)
	for i, v := range n.values {
		if v != nil {
			ret = fmt.Sprintf("%sval%s%02x [label=\"%x\"]\nleaf%s -> val%s%02x\n", ret, path, i, v, path, path, i)
		}
	}
	return ret
}

func (n *LeafNode) setDepth(d byte) {
	n.depth = d
}

func (n *LeafNode) Values() [][]byte {
	vals := make([][]byte, NodeWidth)
	for idx := range n.values {
		vals[idx] = n.values[idx]
	}
	return vals
}

func setBit(bitlist []byte, index int) {
	bitlist[index/8] |= mask[index%8]
}

func ToDot(root VerkleNode) string {
	root.Commit()
	return fmt.Sprintf("digraph D {\n%s}", root.toDot("", ""))
}

// SerializedNode contains a serialization of a tree node.
// It provides everything that the client needs to save the node to the database.
// For example, CommitmentBytes is usually use as key and SerializedBytes as value.
// Providing both allows this library to do more optimizations.
type SerializedNode struct {
	Node            VerkleNode
	CommitmentBytes [32]byte
	SerializedBytes []byte
}

// BatchSerialize is an optimized serialization API when multiple VerkleNodes serializations are required, and all are
// available in memory.
func (n *InternalNode) BatchSerialize() ([]SerializedNode, error) {
	// Commit to the node to update all the nodes commitments.
	n.Commit()

	// Collect all nodes that we need to serialize.
	nodes := make([]VerkleNode, 0, 1024)
	nodes = n.collectNonHashedNodes(nodes)

	// We collect all the *Point, so we can batch all projective->affine transformations.
	pointsToCompress := make([]*Point, 0, 3*len(nodes))
	// Contains a map between VerkleNode and the index in the `compressedPoints` containing the commitment below.
	compressedPointsIdxs := make(map[VerkleNode]int, 3*len(nodes))
	for i := range nodes {
		switch n := nodes[i].(type) {
		case *InternalNode:
			pointsToCompress = append(pointsToCompress, n.commitment)
			compressedPointsIdxs[n] = len(pointsToCompress) - 1
		case *LeafNode:
			pointsToCompress = append(pointsToCompress, n.commitment, n.c1, n.c2)
			compressedPointsIdxs[n] = len(pointsToCompress) - 3
		}
	}

	// Now we do the all transformations in a single-shot.
	compressedPoints := banderwagon.ElementsToBytes(pointsToCompress)

	// Now we that we did the heavy CPU work, we have to do the rest of `nodes` serialization
	// taking the compressed points from this single list.
	ret := make([]SerializedNode, 0, len(nodes))
	idx := 0
	for i := range nodes {
		switch n := nodes[i].(type) {
		case *InternalNode:
			sn := SerializedNode{
				Node:            n,
				CommitmentBytes: compressedPoints[idx],
				SerializedBytes: n.serializeWithCompressedChildren(compressedPointsIdxs, compressedPoints),
			}
			ret = append(ret, sn)
			idx++
		case *LeafNode:
			c1Bytes := compressedPoints[idx+1]
			c2Bytes := compressedPoints[idx+2]
			sn := SerializedNode{
				Node:            n,
				CommitmentBytes: compressedPoints[idx],
				SerializedBytes: n.serializeWithCompressedCommitments(c1Bytes, c2Bytes),
			}
			ret = append(ret, sn)
			idx += 3
		}
	}

	return ret, nil
}

func (n *InternalNode) collectNonHashedNodes(list []VerkleNode) []VerkleNode {
	list = append(list, n)
	for _, child := range n.children {
		switch childNode := child.(type) {
		case *LeafNode:
			list = append(list, childNode)
		case *InternalNode:
			list = childNode.collectNonHashedNodes(list)
		}
	}
	return list
}

func (n *InternalNode) serializeWithCompressedChildren(compressedPointsIdxs map[VerkleNode]int, compressedPoints [][32]byte) []byte {
	var (
		hashlist                    [NodeWidth / 8]byte
		nonHashedCount, hashedCount int
	)

	ret := make([]byte, nodeTypeSize+bitlistSize+NodeWidth*SerializedPointCompressedSize)
	bitlist := ret[internalBitlistOffset:]
	for i, c := range n.children {
		if _, ok := c.(Empty); !ok {
			setBit(bitlist, i)
			if _, ok := c.(*HashedNode); ok {
				setBit(hashlist[:], i)
				hashedCount++
			} else {
				nonHashedCount++
			}
		}
	}

	ret = ret[:nodeTypeSize+bitlistSize+(nonHashedCount+hashedCount)*SerializedPointCompressedSize]
	children := ret[internalNodeChildrenOffset:internalNodeChildrenOffset]
	consumed := 0
	for i := 0; i < NodeWidth; i++ {
		if bit(bitlist, i) {
			if bit(hashlist[:], i) {
				children = append(children, n.children[i].(*HashedNode).commitment...)
			} else {
				childIdx, ok := compressedPointsIdxs[n.children[i]]
				if !ok {
					panic("children commitment not found in cache")
				}
				children = append(children, compressedPoints[childIdx][:]...)
				consumed++
			}
		}
	}

	// Store in ret the serialized result
	ret[nodeTypeOffset] = internalRLPType
	// Note that:
	// - Children were already appended in ret through the children slice.
	// - Bitlist was embedded in ret.

	return ret
}

func (n *LeafNode) serializeWithCompressedCommitments(c1Bytes [32]byte, c2Bytes [32]byte) []byte {
	// Empty value in LeafNode used for padding.
	var emptyValue [LeafValueSize]byte

	// Create bitlist and store in children LeafValueSize (padded) values.
	children := make([]byte, 0, NodeWidth*LeafValueSize)
	var bitlist [bitlistSize]byte
	vals := make([][]byte, NodeWidth)
	for i := range n.values {
		vals[i] = n.values[i]
	}
	for i, v := range vals {
		if v != nil {
			setBit(bitlist[:], i)
			children = append(children, v...)
			if padding := emptyValue[:LeafValueSize-len(v)]; len(padding) != 0 {
				children = append(children, padding...)
			}
		}
	}

	// Create the serialization.
	baseSize := nodeTypeSize + StemSize + bitlistSize + 2*SerializedPointCompressedSize
	result := make([]byte, baseSize, baseSize+4*32) // Extra pre-allocated capacity for 4 values.
	result[0] = leafRLPType
	copy(result[leafSteamOffset:], n.stem[:StemSize])
	copy(result[leafBitlistOffset:], bitlist[:])
	copy(result[leafC1CommitmentOffset:], c1Bytes[:])
	copy(result[leafC2CommitmentOffset:], c2Bytes[:])
	result = append(result, children...)

	return result
}

func (n *InternalNode) BatchInsertOrdered(leaves []LeafNode) {
	var currentBranch [StemSize]*InternalNode
	currentBranch[0] = n

	var prevLeaf *LeafNode

	for i := range leaves {
		newLeaf := &leaves[i]

		idx := firstDiffByteIdx(prevLeaf.stem, newLeaf.stem)

		if currentBranch[idx] != nil {
			currentBranch[idx].cowChild(newLeaf.stem[idx])
			currentBranch[idx].children[newLeaf.stem[idx]] = newLeaf
			newLeaf.setDepth(currentBranch[idx].depth + 1)
			for i := idx + 1; i < len(currentBranch); i++ {
				currentBranch[i] = nil
			}
		} else {
			prevNonNilIdx := 0
			for i := idx - 1; i >= 0; i-- {
				if currentBranch[i] != nil {
					prevNonNilIdx = i
					break
				}
			}
			for k := prevNonNilIdx + 1; k <= idx; k++ {
				currentBranch[k] = newInternalNode(currentBranch[k-1].depth + 1).(*InternalNode)
				currentBranch[k-1].cowChild(newLeaf.stem[k-1])
				currentBranch[k-1].children[newLeaf.stem[k-1]] = currentBranch[k]
			}

			currentBranch[idx].cowChild(prevLeaf.stem[idx])
			currentBranch[idx].children[prevLeaf.stem[idx]] = prevLeaf
			prevLeaf.setDepth(currentBranch[idx].depth + 1)
			currentBranch[idx].cowChild(newLeaf.stem[idx])
			currentBranch[idx].children[newLeaf.stem[idx]] = newLeaf

			for i := idx + 1; i < len(currentBranch); i++ {
				currentBranch[i] = nil
			}
		}

		prevLeaf = newLeaf
	}
}

func (n *InternalNode) InsertLeafNodes(leaves []LeafNode, resolver NodeResolverFn) error {
	for i := range leaves {
		ln := leaves[i]
		parent := n

		// Set `parent` to the parent of the leaf node.
		for {
			if hashedNode, ok := parent.children[ln.stem[parent.depth]].(*HashedNode); ok {
				serialized, err := resolver(hashedNode.commitment)
				if err != nil {
					return fmt.Errorf("resolving node %x: %w", hashedNode.commitment, err)
				}
				resolved, err := ParseNode(serialized, n.depth+1, hashedNode.commitment)
				if err != nil {
					return fmt.Errorf("parsing node %x: %w", serialized, err)
				}
				n.children[ln.stem[parent.depth]] = resolved
			}

			nextParent, ok := parent.children[ln.stem[parent.depth]].(*InternalNode)
			if !ok {
				break
			}
			parent = nextParent
		}

		switch node := parent.children[ln.stem[parent.depth]].(type) {
		case Empty:
			parent.cowChild(ln.stem[parent.depth])
			parent.children[ln.stem[parent.depth]] = &ln
			ln.setDepth(parent.depth + 1)
		case *LeafNode:
			// If LeafNodes are for the same stem, then it means it was already migrated.
			// Nothing to do.
			if bytes.Equal(node.stem, ln.stem) {
				continue
			}

			// Otherwise, we need to create the missing internal nodes depending in the fork point in their stems.
			idx := firstDiffByteIdx(node.stem, ln.stem)
			for i := parent.depth + 1; i <= byte(idx); i++ {
				nextParent := newInternalNode(parent.depth + 1).(*InternalNode)
				parent.cowChild(ln.stem[parent.depth])
				parent.children[ln.stem[parent.depth]] = nextParent
				parent = nextParent
			}
			// Add old and new leaf node to the latest created parent.
			parent.cowChild(node.stem[parent.depth])
			parent.children[node.stem[parent.depth]] = node
			ln.setDepth(parent.depth + 1)
			parent.cowChild(ln.stem[parent.depth])
			parent.children[ln.stem[parent.depth]] = &ln
			ln.setDepth(parent.depth + 1)
		}
	}
	return nil
}
