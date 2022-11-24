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

// StatelessNode represents a node for execution in a stateless context,
// i.e. that its children/values are not all known. It can represent both
// an InternalNode or a LeafNode.
type StatelessNode struct {
	// List of available child nodes of this internal node,
	// nil if this is an extension node.
	children map[byte]VerkleNode

	// Used during the deserialization to avoid unnecessary calls
	// to SetBytes, that are very costly. It contains the list of
	// all non-deserialized nodes, for future references.
	unresolved map[byte][]byte

	// List of values, nil if this is an internal node.
	values map[byte][]byte

	stem []byte

	// node depth in the tree, in bits
	depth byte

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
	cfg := GetConfig()
	return &StatelessNode{
		children:   make(map[byte]VerkleNode),
		hash:       new(Fr).SetZero(),
		committer:  cfg,
		commitment: Generator(),
		unresolved: make(map[byte][]byte),
	}
}

func NewStatelessWithCommitment(point *Point) *StatelessNode {
	var (
		xfr Fr
	)
	toFr(&xfr, point)
	cfg := GetConfig()
	return &StatelessNode{
		children:   make(map[byte]VerkleNode),
		hash:       &xfr,
		committer:  cfg,
		commitment: point,
	}
}

func (n *StatelessNode) Children() []VerkleNode {
	var children [256]VerkleNode
	for i := range children {
		if n.children[byte(i)] != nil {
			children[i] = n.children[byte(i)]
		} else {
			children[i] = Empty(struct{}{})
		}
	}
	return children[:]
}

func (n *StatelessNode) SetChild(i int, v VerkleNode) error {
	if i >= NodeWidth {
		return errors.New("child index higher than node width")
	}
	c, ok := v.(*StatelessNode)
	if !ok {
		return errStatelessAndStatefulMix
	}
	n.children[byte(i)] = c
	return nil
}

func (n *StatelessNode) getOldCn(index byte) (*Point, *Fr) {
	var (
		c    *Point
		oldc Fr
	)
	if index < 128 {
		c = n.c1
	} else {
		c = n.c2
	}
	toFr(&oldc, c)
	return c, &oldc
}

func (n *StatelessNode) updateC(index byte, c *Point, oldc *Fr) {
	var (
		newc Fr
		diff Point
	)

	toFr(&newc, c)
	newc.Sub(&newc, oldc)
	diff.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[2+(index/128)], &newc)
	n.commitment.Add(n.commitment, &diff)
}

func (n *StatelessNode) updateCn(index byte, value []byte, c *Point) {
	var (
		oldVal, newVal [2]Fr
		diff           Point
	)

	// Optimization idea:
	// If the value is created (i.e. not overwritten), the leaf marker
	// is already present in the commitment. In order to save computations,
	// do not include it. The result should be the same,
	// but the computation time should be faster as one doesn't need to
	// compute 1 - 1 mod N.
	leafToComms(oldVal[:], n.values[index])
	leafToComms(newVal[:], value)

	newVal[0].Sub(&newVal[0], &oldVal[0])
	diff.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[2*(index%128)], &newVal[0])
	c.Add(c, &diff)

	newVal[1].Sub(&newVal[1], &oldVal[1])
	diff.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[2*(index%128)+1], &newVal[1])
	c.Add(c, &diff)
}

func (n *StatelessNode) updateLeaf(index byte, value []byte) {
	c, oldc := n.getOldCn(index)
	n.updateCn(index, value, c)
	n.updateC(index, c, oldc)
	if n.values[index] == nil {
		// only increase the count if no value is
		// overwritten.
		n.count++
	}
	n.values[index] = value
}

func (n *StatelessNode) Insert(key []byte, value []byte, resolver NodeResolverFn) error {
	// if this is a leaf value and the stems are different, intermediate
	// nodes need to be inserted.
	if n.values != nil {
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if equalPaths(n.stem, key) {
			n.updateLeaf(key[31], value)
		} else {
			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextexisting := offset2key(n.stem, n.depth)
			oldExtNode := &StatelessNode{
				depth:      n.depth + 1,
				committer:  n.committer,
				count:      n.count,
				values:     n.values,
				stem:       n.stem,
				commitment: new(Point),
				hash:       n.hash,
				c1:         n.c1,
				c2:         n.c2,
			}
			n.children = map[byte]VerkleNode{
				nextexisting: oldExtNode,
			}
			n.values = nil
			n.stem = nil
			n.c1 = nil
			n.c2 = nil
			n.count++
			CopyPoint(oldExtNode.commitment, n.commitment)
			n.hash = new(Fr)

			nextinserted := offset2key(key, n.depth)
			if nextinserted != nextexisting {
				// Next word differs, so the branching point
				// has been reached. Create the "new" child.
				n.children[nextinserted] = n.newLeafChildFromSingleValue(key, value)
			}

			// recurse into the newly created child
			err := n.children[nextinserted].Insert(key, value, resolver)
			if err != nil {
				return err
			}
			var poly [NodeWidth]Fr
			CopyFr(&poly[nextexisting], oldExtNode.Hash())
			if nextexisting != nextinserted {
				CopyFr(&poly[nextinserted], n.children[nextinserted].Hash())
			}
			n.commitment = n.committer.CommitToPoly(poly[:], NodeWidth-2)
			toFr(n.hash, n.commitment)
		}
	} else {
		// internal node
		nChild := offset2key(key, n.depth)

		// special case: missing child, check whether there is a child node
		// to deserialize, and if that is not the case, this is an empty child.
		cfg := GetConfig()
		if n.children[nChild] == nil {
			unresolved := n.unresolved[nChild]
			if len(unresolved) == 0 {
				n.children[nChild] = n.newLeafChildFromSingleValue(key, value)

				var diff Point
				diff.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[nChild], n.children[nChild].Hash())
				n.commitment.Add(n.commitment, &diff)
				toFr(n.hash, n.commitment)
				return nil
			}

			n.children[nChild] = &HashedNode{unresolved}
			// fallthrough to hash resolution
		}

		// If the child is a hash, the node needs to be resolved
		// before there is an insert into it.
		if h, ok := n.children[nChild].(*HashedNode); ok {
			comm := h.commitment
			serialized, err := resolver(comm)
			if err != nil {
				return err
			}
			node, err := ParseNode(serialized, n.depth+1, comm)
			if err != nil {
				return err
			}
			n.children[nChild] = node
		}

		// Save the value of the initial child commitment
		var pre Fr
		CopyFr(&pre, n.children[nChild].Hash())

		var err error
		switch child := n.children[nChild].(type) {
		case *StatelessNode:
			err = child.Insert(key, value, resolver)
		case *LeafNode:
			if !bytes.Equal(child.stem, key[:31]) {
				child.setDepth(child.depth + 1)
				existing := child.stem[n.depth+1]
				inserted := key[n.depth+1]
				newbranch := &StatelessNode{
					children:   map[byte]VerkleNode{existing: child},
					depth:      n.depth + 1,
					commitment: Generator(),
					hash:       new(Fr),
				}
				n.children[nChild] = newbranch

				// reuse pre here, since the child commitment is the same for this
				// new branch as it was for the current node before the insertion.
				newbranch.commitment.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[existing], &pre)

				if inserted != existing {
					values := make([][]byte, NodeWidth)
					lastnode := NewLeafNode(key[:31], values)
					newbranch.children[inserted] = lastnode
					newbranch.children[inserted].setDepth(child.depth + 1)
					lastnode.Insert(key, value, nil)
					var lnComm Fr
					var diff Point
					toFr(&lnComm, lastnode.Commitment())
					diff.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[inserted], &lnComm)
					newbranch.commitment.Add(newbranch.commitment, &diff)
				} else {
					err = newbranch.Insert(key, value, resolver)
				}
			} else {
				err = child.Insert(key, value, resolver)
			}
		default:
			err = errNotSupportedInStateless
		}
		if err != nil {
			return err
		}

		// update the commitment
		var diff Point
		diff.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[nChild], pre.Sub(n.children[nChild].Hash(), &pre))
		n.commitment.Add(n.commitment, &diff)
	}

	toFr(n.hash, n.commitment)
	return nil
}

func (n *StatelessNode) updateMultipleLeaves(values [][]byte) {
	var c1, c2 *Point
	var old1, old2 *Fr
	for i, v := range values {
		if len(v) != 0 && !bytes.Equal(v, n.values[byte(i)]) {
			if i < 128 {
				if c1 == nil {
					c1, old1 = n.getOldCn(byte(i))
				}
				n.updateCn(byte(i), v, c1)
			} else {
				if c2 == nil {
					c2, old2 = n.getOldCn(byte(i))
				}
				n.updateCn(byte(i), v, c2)
			}

			n.values[byte(i)] = v
		}
	}

	if c1 != nil {
		n.updateC(0, c1, old1)
	}
	if c2 != nil {
		n.updateC(128, c2, old2)
	}
}

func (n *StatelessNode) InsertAtStem(stem []byte, values [][]byte, resolver NodeResolverFn, _ bool) error {
	nChild := offset2key(stem, n.depth) // index of the child pointed by the next byte in the key

	if n.values != nil {
		n.updateMultipleLeaves(values)
		return nil
	}

	// special case: missing child, check whether there is a child node
	// to deserialize, and if that is not the case, this is an empty child.
	cfg := GetConfig()
	if n.children[nChild] == nil {
		unresolved := n.unresolved[nChild]
		if len(unresolved) == 0 {
			n.children[nChild] = n.newLeafChildFromMultipleValues(stem, values)
			return nil
		}

		n.children[nChild] = &HashedNode{unresolved}
		// fallthrough to hash resolution
	}

	// If the child is a hash, the node needs to be resolved
	// before there is an insert into it.
	if h, ok := n.children[nChild].(*HashedNode); ok {
		comm := h.commitment
		serialized, err := resolver(comm)
		if err != nil {
			return fmt.Errorf("stem insertion failed (node resolution error) %x %w", stem, err)
		}
		node, err := ParseNode(serialized, n.depth+1, comm)
		if err != nil {
			return err
		}
		n.children[nChild] = node
	}

	// Save the value of the initial child commitment
	var pre Fr
	CopyFr(&pre, n.children[nChild].Hash())

	var err error
	switch child := n.children[nChild].(type) {
	case *InternalNode:
		leaf := NewLeafNode(stem, values)
		err = child.InsertStem(stem, leaf, resolver, true)
	case *StatelessNode:
		err = child.InsertAtStem(stem, values, resolver, false)
	case *LeafNode:
		if equalPaths(child.stem, stem) {
			child.updateMultipleLeaves(values)
		} else {
			nextexisting := offset2key(child.stem, child.depth)
			// Insert multiple intermediate nodes
			newbranch := &StatelessNode{
				children:   map[byte]VerkleNode{nextexisting: child},
				commitment: Generator(),
				depth:      child.depth,
				committer:  n.committer,
			}
			child.setDepth(child.depth + 1)
			n.children[nChild] = newbranch
			n.count++

			// pre-insertion commitment - it's a bit wasteful since
			// it is computed once and then updated. TODO see if this
			// can be optimized by inserting intermediate nodes iteratively.
			newbranch.commitment.ScalarMul(&cfg.conf.SRSPrecompPoints.SRS[nextexisting], child.Hash())

			err = newbranch.InsertAtStem(stem, values, resolver, false)
		}
	default:
		return errNotSupportedInStateless
	}
	if err != nil {
		return err
	}

	// update the commitment
	var poly [256]Fr
	poly[nChild].Sub(n.children[nChild].Hash(), &pre)
	diff := cfg.conf.Commit(poly[:])
	n.commitment.Add(n.commitment, &diff)
	return nil
}

func (n *StatelessNode) newLeafChildFromSingleValue(key, value []byte) *LeafNode {
	newchild := NewLeafNode(key[:31], make([][]byte, NodeWidth))
	newchild.setDepth(n.depth + 1)
	newchild.Insert(key, value, nil)
	return newchild
}

func (n *StatelessNode) newLeafChildFromMultipleValues(stem []byte, values [][]byte) *StatelessNode {
	newchild := &StatelessNode{
		depth:     n.depth + 1,
		stem:      stem,
		values:    map[byte][]byte{},
		committer: n.committer,
		count:     1,
		hash:      new(Fr),
		c1:        Generator(),
		c2:        Generator(),
	}

	var poly [4]Fr
	poly[0].SetUint64(1)
	StemFromBytes(&poly[1], newchild.stem)

	for i, v := range values {
		var cpoly [256]Fr
		newchild.values[byte(i)] = v

		leafToComms(cpoly[byte(i%128)*2:], v)
		if i < 128 {
			newchild.c1 = n.committer.CommitToPoly(cpoly[:], 2)
			toFr(&poly[2], newchild.c1)
		} else {
			newchild.c2 = n.committer.CommitToPoly(cpoly[:], 2)
			toFr(&poly[3], newchild.c2)
		}
		newchild.commitment = n.committer.CommitToPoly(poly[:], 4)
		toFr(newchild.hash, newchild.commitment)
	}

	return newchild
}

// insertStem is a translation of insert_node in the block explorer.
// It inserts a given stem in the tree, placing it as described
// by stemInfo. Its third parameters is the list of commitments
// that have not been assigned a node. It returns the same list,
// save the commitments that have been assigned a node during the
// call.
func (n *StatelessNode) insertStem(path []byte, stemInfo stemInfo, comms []*Point) ([]*Point, error) {
	if len(path) == 0 {
		return comms, errors.New("invalid path")
	}

	// path is 1 byte long, the leaf node must be created
	if len(path) == 1 {
		switch stemInfo.stemType & 3 {
		case extStatusAbsentEmpty:
			// nothing to do
		case extStatusAbsentOther:
			// insert poa stem
		case extStatusPresent:
			// insert stem
			newchild := NewStatelessWithCommitment(comms[0])
			n.children[path[0]] = newchild
			comms = comms[1:]
			if stemInfo.has_c1 {
				newchild.c1 = comms[0]
				comms = comms[1:]
			}
			if stemInfo.has_c2 {
				newchild.c2 = comms[0]
				comms = comms[1:]
			}
			newchild.values = stemInfo.values
			newchild.stem = stemInfo.stem
			newchild.depth = n.depth + 1
		}
		return comms, nil
	}

	// create the child node if missing
	if n.children[path[0]] == nil {
		n.children[path[0]] = NewStatelessWithCommitment(comms[0])
		comms = comms[1:]
		n.children[path[0]].setDepth(n.depth + 1)
	}

	// This should only be used in the context of
	// stateless nodes, so panic if another node
	// type is found.
	child := n.children[path[0]].(*StatelessNode)

	// recurse
	return child.insertStem(path[1:], stemInfo, comms)
}

func (n *StatelessNode) insertValue(key, value []byte) error {
	// reached a leaf node ?
	if len(n.children) == 0 {
		if !bytes.Equal(key[:31], n.stem) {
			return errInsertIntoOtherStem
		}
		n.values[key[31]] = value
	} else { // no, recurse
		nChild := offset2key(key, n.depth)
		n.children[nChild].(*StatelessNode).insertValue(key, value)
	}

	return nil
}

func (*StatelessNode) InsertOrdered([]byte, []byte, NodeFlushFn) error {
	return errNotSupportedInStateless
}

// Delete writes the value `0` at `key` since verkle trees need to distinguish
// between a node that used to be present and was then deleted, and a node that
// was never present.
func (n *StatelessNode) Delete(key []byte, resolver NodeResolverFn) error {
	var zero [32]byte
	return n.Insert(key, zero[:], resolver)
}

func (n *StatelessNode) Get(k []byte, getter NodeResolverFn) ([]byte, error) {
	if n.values != nil {
		// if the stems are different, then the key is missing
		if bytes.Equal(n.stem, k[:31]) {
			return n.values[k[31]], nil
		}
		return nil, nil
	}

	nChild := offset2key(k, n.depth)

	child := n.children[nChild]
	if child == nil {
		if n.unresolved[nChild] == nil {

			return nil, nil
		}

		// resolve the child before recursing
		serialized, err := getter(n.unresolved[nChild])
		if err != nil {
			return nil, fmt.Errorf("could not resolve unresolved item: %w", err)
		}
		child, err = ParseNode(serialized, n.depth+1, n.unresolved[nChild])
		if err != nil {
			return nil, fmt.Errorf("could not deserialize node: %w", err)
		}
		n.children[nChild] = child
		delete(n.unresolved, nChild)
	}
	return child.Get(k, getter)
}

func (n *StatelessNode) Commitment() *Point {
	return n.commitment
}

func (n *StatelessNode) Commit() *Point {
	// TODO go over dirty children and update the
	// current commitment.
	return n.commitment
}

func (n *StatelessNode) Hash() *Fr {
	// TODO add some caching here for better performance
	if n.hash == nil {
		n.hash = new(Fr)
	}
	toFr(n.hash, n.commitment)
	return n.hash
}

func (n *StatelessNode) GetProofItems(keys keylist) (*ProofElements, []byte, [][]byte) {
	var (
		pe = &ProofElements{
			Cis:    []*Point{},
			Zis:    []byte{},
			Yis:    []*Fr{},
			ByPath: map[string]*Point{},
		}

		esses []byte   = nil // list of extension statuses
		poass [][]byte       // list of proof-of-absence stems
	)

	if len(n.values) == 0 {
		var (
			groups = groupKeys(keys, n.depth)
		)

		for _, group := range groups {
			childIdx := offset2key(group[0], n.depth)

			var yi Fr
			// when proving that a key is not in the tree
			if n.children[childIdx] == nil {
				yi.SetZero()
			} else {
				toFr(&yi, n.children[childIdx].Commitment())
			}

			pe.Cis = append(pe.Cis, n.commitment)
			pe.Zis = append(pe.Zis, childIdx)
			pe.Yis = append(pe.Yis, &yi)
			pe.ByPath[string(group[0][:n.depth])] = n.commitment

		}

		// Loop over again, collecting the children's proof elements
		// This is because the order is breadth-first.
		for _, group := range groups {
			childIdx := offset2key(group[0], n.depth)

			// Special case of a proof of absence: no children
			// commitment, as the value is 0.
			if n.children[childIdx] == nil {
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
	} else {
		pe.Cis = append(pe.Cis, n.commitment, n.commitment)
		pe.Zis = append(pe.Zis, 0, 1)
		pe.Yis = append(pe.Yis, new(Fr).SetOne(), new(Fr).SetZero())
		StemFromBytes(pe.Yis[len(pe.Yis)-1], n.stem)

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
			var yi Fr
			toFr(&yi, n.c1)
			pe.Cis = append(pe.Cis, n.commitment)
			pe.Zis = append(pe.Zis, 2)
			pe.Yis = append(pe.Yis, &yi)
		}
		if hasC2 {
			var yi Fr
			toFr(&yi, n.c2)
			pe.Cis = append(pe.Cis, n.commitment)
			pe.Zis = append(pe.Zis, 3)
			pe.Yis = append(pe.Yis, &yi)
		}

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
				scomm    *Point
			)

			if suffix < 128 {
				scomm = n.c1
			} else {
				scomm = n.c2
			}

			// Proof of absence: case of a missing suffix tree.
			//
			// The suffix tree for this value is missing, i.e. all
			// values in the extension-and-suffix tree are grouped
			// in the other suffix tree (e.g. C2 if we are looking
			// at C1).
			if scomm == nil {
				esses = append(esses, extStatusAbsentEmpty|(n.depth<<3))
				continue
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
				pe.Cis = append(pe.Cis, scomm, scomm)
				pe.Zis = append(pe.Zis, 2*suffix, 2*suffix+1)
				pe.Yis = append(pe.Yis, &FrZero, &FrZero)
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
			if len(esses) == 0 || esses[len(esses)-1] != extStatusPresent|(n.depth<<3) {
				esses = append(esses, extStatusPresent|(n.depth<<3))
			}
			pe.ByPath[slotPath] = scomm
		}

	}
	return pe, esses, poass
}

func (n *StatelessNode) Serialize() ([]byte, error) {
	var (
		bitlist  [32]byte
		children = make([]byte, 0, NodeWidth*32)
	)
	// Only serialize leaf nodes if all the values are loaded,
	// otherwise we are facing a partially-loaded node and it
	// would be impossible to serialize it without overwriting
	// unloaded data.
	if n.children == nil {
		for i := 0; i < NodeWidth; i++ {
			v, present := n.values[byte(i)]
			if !present {
				return nil, errNotSupportedInStateless
			}
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

	for i := 0; i < NodeWidth; i++ {
		// if neither resolved nor unresolved, this
		// is an empty node, to be skipped.
		if c, ok := n.children[byte(i)]; ok {
			setBit(bitlist[:], i)
			digits := c.Commitment().Bytes()
			children = append(children, digits[:]...)
		} else if bytes, ok := n.unresolved[byte(i)]; ok {
			setBit(bitlist[:], i)
			children = append(children, bytes...)
		}
	}

	return append(append([]byte{internalRLPType}, bitlist[:]...), children...), nil
}

func (n *StatelessNode) Copy() VerkleNode {
	ret := &StatelessNode{
		commitment: new(Point),
		depth:      n.depth,
		committer:  n.committer,
		count:      n.count,
	}

	if n.children != nil {
		ret.children = make(map[byte]VerkleNode, len(n.children))
		for i, child := range n.children {
			ret.children[i] = child.Copy()
		}
	} else {
		ret.values = make(map[byte][]byte, len(n.values))
		for i, val := range n.values {
			ret.values[i] = make([]byte, len(val))
			copy(ret.values[i], val)
		}
	}

	if n.unresolved != nil {
		ret.unresolved = make(map[byte][]byte)
		for k, v := range n.unresolved {
			ret.unresolved[k] = make([]byte, len(v))
			copy(ret.unresolved[k], v)
		}
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
	n.Commit()
	me := fmt.Sprintf("internal%s", path)
	var ret string
	if len(n.values) != 0 {
		var c1bytes, c2bytes [32]byte
		if n.c1 != nil {
			c1bytes = n.c1.Bytes()
		}
		if n.c2 != nil {
			c2bytes = n.c2.Bytes()
		}
		var hash Fr
		toFr(&hash, n.commitment)
		ret = fmt.Sprintf("leaf%s [label=\"L: %x\nC: %x\nC₁: %x\nC₂:%x\"]\n%s -> leaf%s\n", path, n.hash.Bytes(), n.commitment.Bytes(), c1bytes, c2bytes, parent, path)
		for i, v := range n.values {
			if v != nil {
				ret = fmt.Sprintf("%sval%s%x [label=\"%x\"]\nleaf%s -> val%s%x\n", ret, path, i, v, path, path, i)
			}
		}
	} else {
		ret = fmt.Sprintf("%s [label=\"I: %x\"]\n", me, n.hash.BytesLE())
		if len(parent) > 0 {
			ret += fmt.Sprintf(" %s -> %s\n", parent, me)
		}

		for i, child := range n.children {
			ret += child.toDot(me, fmt.Sprintf("%s%02x", path, i)) + "\n"
		}
	}

	return ret
}

func (n *StatelessNode) setDepth(d byte) {
	n.depth = d
}

func (n *StatelessNode) ToHashedNode() *HashedNode {
	b := n.commitment.Bytes()
	return &HashedNode{b[:]}
}

func (n *StatelessNode) Flush(flush NodeFlushFn) {
	if n.values == nil {
		for _, child := range n.children {
			switch child := child.(type) {
			case *InternalNode:
				child.Flush(flush)
			case *StatelessNode:
				if child.values != nil {
					flush(child)
				} else {
					child.Flush(flush)
				}
			case *LeafNode:
				flush(child)
			}
		}
	}

	flush(n)
}
