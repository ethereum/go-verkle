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
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/protolambda/go-kzg/bls"
)

// StatelessNode only contains a commitment and a pointer to
// its children. It is used to update the root commitment in
// stateless mode, when only the proof data is available and
// most siblings of a child are missing.
type StatelessNode struct {
	commitment *bls.G1Point
	hash       *bls.Fr
	children   map[byte]*StatelessNode
	depth      int
	values     map[byte][]byte
	key        []byte
	committer  Committer
}

func (n *StatelessNode) insertIntoLeaf(key, value []byte) error {
	if len(value) != 32 {
		return fmt.Errorf("invalid value size %d != 32", len(value))
	}

	// need for a middle node?
	if !equalPaths(n.key, key) {
		// child corresponding to the initial value
		initNode := &StatelessNode{
			values:     n.values,
			key:        n.key,
			depth:      n.depth + 1,
			hash:       n.hash,
			commitment: n.commitment,
			committer:  n.committer,
		}
		n.children = map[byte]*StatelessNode{key[n.depth]: initNode}

		// does the split happens at this depth?
		if n.key[n.depth] != key[n.depth] {
			// keys differ at one location, create an
			// intermediate node, and recurse if needed.

			// child corresponding to the new value
			newNode := &StatelessNode{
				values:     map[byte][]byte{key[31]: value},
				key:        key[:31],
				depth:      n.depth + 1,
				hash:       new(bls.Fr),
				commitment: new(bls.G1Point),
				committer:  n.committer,
			}
			hashToFr(newNode.hash, value)
			n.children[key[n.depth]] = newNode
		} else {
			// nope, so recurse into node
			err := initNode.insertIntoLeaf(key, value)
			if err != nil {
				return err
			}
		}

		n.values = nil
		n.key = nil
	} else {
		n.values[key[31]] = value
		//computeCommitment(n.hash, n.commitment, value)
	}

	// reclaculate the commitment
	n.hash = nil
	n.ComputeCommitment()

	return nil
}

// Insert or Update value into the tree. Compared to its stateful version, this
// code assumes that the general structure has already been set from the proof,
// and therefore that all changes in the structure correspond to an "overwrite"
// of the pre-tree with the structure of the post-tree, in order to compute the
// post-state transition root commitment.
func (n *StatelessNode) Insert(key, value []byte, resolver NodeResolverFn) error {
	// A leaf was reached, overwrite the value and update the commitment
	if n.values != nil {
		err := n.insertIntoLeaf(key, value)
		if err != nil {
			return err
		}
		n.ComputeCommitment()
		return nil
	}

	if child, ok := n.children[key[n.depth]]; ok {
		// child exists, recurse
		var diff, pre bls.G1Point
		if child.commitment == nil {
			// For stateless root commitment calculations to work,
			// the initial commitments have to be available. Fail
			// early if that isn't the case.
			return errors.New("child commitment was not calculated")
		}
		bls.CopyG1(&pre, child.commitment)
		child.Insert(key, value, resolver)

		// Special case: if there is only one key, the top branch
		// node is ignored.
		if n.depth == 0 && len(n.children) == 1 {
			n.hash = child.hash
			return nil
		}

		// Update the commitment by applying the delta
		bls.SubG1(&diff, &pre, child.commitment)
		// TODO bls.MulG1
		bls.AddG1(n.commitment, n.commitment, &diff)
		h := sha256.Sum256(bls.ToCompressedG1(n.commitment))
		hashToFr(n.hash, h[:])
	} else {
		// child does not exist, insert a new node
		child := &StatelessNode{
			depth:     n.depth + 1,
			values:    map[byte][]byte{key[31]: value},
			key:       key[:31],
			committer: n.committer,
		}
		n.children[key[n.depth]] = child

		child.ComputeCommitment()
	}

	return nil
}

// Insert "à la" Stacktrie. Same thing as insert, except that
// values are expected to be ordered, and the commitments and
// hashes for each subtrie are computed online, as soon as it
// is clear that no more values will be inserted in there.
func (*StatelessNode) InsertOrdered([]byte, []byte, NodeFlushFn) error {
	return errors.New("not supported")
}

// Delete a leaf with the given key
func (n *StatelessNode) Delete(key []byte) error {
	// Stop condition: a leaf was reached
	if n.values != nil {
		n.commitment = &bls.ZERO_G1
		hashToFr(n.hash, bls.ToCompressedG1(n.commitment))
		return nil
	}

	// Recurse into child, then update the commitment
	if child, ok := n.children[key[n.depth]]; ok {
		var diff, pre bls.G1Point
		bls.CopyG1(&pre, child.commitment)
		child.Delete(key)
		bls.SubG1(&diff, &pre, child.commitment)
		// TODO bls.MulG1
		bls.AddG1(n.commitment, n.commitment, &diff)
		hashToFr(n.hash, bls.ToCompressedG1(n.commitment))
		return nil
	}

	return fmt.Errorf("key %x isn't present in tree", key)
}

// Get value at a given key
func (n *StatelessNode) Get(key []byte, resolver NodeResolverFn) ([]byte, error) {
	if len(n.values) != 0 && n.values[key[31]] != nil {
		return n.values[key[31]], nil
	}

	if child, ok := n.children[key[n.depth]]; ok {
		return child.Get(key, resolver)
	}

	return nil, fmt.Errorf("key %x isn't present in tree", key)
}

// ComputeCommitment computes the commitment of the node
// The results (the curve point and the field element
// representation of its hash) are cached.
func (n *StatelessNode) ComputeCommitment() *bls.Fr {
	if n.hash == nil {
		var poly [NodeWidth]bls.Fr
		if n.values != nil {
			for b, val := range n.values {
				if val != nil {
					fmt.Println(b, val)
					h := sha256.Sum256(val)
					hashToFr(&poly[b], h[:])
				}
			}
		} else {
			for b, child := range n.children {
				child.ComputeCommitment()
				bls.CopyFr(&poly[b], child.hash)
			}
		}

		n.commitment = n.committer.CommitToPoly(poly[:], NodeWidth-len(n.children)-len(n.values))
		n.hash = new(bls.Fr)
		var serialized [32]byte
		h := sha256.Sum256(bls.ToCompressedG1(n.commitment))
		copy(serialized[:], h[:])
		hashToFr(n.hash, serialized[:])

		// Mix in the key if this is a leaf node
		if n.values != nil {
			digest := sha256.New()
			digest.Write(n.key)
			tmp := bls.FrTo32(n.hash)
			digest.Write(tmp[:])
			hashToFr(n.hash, digest.Sum(nil))
		}
	}
	return n.hash
}

// GetCommitmentAlongPath follows the path that one key
// traces through the tree, and collects the various
// elements needed to build a proof. The order of elements
// is from the bottom of the tree, up to the root.
func (*StatelessNode) GetCommitmentsAlongPath([]byte) ([]*bls.G1Point, []uint, []*bls.Fr, [][]bls.Fr) {
	panic("trying to make a proof from a proof")
}

// Serialize encodes the node to RLP.
func (*StatelessNode) Serialize() ([]byte, error) {
	return nil, errors.New("can't serialize a stateless node")
}

// Copy a node and its children
func (n *StatelessNode) Copy() VerkleNode {
	ret := &StatelessNode{
		commitment: new(bls.G1Point),
		hash:       new(bls.Fr),
		children:   make(map[byte]*StatelessNode),
	}

	bls.CopyFr(ret.hash, n.hash)
	bls.CopyG1(ret.commitment, n.commitment)

	for b, child := range n.children {
		ret.children[b] = child.Copy().(*StatelessNode)
	}

	return ret
}

// toDot returns a string representing this subtree in DOT language
func (n *StatelessNode) toDot(parent, path string) string {
	n.ComputeCommitment()
	me := fmt.Sprintf("stateless%s", path)
	ret := fmt.Sprintf("%s [label=\"I: %x depth=%d count=%d,%d\"]\n", me, bls.FrTo32(n.hash), n.depth, len(n.children), len(n.values))
	if len(parent) > 0 {
		ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
	}

	for i, child := range n.children {
		ret = fmt.Sprintf("%s%s", ret, child.toDot(me, fmt.Sprintf("%s%02x", path, i)))
	}
	for i, value := range n.values {
		ret = fmt.Sprintf("%s\nvalue%s%d [label=\"%x\"]\n%s -> value%s%d\n", ret, path, i, value, me, path, i)
	}

	return ret
}
