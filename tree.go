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

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

type VerkleNode interface {
	// Insert or Update value `v` at key `k`
	Insert(k []byte, v []byte) error

	// Get value at key `k`
	Get(k []byte) ([]byte, error)

	// Hash of the current node
	Hash() common.Hash

	// ComputeCommitment computes the commitment of the node
	ComputeCommitment(*kzg.KZGSettings) *bls.G1Point

	// GetCommitment retrieves the (previously computed)
	// commitment of a node.
	GetCommitment() *bls.G1Point

	// GetCommitmentAlongPath follows the path of one key,
	// and collect the commitments along this path in
	// reverse order, since f_{m-1} = commitment at root
	// level and f_0 = commitment to leaf.
	// It returns the list of commitments, as well as the
	// z_i.
	GetCommitmentsAlongPath([]byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr)

	// EvalPathAt evaluates the polynomial at each level along the
	// path traced by `key`, and returns the list of evaluations.
	EvalPathAt([]byte, *bls.Fr) []bls.Fr
}

const (
	// log of the number of children in an internal node
	width = 10

	// Number of children in an internal node
	InternalNodeNumChildren = 1 << width

	// Number of children in the last level node, which
	// is not width-aligned.
	LastLevelNodeNumChildren = 1 << (256 % width)

	// Number of internal (i.e. width-sized) node levels
	nInternalLevels = 256 / width
)

var (
	errInsertIntoHash = errors.New("trying to insert into hashed node")

	zeroHash = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000000")
)

type (
	// Represents an internal node at any level except
	// the bottom one, with 1024 children.
	internalNode struct {
		// List of child nodes of this internal node.
		children [InternalNodeNumChildren]VerkleNode

		// node depth in the tree, in bits
		depth uint

		// Cache the hash of the current node
		hash common.Hash

		// Cache the commitment value
		commitment *bls.G1Point
	}

	// Represents an internal node at the last level,
	// with 64 children.
	lastLevelNode struct {
		// List of values in this last level node
		children [LastLevelNodeNumChildren]VerkleNode

		// Cache the hash of the current node
		hash common.Hash

		// Cache the commitment value
		commitment *bls.G1Point
	}

	hashedNode common.Hash

	leafNode struct {
		key   []byte
		value []byte
	}

	empty struct{}
)

func init() {
	// Calculate the lagrangian basis for internal nodes and
	// last level nodes.
	var tmp bls.Fr
	bls.CopyFr(&tmp, &bls.ONE)
	for i := 0; i < LastLevelNodeNumChildren; i++ {
		bls.CopyFr(&omegaLast[i], &tmp)
		bls.MulModFr(&tmp, &tmp, &bls.Scale2RootOfUnity[6])
	}
	bls.CopyFr(&tmp, &bls.ONE)
	for i := 0; i < InternalNodeNumChildren; i++ {
		bls.CopyFr(&omegaInternal[i], &tmp)
		bls.MulModFr(&tmp, &tmp, &bls.Scale2RootOfUnity[10])
	}
}

var omegaLast [LastLevelNodeNumChildren]bls.Fr
var omegaInternal [InternalNodeNumChildren]bls.Fr

func newInternalNode(depth uint) VerkleNode {
	node := new(internalNode)
	for idx := range node.children {
		node.children[idx] = empty(struct{}{})
	}
	node.depth = depth
	return node
}

func newLastLevelNode() VerkleNode {
	node := new(lastLevelNode)
	for idx := range node.children {
		node.children[idx] = empty(struct{}{})
	}
	return node
}

// New creates a new tree root
func New() VerkleNode {
	return newInternalNode(0)
}

// offset2Key extracts the 10 bits of a key that correspond to the
// index of a child node.
func offset2Key(key []byte, offset uint) uint {
	// The node has 1024 children, i.e. 10 bits. Extract it
	// from the key to figure out which child to recurse into.
	// The number is necessarily spread across 2 bytes because
	// the pitch is 10 and therefore a multiple of 2. Hence, no
	// 3 byte scenario is possible.
	nFirstByte := offset / 8
	nBitsInSecondByte := (offset + width) % 8
	firstBitShift := (8 - (offset % 8))
	lastBitShift := (8 - nBitsInSecondByte) % 8
	leftMask := (key[nFirstByte] >> firstBitShift) << firstBitShift
	return (uint(key[nFirstByte]^leftMask) << ((nBitsInSecondByte-1)%8 + 1)) | uint(key[nFirstByte+1]>>lastBitShift)
}

func (n *internalNode) Insert(key []byte, value []byte) error {
	nChild := offset2Key(key, n.depth)

	switch child := n.children[nChild].(type) {
	case empty:
		// empty subtree; recurse-initialize. Depending
		// on the depth it's a full internal node (1024
		// entries) or a last-level node (64 entries).
		if n.depth == 240 {
			n.children[nChild] = newLastLevelNode()
		} else {
			n.children[nChild] = newInternalNode(n.depth + 10)
		}
		return n.children[nChild].Insert(key, value)
	case hashedNode:
		return errInsertIntoHash
	default:
		return child.Insert(key, value)
	}
}

func (n *internalNode) Get(k []byte) ([]byte, error) {
	nChild := offset2Key(k, n.depth)

	switch child := n.children[nChild].(type) {
	case empty, hashedNode, leafNode:
		return nil, errors.New("trying to read from an invalid child")
	default:
		return child.Get(k)
	}
}

func (n *internalNode) Hash() common.Hash {
	digest := sha256.New()
	for _, child := range n.children {
		digest.Write(child.Hash().Bytes())
	}

	return common.BytesToHash(digest.Sum(nil))
}

func compressG1Point(p *bls.G1Point) []byte {
	// Get the compressed form of the commitment as described in:
	// https://docs.rs/bls12_381/0.4.0/bls12_381/notes/serialization/index.html
	compressed := p.X.Serialize()
	compressed[0] |= 0x80 // compressed form
	if p.Z.IsZero() {
		compressed[0] |= 0x40 // infinity
	} else if !p.Y.IsNegative() {
		compressed[0] |= 0x20 // largest Y coordinate
	}

	return compressed
}

func (n *internalNode) ComputeCommitment(ks *kzg.KZGSettings) *bls.G1Point {
	var poly [InternalNodeNumChildren]bls.Fr
	for idx, childC := range n.children {
		switch child := childC.(type) {
		case empty:
		case *leafNode:
			bls.FrFrom32(&poly[idx], child.Hash())
		default:
			compressed := compressG1Point(childC.ComputeCommitment(ks))
			h := sha256.Sum256(compressed)
			bls.FrFrom32(&poly[idx], h)
		}
	}

	n.commitment = ks.CommitToPoly(poly[:])
	return n.commitment
}

func (n *internalNode) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *internalNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr) {
	childIdx := offset2Key(key, n.depth)
	comms, zis, yis := n.children[childIdx].GetCommitmentsAlongPath(key)
	var zi bls.Fr
	bls.AsFr(&zi, uint64(childIdx))
	var yi bls.Fr
	bls.FrFrom32(&yi, n.children[childIdx].Hash())
	return append(comms, n.GetCommitment()), append(zis, &zi), append(yis, &yi)
}

func (n *internalNode) EvalPathAt(key []byte, at *bls.Fr) []bls.Fr {
	childIdx := offset2Key(key, n.depth)
	depthIdx := 1 + (240-n.depth)/width // index to store the computation result at.
	ret := n.children[childIdx].EvalPathAt(key, at)

	// Apply the barycenter formula to this level
	for i := range n.children {
		var fi, tmp, quotient bls.Fr
		bls.SubModFr(&quotient, at, &omegaInternal[i])
		bls.FrFrom32(&fi, n.children[i].Hash())
		bls.MulModFr(&tmp, &fi, &omegaInternal[i])
		bls.DivModFr(&fi, &tmp, &quotient)

		// Add fᵢ x ret[depthIdx] to accumulator and iterate
		bls.AddModFr(&tmp, &ret[depthIdx], &fi)
		bls.CopyFr(&ret[depthIdx], &tmp)
	}
	return ret
}

func (n *lastLevelNode) Insert(k []byte, value []byte) error {
	// Child index is in the last 6 bits of the key
	nChild := k[31] & 0x3F

	// The child is either a value node, a hashed value
	// or an empty node.
	switch n.children[nChild].(type) {
	case empty, leafNode:
		n.children[nChild] = leafNode{key: k, value: value}
	case hashedNode:
		return errors.New("trying to update a hashed leaf node")
	default:
		return errors.New("inserting into an invalid node type at this level")
	}

	return nil
}

func (n *lastLevelNode) Get(k []byte) ([]byte, error) {
	nChild := k[31] & 0x3F

	switch child := n.children[nChild].(type) {
	case empty:
		return nil, nil
	case hashedNode:
		return nil, errors.New("can not Get value from hash")
	case leafNode:
		return child.Get(k)
	default:
		return nil, errors.New("invalid node type encountered")
	}
}

func (n *lastLevelNode) Hash() common.Hash {
	digest := sha256.New()
	for _, child := range n.children {
		digest.Write(child.Hash().Bytes())
	}

	return common.BytesToHash(digest.Sum(nil))
}

func (n *lastLevelNode) ComputeCommitment(ks *kzg.KZGSettings) *bls.G1Point {
	var poly [64]bls.Fr
	for idx, childC := range n.children {
		// Skip empty commitments
		if _, ok := childC.(empty); ok {
			continue
		}

		// children are leaves, just get their hashes
		bls.FrFrom32(&poly[idx], childC.Hash())
	}

	n.commitment = ks.CommitToPoly(poly[:])
	return n.commitment
}

func (n *lastLevelNode) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *lastLevelNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr) {
	childIdx := offset2Key(key, 240)
	_, zis, _ := n.children[childIdx].GetCommitmentsAlongPath(key)
	var z0 bls.Fr
	bls.AsFr(&z0, uint64(childIdx))
	var y0 bls.Fr
	bls.FrFrom32(&y0, n.children[childIdx].Hash())
	return []*bls.G1Point{n.GetCommitment()}, append(zis, &z0), []*bls.Fr{&y0}
}

func (n *lastLevelNode) EvalPathAt(key []byte, at *bls.Fr) []bls.Fr {
	// Allocate the vector once, to be filled and passed up the tree
	ret := make([]bls.Fr, 26)
	bls.CopyFr(&ret[0], &bls.ZERO)

	// Apply the barycenter formula to this level
	for i := range n.children {
		var fi, tmp, quotient bls.Fr
		bls.SubModFr(&quotient, at, &omega64[i])
		bls.FrFrom32(&fi, n.children[i].Hash())
		bls.MulModFr(&tmp, &fi, &omega64[i])
		bls.DivModFr(&fi, &tmp, &quotient)

		// Add fᵢ x ret[0] to accumulator and iterate
		bls.AddModFr(&tmp, &ret[0], &fi)
		bls.CopyFr(&ret[0], &tmp)
	}
	return ret
}

func (n leafNode) Insert(k []byte, value []byte) error {
	n.key = k
	n.value = value
	return nil
}

func (n leafNode) Get(k []byte) ([]byte, error) {
	return n.value, nil
}

func (n leafNode) ComputeCommitment(*kzg.KZGSettings) *bls.G1Point {
	panic("can't compute the commitment directly")
}

func (n leafNode) GetCommitment() *bls.G1Point {
	panic("can't get the commitment directly")
}

func (n leafNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr) {
	h := n.Hash()
	var hFr bls.Fr
	bls.FrFrom32(&hFr, h)
	return nil, nil, []*bls.Fr{&hFr}
}

func (n leafNode) EvalPathAt([]byte, *bls.Fr) []bls.Fr {
	panic("should not evaluate path at key level")
}

func (n leafNode) Hash() common.Hash {
	digest := sha256.New()
	digest.Write(n.key)
	digest.Write(n.value)
	return common.BytesToHash(digest.Sum(nil))
}
func (n hashedNode) Insert(k []byte, value []byte) error {
	return errInsertIntoHash
}

func (n hashedNode) Get(k []byte) ([]byte, error) {
	return nil, errors.New("can not read from a hash node")
}

func (n hashedNode) Hash() common.Hash {
	return common.Hash(n)
}

func (n hashedNode) ComputeCommitment(*kzg.KZGSettings) *bls.G1Point {
	panic("not implemented yet")
}

func (n hashedNode) GetCommitment() *bls.G1Point {
	var tmp bls.Fr
	var out bls.G1Point
	bls.FrFrom32(&tmp, n)
	bls.MulG1(&out, &bls.GenG1, &tmp)
	return &out
}
func (n hashedNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr) {
	panic("can not get the full path, and there is no proof of absence")
}

func (n hashedNode) EvalPathAt([]byte, *bls.Fr) []bls.Fr {
	panic("can not evaluate path through hash node")
}

func (e empty) Insert(k []byte, value []byte) error {
	return errors.New("hmmmm... a leaf node should not be inserted directly into")
}

func (e empty) Get(k []byte) ([]byte, error) {
	return nil, nil
}

func (e empty) Hash() common.Hash {
	return zeroHash
}

func (e empty) ComputeCommitment(*kzg.KZGSettings) *bls.G1Point {
	return &bls.ZeroG1
}

func (e empty) GetCommitment() *bls.G1Point {
	return &bls.ZeroG1
}

func (e empty) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr) {
	panic("trying to produce a commitment for an empty subtree")
}

func (e empty) EvalPathAt(_ []byte, _ *bls.Fr) []bls.Fr {
	panic("trying to evaluate the polynomial at an empty place")
}
