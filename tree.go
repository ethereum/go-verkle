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
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

type VerkleNode interface {
	// Insert or Update value `v` at key `k`
	Insert(k []byte, v []byte) error

	// Insert "à la" Stacktrie. Same thing as insert, except that
	// values are expected to be ordered, and the commitments and
	// hashes for each subtrie are computed online, as soon as it
	// is clear that no more values will be inserted in there.
	InsertOrdered([]byte, []byte, *kzg.KZGSettings, []bls.G1Point) error

	// Get value at key `k`
	Get(k []byte) ([]byte, error)

	// Hash of the current node
	Hash() common.Hash

	// ComputeCommitment computes the commitment of the node
	ComputeCommitment(*kzg.KZGSettings, []bls.G1Point) *bls.G1Point

	// GetCommitment retrieves the (previously computed)
	// commitment of a node.
	GetCommitment() *bls.G1Point

	// GetCommitmentAlongPath follows the path that one key
	// traces through the tree, and collects the various
	// elements needed to build a proof. The order of elements
	// is from the bottom of the tree, up to the root.
	GetCommitmentsAlongPath([]byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr)
}

const (
	// number of key bits spanned by a node
	width = 10

	// Number of children in an internal node
	nodeWidth = 1 << width

	// Threshold for using multi exponentiation when
	// computing commitment. Number refers to non-zero
	// children in a node.
	multiExpThreshold = 110
)

var (
	errInsertIntoHash  = errors.New("trying to insert into hashed node")
	errValueNotPresent = errors.New("value not present in tree")

	zeroHash = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000000")
)

type (
	// Represents an internal node at any level except
	// the bottom one, with 1024 children.
	internalNode struct {
		// List of child nodes of this internal node.
		children [nodeWidth]VerkleNode

		// node depth in the tree, in bits
		depth uint

		// Cache the hash of the current node
		hash common.Hash

		// Cache the commitment value
		commitment *bls.G1Point
	}

	hashedNode struct {
		hash       common.Hash
		commitment *bls.G1Point
	}

	leafNode struct {
		key   []byte
		value []byte
	}

	empty struct{}
)

var modulus *big.Int		// Field's modulus
var omegaIs [nodeWidth]bls.Fr	// List of the root of unity
var inverses [nodeWidth]bls.Fr	// List of all 1 / (1 - ωⁱ)
var nodeWidthInversed bls.Fr	// Inverse of node witdh in prime field

func init() {
	// Calculate the lagrangian evaluation basis.
	var tmp bls.Fr
	bls.CopyFr(&tmp, &bls.ONE)
	for i := 0; i < nodeWidth; i++ {
		bls.CopyFr(&omegaIs[i], &tmp)
		bls.MulModFr(&tmp, &tmp, &bls.Scale2RootOfUnity[10])
	}

	var ok bool
	modulus, ok = big.NewInt(0).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	if !ok {
		panic("could not get modulus")
	}

	// Compute all 1 / (1 - ωⁱ)
	bls.CopyFr(&inverses[0], &bls.ZERO)
	for i := 1; i < nodeWidth; i++ {
		var tmp bls.Fr
		bls.SubModFr(&tmp, &bls.ONE, &omegaIs[i])
		bls.DivModFr(&inverses[i], &bls.ONE, &tmp)
	}

	bls.AsFr(&nodeWidthInversed, nodeWidth)
	bls.InvModFr(&nodeWidthInversed, &nodeWidthInversed)
}

func newInternalNode(depth uint) VerkleNode {
	node := new(internalNode)
	for idx := range node.children {
		node.children[idx] = empty(struct{}{})
	}
	node.depth = depth
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
	ret := (uint(key[nFirstByte]^leftMask) << ((nBitsInSecondByte-1)%8 + 1))
	if int(nFirstByte)+1 < len(key) {
		ret |= uint(key[nFirstByte+1] >> lastBitShift)
	}
	return ret
}

func (n *internalNode) Insert(key []byte, value []byte) error {
	nChild := offset2Key(key, n.depth)

	switch child := n.children[nChild].(type) {
	case empty:
		n.children[nChild] = &leafNode{key: key, value: value}
	case *hashedNode:
		return errInsertIntoHash
	case *leafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if bytes.Equal(child.key, key) {
			child.value = value
		} else {
			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := offset2Key(child.key, n.depth+width)
			newBranch := newInternalNode(n.depth + width).(*internalNode)
			n.children[nChild] = newBranch
			newBranch.children[nextWordInExistingKey] = child

			nextWordInInsertedKey := offset2Key(key, n.depth+width)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				newBranch.children[nextWordInInsertedKey] = &leafNode{key: key, value: value}
			} else {
				newBranch.Insert(key, value)
			}
		}
	default: // internalNode
		return child.Insert(key, value)
	}
	return nil
}

func (n *internalNode) InsertOrdered(key []byte, value []byte, ks *kzg.KZGSettings, lg1 []bls.G1Point) error {
	nChild := offset2Key(key, n.depth)

	switch child := n.children[nChild].(type) {
	case empty:
		// Insert into a new subtrie, which means that the
		// subtree directly preceding this new one, can
		// safely be calculated.
		for i := int(nChild) - 1; i >= 0; i-- {
			switch n.children[i].(type) {
			case empty:
				continue
			case *leafNode:
				n.children[i] = &hashedNode{hash: n.children[i].Hash()}
				break
			case *hashedNode:
				break
			default:
				comm := n.children[i].ComputeCommitment(ks, lg1)
				h := sha256.Sum256(bls.ToCompressedG1(comm))
				n.children[i] = &hashedNode{hash: h, commitment: comm}
				break
			}
		}

		n.children[nChild] = &leafNode{key: key, value: value}
	case *hashedNode:
		return errInsertIntoHash
	case *leafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if bytes.Equal(child.key, key) {
			child.value = value
		} else {
			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := offset2Key(child.key, n.depth+width)
			newBranch := newInternalNode(n.depth + width).(*internalNode)
			n.children[nChild] = newBranch

			nextWordInInsertedKey := offset2Key(key, n.depth+width)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Directly hash the (left) node that was already
				// inserted.
				h := child.Hash()
				comm := new(bls.G1Point)
				var tmp bls.Fr
				hashToFr(&tmp, h)
				bls.MulG1(comm, &bls.GenG1, &tmp)
				newBranch.children[nextWordInExistingKey] = &hashedNode{hash: h, commitment: comm}
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				newBranch.children[nextWordInInsertedKey] = &leafNode{key: key, value: value}
			} else {
				// Reinsert the leaf in order to recurse
				newBranch.children[nextWordInExistingKey] = child
				newBranch.InsertOrdered(key, value, ks, lg1)
			}
		}
	default: // internalNode
		return child.InsertOrdered(key, value, ks, lg1)
	}
	return nil
}

func (n *internalNode) Get(k []byte) ([]byte, error) {
	nChild := offset2Key(k, n.depth)

	switch child := n.children[nChild].(type) {
	case empty, *hashedNode, nil:
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

// This function takes a hash and turns it into a bls.Fr integer, making
// sure that this doesn't overflow the modulus.
// This piece of code is really ugly, and probably a performance hog, it
// needs to be rewritten more efficiently.
func hashToFr(out *bls.Fr, h [32]byte) {
	var h2 [32]byte
	// reverse endianness
	for i := range h {
		h2[i] = h[len(h)-i-1]
	}

	// Apply modulus
	x := big.NewInt(0).SetBytes(h2[:])
	x.Mod(x, modulus)

	// clear the buffer in case the trailing bytes were 0
	for i := 0; i < 32; i++ {
		h2[i] = 0
	}
	copy(h2[32-len(x.Bytes()):], x.Bytes())

	// back to original endianness
	for i := range h2 {
		h[i] = h2[len(h)-i-1]
	}

	if !bls.FrFrom32(out, h) {
		panic(fmt.Sprintf("invalid Fr number %x", h))
	}
}

func (n *internalNode) ComputeCommitment(ks *kzg.KZGSettings, lg1 []bls.G1Point) *bls.G1Point {
	if n.commitment != nil {
		return n.commitment
	}

	emptyChildren := 0
	var poly [nodeWidth]bls.Fr
	for idx, childC := range n.children {
		switch child := childC.(type) {
		case empty:
			emptyChildren++
		case *leafNode, *hashedNode:
			hashToFr(&poly[idx], child.Hash())
		default:
			compressed := bls.ToCompressedG1(childC.ComputeCommitment(ks, lg1))
			hashToFr(&poly[idx], sha256.Sum256(compressed))
		}
	}

	var commP *bls.G1Point
	if nodeWidth-emptyChildren >= multiExpThreshold {
		commP = bls.LinCombG1(lg1, poly[:])
	} else {
		var comm bls.G1Point
		bls.CopyG1(&comm, &bls.ZERO_G1)
		for i := range poly {
			if !bls.EqualZero(&poly[i]) {
				var tmpG1, eval bls.G1Point
				bls.MulG1(&eval, &lg1[i], &poly[i])
				bls.CopyG1(&tmpG1, &comm)
				bls.AddG1(&comm, &tmpG1, &eval)
			}
		}
		commP = &comm
	}
	n.commitment = commP
	return n.commitment
}

func (n *internalNode) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *internalNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	childIdx := offset2Key(key, n.depth)
	comms, zis, yis, fis := n.children[childIdx].GetCommitmentsAlongPath(key)
	var zi, yi bls.Fr
	bls.AsFr(&zi, uint64(childIdx))
	var fi [nodeWidth]bls.Fr
	for i, child := range n.children {
		hashToFr(&fi[i], child.Hash())
		if i == int(childIdx) {
			bls.CopyFr(&yi, &fi[i])
		}
	}
	return append(comms, n.GetCommitment()), append(zis, &zi), append(yis, &yi), append(fis, fi[:])
}

func (n *leafNode) Insert(k []byte, value []byte) error {
	n.key = k
	n.value = value
	return nil
}

func (n *leafNode) InsertOrdered(key []byte, value []byte, ks *kzg.KZGSettings, lg1 []bls.G1Point) error {
	return n.Insert(key, value)
}

func (n *leafNode) Get(k []byte) ([]byte, error) {
	if !bytes.Equal(k, n.key) {
		return nil, errValueNotPresent
	}
	return n.value, nil
}

func (n *leafNode) ComputeCommitment(*kzg.KZGSettings, []bls.G1Point) *bls.G1Point {
	panic("can't compute the commitment directly")
}

func (n *leafNode) GetCommitment() *bls.G1Point {
	panic("can't get the commitment directly")
}

func (n *leafNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	return nil, nil, nil, nil
}

func (n *leafNode) Hash() common.Hash {
	digest := sha256.New()
	digest.Write(n.key)
	digest.Write(n.value)
	return common.BytesToHash(digest.Sum(nil))
}

func (n *hashedNode) Insert(k []byte, value []byte) error {
	return errInsertIntoHash
}

func (n *hashedNode) InsertOrdered(key []byte, value []byte, ks *kzg.KZGSettings, lg1 []bls.G1Point) error {
	return errInsertIntoHash
}

func (n *hashedNode) Get(k []byte) ([]byte, error) {
	return nil, errors.New("can not read from a hash node")
}

func (n *hashedNode) Hash() common.Hash {
	return n.hash
}

func (n *hashedNode) ComputeCommitment(*kzg.KZGSettings, []bls.G1Point) *bls.G1Point {
	if n.commitment == nil {
		var hashAsFr bls.Fr
		hashToFr(&hashAsFr, n.hash)
		n.commitment = new(bls.G1Point)
		bls.MulG1(n.commitment, &bls.GenG1, &hashAsFr)
	}
	return n.commitment
}

func (n *hashedNode) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *hashedNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	panic("can not get the full path, and there is no proof of absence")
}

func (e empty) Insert(k []byte, value []byte) error {
	return errors.New("hmmmm... a leaf node should not be inserted directly into")
}

func (e empty) InsertOrdered(key []byte, value []byte, ks *kzg.KZGSettings, lg1 []bls.G1Point) error {
	return e.Insert(key, value)
}

func (e empty) Get(k []byte) ([]byte, error) {
	return nil, nil
}

func (e empty) Hash() common.Hash {
	return zeroHash
}

func (e empty) ComputeCommitment(*kzg.KZGSettings, []bls.G1Point) *bls.G1Point {
	return &bls.ZeroG1
}

func (e empty) GetCommitment() *bls.G1Point {
	return &bls.ZeroG1
}

func (e empty) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	panic("trying to produce a commitment for an empty subtree")
}
