package verkle

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const ErrInvalidNodeEncoding = "invalid node encoding"

func ParseNode(serialized []byte, tc *TreeConfig) (VerkleNode, error) {
	elems, _, err := rlp.SplitList(serialized)
	if err != nil {
		return nil, err
	}
	c, err := rlp.CountValues(elems)
	if err != nil {
		return nil, err
	}

	if c == 1 {
		// HashedNode
		hash, _, err := rlp.SplitString(elems)
		if err != nil {
			return nil, err
		}
		return &HashedNode{hash: common.BytesToHash(hash)}, nil
	} else if c == 2 {
		// either leaf or internal
		kind, first, rest, err := rlp.Split(elems)
		if err != nil {
			return nil, err
		}
		if kind != rlp.String {
			return nil, errors.New(ErrInvalidNodeEncoding)
		}

		if len(first) == 32 {
			// leaf
			value, _, err := rlp.SplitString(rest)
			if err != nil {
				return nil, err
			}
			return &LeafNode{key: first, value: value}, nil
		} else if len(first) == 128 {
			// internal
			children, _, err := rlp.SplitString(rest)
			if err != nil {
				return nil, err
			}
			return createInternalNode(first, children, tc)
		} else {
			return nil, errors.New(ErrInvalidNodeEncoding)
		}
	} else {
		return nil, errors.New(ErrInvalidNodeEncoding)
	}
}

func createInternalNode(bitlist []byte, raw []byte, tc *TreeConfig) (*InternalNode, error) {
	// TODO: fix depth
	n := (newInternalNode(0, tc)).(*InternalNode)
	indices := indicesFromBitlist(bitlist)
	if len(raw)/32 != len(indices) {
		return nil, errors.New(ErrInvalidNodeEncoding)
	}
	for i, index := range indices {
		n.children[index] = &HashedNode{hash: common.BytesToHash(raw[i*32 : (i+1)*32])}
	}
	return n, nil
}

func indicesFromBitlist(bitlist []byte) []int {
	indices := make([]int, 0)
	for i, b := range bitlist {
		if b&0xff == 0x00 {
			continue
		}
		for j := 0; j < 8; j++ {
			mask := byte(1 << j)
			if b&mask == mask {
				index := i*8 + j
				indices = append(indices, index)
			}
		}
	}
	return indices
}
