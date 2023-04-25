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

var (
	ErrInvalidNodeEncoding = errors.New("invalid node encoding")

	mask = [8]byte{0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1}
)

const (
	nodeTypeSize = 1
	bitlistSize  = NodeWidth / 8

	// Shared between internal and leaf nodes.
	nodeTypeOffset = 0

	// Internal nodes offsets.
	internalBitlistOffset      = nodeTypeOffset + nodeTypeSize
	internalNodeChildrenOffset = internalBitlistOffset + bitlistSize

	// Leaf node offsets.
	leafSteamOffset        = nodeTypeOffset + nodeTypeSize
	leafBitlistOffset      = leafSteamOffset + StemSize
	leafC1CommitmentOffset = leafBitlistOffset + bitlistSize
	leafC2CommitmentOffset = leafC1CommitmentOffset + SerializedPointCompressedSize
	leafChildrenOffset     = leafC2CommitmentOffset + SerializedPointCompressedSize
)

func bit(bitlist []byte, nr int) bool {
	if len(bitlist)*8 <= nr {
		return false
	}
	return bitlist[nr/8]&mask[nr%8] != 0
}

var errSerializedPayloadTooShort = errors.New("verkle payload is too short")

// ParseNode deserializes a node into its proper VerkleNode instance.
// The serialized bytes have the format:
// - Internal nodes: <nodeType><bitlist><children...>
// - Leaf nodes:     <nodeType><stem><bitlist><c1comm><c2comm><children...>
func ParseNode(serializedNode []byte, depth byte, comm SerializedPointCompressed) (VerkleNode, error) {
	// Check that the length of the serialized node is at least the smallest possible serialized node.
	if len(serializedNode) < nodeTypeSize+bitlistSize {
		return nil, errSerializedPayloadTooShort
	}

	switch serializedNode[0] {
	case leafRLPType:
		return parseLeafNode(serializedNode, depth, comm)
	case internalRLPType:
		bitlist := serializedNode[internalBitlistOffset : internalBitlistOffset+bitlistSize]
		children := serializedNode[internalNodeChildrenOffset:]
		return CreateInternalNode(bitlist, children, depth, comm)
	default:
		return nil, ErrInvalidNodeEncoding
	}
}

func parseLeafNode(serialized []byte, depth byte, comm SerializedPointCompressed) (VerkleNode, error) {
	bitlist := serialized[leafBitlistOffset : leafBitlistOffset+bitlistSize]
	var values [NodeWidth][]byte
	offset := leafChildrenOffset
	for i := 0; i < NodeWidth; i++ {
		if bit(bitlist, i) {
			if offset+LeafValueSize > len(serialized) {
				return nil, fmt.Errorf("verkle payload is too short, need at least %d and only have %d, payload = %x (%w)", offset+32, len(serialized), serialized, errSerializedPayloadTooShort)
			}
			values[i] = serialized[offset : offset+LeafValueSize]
			offset += LeafValueSize
		}
	}
	ln := NewLeafNodeWithNoComms(serialized[leafSteamOffset:leafSteamOffset+StemSize], values[:])
	ln.setDepth(depth)
	ln.c1 = new(Point)
	ln.c1.SetBytesTrusted(serialized[leafC1CommitmentOffset : leafC1CommitmentOffset+SerializedPointCompressedSize])
	ln.c2 = new(Point)
	ln.c2.SetBytesTrusted(serialized[leafC2CommitmentOffset : leafC2CommitmentOffset+SerializedPointCompressedSize])
	ln.commitment = new(Point)
	ln.commitment.SetBytesTrusted(comm)
	return ln, nil
}

func CreateInternalNode(bitlist []byte, raw []byte, depth byte, comm SerializedPointCompressed) (*InternalNode, error) {
	// GetTreeConfig caches computation result, hence
	// this op has low overhead
	n := (newInternalNode(depth)).(*InternalNode)
	indices := indicesFromBitlist(bitlist)

	if len(raw)/SerializedPointCompressedSize != len(indices) {
		return nil, ErrInvalidNodeEncoding
	}

	freelist := make([]HashedNode, len(indices))
	for i, index := range indices {
		freelist[i].commitment = raw[i*SerializedPointCompressedSize : (i+1)*SerializedPointCompressedSize]
		n.children[index] = &freelist[i]
	}
	n.commitment = new(Point)
	n.commitment.SetBytesTrusted(comm)
	return n, nil
}

func indicesFromBitlist(bitlist []byte) []int {
	indices := make([]int, 0, 32)
	for i, b := range bitlist {
		if b == 0 {
			continue
		}
		// the bitmap is little-endian, inside a big-endian byte list
		for j := 0; j < 8; j++ {
			if b&mask[j] != 0 {
				indices = append(indices, i*8+j)
			}
		}
	}
	return indices
}
