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

var ErrInvalidNodeEncoding = errors.New("invalid node encoding")

var mask = [8]byte{0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1}

func bit(bitlist []byte, nr int) bool {
	if len(bitlist)*8 <= nr {
		return false
	}
	return bitlist[nr/8]&mask[nr%8] != 0
}

var errSerializedPayloadTooShort = errors.New("verkle payload is too short")

func ParseNode(serialized []byte, depth byte, comm SerializedPointCompressed) (VerkleNode, error) {
	if len(serialized) < 1+StemSize+SerializedPointSize {
		return nil, errSerializedPayloadTooShort
	}
	switch serialized[0] {
	case leafRLPType:
		return parseLeafNode(serialized, depth, comm)
	case internalRLPType:
		return CreateInternalNode(serialized[1:1+NodeWidth/8], serialized[1+NodeWidth/8:], depth, comm)
	default:
		return nil, ErrInvalidNodeEncoding
	}
}

func ParseStatelessNode(serialized []byte, depth byte, comm SerializedPointCompressed) (VerkleNode, error) {
	if len(serialized) < 1+StemSize+SerializedPointSize {
		return nil, errSerializedPayloadTooShort
	}
	switch serialized[0] {
	case leafRLPType:
		return parseLeafNode(serialized, depth, comm)
	case internalRLPType:
		return deserializeIntoStateless(serialized[1:33], serialized[33:], depth, comm)
	default:
		return nil, ErrInvalidNodeEncoding
	}
}

func parseLeafNode(serialized []byte, depth byte, comm SerializedPointCompressed) (VerkleNode, error) {
	var values [NodeWidth][]byte
	offset := 1 + StemSize + 32 + 2*SerializedPointSize
	for i := 0; i < NodeWidth; i++ {
		if bit(serialized[1+StemSize:1+StemSize+32], i) {
			if offset+32 > len(serialized) {
				return nil, fmt.Errorf("verkle payload is too short, need at least %d and only have %d, payload = %x (%w)", offset+32, len(serialized), serialized, errSerializedPayloadTooShort)
			}
			values[i] = serialized[offset : offset+32]
			offset += 32
		}
	}
	if NodeWidth != len(values) {
		return nil, fmt.Errorf("invalid number of nodes in decoded child expected %d, got %d", NodeWidth, len(values))
	}
	ln := NewLeafNodeWithNoComms(serialized[1:1+StemSize], values[:])
	ln.setDepth(depth)
	ln.c1 = new(Point)
	ln.c1.SetBytesUncompressed(serialized[1+StemSize+32:1+StemSize+32+SerializedPointSize], true)
	ln.c2 = new(Point)
	ln.c2.SetBytesUncompressed(serialized[1+StemSize+32+SerializedPointSize:1+StemSize+32+2*SerializedPointSize], true)
	ln.commitment = new(Point)
	ln.commitment.SetBytes(comm, true)
	return ln, nil
}

func deserializeIntoStateless(bitlist []byte, raw []byte, depth byte, comm SerializedPointCompressed) (*StatelessNode, error) {
	// GetTreeConfig caches computation result, hence
	// this op has low overhead
	n := NewStateless()
	n.setDepth(depth)
	indices := indicesFromBitlist(bitlist)
	if len(raw)/SerializedPointSize != len(indices) {
		return nil, ErrInvalidNodeEncoding
	}
	for i, index := range indices {
		n.unresolved[byte(index)] = raw[i*SerializedPointSize : (i+1)*SerializedPointSize]
	}
	n.commitment = new(Point)
	n.commitment.SetBytes(comm, true)
	return n, nil
}

func CreateInternalNode(bitlist []byte, raw []byte, depth byte, comm SerializedPointCompressed) (*InternalNode, error) {
	// GetTreeConfig caches computation result, hence
	// this op has low overhead
	n := (newInternalNode(depth)).(*InternalNode)
	indices := indicesFromBitlist(bitlist)

	if len(raw)/SerializedPointSize != len(indices) {
		return nil, ErrInvalidNodeEncoding
	}

	freelist := make([]HashedNode, len(indices))
	for i, index := range indices {
		freelist[i].serialized = raw[i*SerializedPointSize : (i+1)*SerializedPointSize]
		n.children[index] = &freelist[i]
	}
	n.commitment = new(Point)
	n.commitment.SetBytes(comm, true)
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
