package verkle

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/crate-crypto/go-ipa/banderwagon"
)

func TestParseNodeEmptyPayload(t *testing.T) {
	t.Parallel()

	_, err := ParseNode([]byte{}, 0)
	if err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, "unexpected EOF")
	}
}

func TestLeafStemLength(t *testing.T) {
	t.Parallel()

	// Serialize a leaf with no values, but whose stem is 32 bytes. The
	// serialization should trim the extra byte.
	toolong := make([]byte, 32)
	values := make([][]byte, NodeWidth)
	values[42] = zero32[:]
	leaf, err := NewLeafNode(toolong, values)
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) != singleSlotLeafSize {
		t.Fatalf("invalid serialization when the stem is longer than 31 bytes: %x (%d bytes != %d)", ser, len(ser), singleSlotLeafSize)
	}
}

func TestInvalidNodeEncoding(t *testing.T) {
	t.Parallel()

	// Test a short payload.
	if _, err := ParseNode([]byte{leafType}, 0); err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, errSerializedPayloadTooShort)
	}

	// Test an invalid node type.
	values := make([][]byte, NodeWidth)
	values[42] = testValue
	ln, err := NewLeafNode(ffx32KeyTest, values)
	if err != nil {
		t.Fatal(err)
	}
	lnbytes, err := ln.Serialize()
	if err != nil {
		t.Fatalf("serializing leaf node: %v", err)
	}
	lnbytes[0] = 0xc0 // Change the type of the node to something invalid.
	if _, err := ParseNode(lnbytes, 0); err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}

func TestParseNodeEoA(t *testing.T) {
	var basicdata [32]byte
	values := make([][]byte, 256)
	values[0] = basicdata[:]
	binary.BigEndian.PutUint64(values[0][8:], 0xde)
	values[1] = EmptyCodeHash[:] // set empty code hash as balance, because why not
	ln, err := NewLeafNode(ffx32KeyTest[:31], values)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != eoAccountType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], eoAccountType)
	}

	deserialized, err := ParseNode(serialized, 5)
	if err != nil {
		t.Fatalf("error deserializing leaf node: %v", err)
	}

	lnd, ok := deserialized.(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", deserialized)
	}

	if lnd.depth != 5 {
		t.Fatalf("invalid depth, got %d, expected %d", lnd.depth, 5)
	}

	if !bytes.Equal(lnd.stem, ffx32KeyTest[:31]) {
		t.Fatalf("invalid stem, got %x, expected %x", lnd.stem, ffx32KeyTest[:31])
	}

	nonce := binary.BigEndian.Uint64(lnd.values[0][8:])
	if nonce != 0xde {
		t.Fatalf("invalid version, got %x, expected %x", nonce, 0xde)
	}

	if !bytes.Equal(lnd.values[1], EmptyCodeHash[:]) {
		t.Fatalf("invalid balance, got %x, expected %x", lnd.values[1], EmptyCodeHash[:])
	}

	if !lnd.c2.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c1.Equal(ln.c1) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}
func TestParseNodeSingleSlot(t *testing.T) {
	values := make([][]byte, 256)
	values[153] = EmptyCodeHash
	ln, err := NewLeafNode(ffx32KeyTest[:31], values)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != singleSlotType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], singleSlotType)
	}

	deserialized, err := ParseNode(serialized, 5)
	if err != nil {
		t.Fatalf("error deserializing leaf node: %v", err)
	}

	lnd, ok := deserialized.(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", deserialized)
	}

	if lnd.depth != 5 {
		t.Fatalf("invalid depth, got %d, expected %d", lnd.depth, 5)
	}

	if !bytes.Equal(lnd.stem, ffx32KeyTest[:31]) {
		t.Fatalf("invalid stem, got %x, expected %x", lnd.stem, ffx32KeyTest[:31])
	}

	for i := range values {
		if i != 153 {
			if lnd.values[i] != nil {
				t.Fatalf("value %d, got %x, expected empty slot", i, lnd.values[i])
			}
		} else {
			if !bytes.Equal(lnd.values[i], EmptyCodeHash[:]) {
				t.Fatalf("got %x, expected empty slot", lnd.values[i])
			}
		}
	}

	if !lnd.c2.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c1.Equal(ln.c1) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}

func TestSerializeWithSkipLists(t *testing.T) {
	t.Parallel()

	values := make([][]byte, NodeWidth)
	values[42] = zero32[:]
	values[57] = fourtyKeyTest[:]
	leaf, err := NewLeafNode(ffx32KeyTest, values)
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) == 0 {
		t.Fatal("empty serialization buffer")
	}
	if ser[0] != skipListType {
		t.Fatalf("invalid serialization type, got %d, expected %d", ser[0], skipListType)
	}
	if !bytes.Equal(ser[1:32], ffx32KeyTest[:31]) {
		t.Fatalf("stem didn't serialize properly, got %x, want %x", ser[1:32], ffx32KeyTest[:31])
	}
	expectedSize := nodeTypeSize + StemSize + 3*banderwagon.UncompressedSize + 4 + 2*leafSlotSize
	if len(ser) != expectedSize {
		t.Fatalf("invalid skiplist serialization: %x (%d bytes != %d)", ser, len(ser), expectedSize)
	}
	if ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize] != 42 {
		t.Fatalf("invalid amount of leaves skipped, got %d, want %d", ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize], 42)
	}
	if ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+1] != 1 {
		t.Fatalf("invalid amount of leaves skipped, got %d, want %d", ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+1], 42)
	}
	if ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+2+leafSlotSize] != 14 {
		t.Fatalf("invalid amount of leaves skipped, got %d, want %d", ser[nodeTypeSize+StemSize+3*banderwagon.UncompressedSize+2+leafSlotSize], 14)
	}

	// add a last value to check that the final gap is properly handled
	values[255] = ffx32KeyTest
	ser, err = leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	expectedSize = nodeTypeSize + StemSize + 3*banderwagon.UncompressedSize + 6 + 3*leafSlotSize
	if len(ser) != expectedSize {
		t.Fatalf("invalid skiplist serialization: %x (%d bytes != %d)", ser, len(ser), expectedSize)
	}

	deser, err := ParseNode(ser, 5)
	if err != nil {
		t.Fatal(err)
	}
	vals := deser.(*LeafNode).values
	for i, val := range vals {

		switch i {
		case 42:
			if !bytes.Equal(val, zero32[:]) {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want %x", i, val, zero32)
			}
		case 57:
			if !bytes.Equal(val, fourtyKeyTest[:]) {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want %x", i, val, fourtyKeyTest)
			}
		case 255:
			if !bytes.Equal(val, ffx32KeyTest[:]) {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want %x", i, val, ffx32KeyTest)
			}
		default:
			if val != nil {
				t.Fatalf("invalid deserialized skiplist value at %d: got %x, want nil", i, val)
			}
		}
	}
}
