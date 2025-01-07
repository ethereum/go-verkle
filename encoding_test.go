package verkle

import (
	"bytes"
	"encoding/binary"
	"math/big"
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
	leaf, err := NewLeafNode(toolong, make([][]byte, NodeWidth))
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) != nodeTypeSize+StemSize+bitlistSize+3*banderwagon.UncompressedSize {
		t.Fatalf("invalid serialization when the stem is longer than 31 bytes: %x (%d bytes != %d)", ser, len(ser), nodeTypeSize+StemSize+bitlistSize+2*banderwagon.UncompressedSize)
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
	values := make([][]byte, 256)
	values[0] = make([]byte, 32)
	binary.BigEndian.PutUint64(values[0][8:], 64)  // nonce = 64
	copy(values[0][30:], big.NewInt(1337).Bytes()) // balance = 1337
	values[1] = EmptyCodeHash[:]                   // set empty code hash as balance, because why not
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

	if lnd.values[0][0] != 0 {
		t.Fatalf("invalid version, got %x, expected %x", lnd.values[0][0], 0)
	}

	if cs := binary.BigEndian.Uint32(lnd.values[0][4:]); cs != 0 {
		t.Fatalf("invalid code size, got %x, expected %x", cs, 0)
	}

	if nonce := binary.BigEndian.Uint64(lnd.values[0][8:]); nonce != 64 {
		t.Fatalf("invalid nonce, got %x, expected %x", nonce, 64)
	}

	if balance := new(big.Int).SetBytes(lnd.values[0][16:]); balance.Cmp(big.NewInt(1337)) != 0 {
		t.Fatalf("invalid balance, got %x, expected %x", balance, 1337)
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

	if !lnd.c1.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c2.Equal(ln.c2) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}
