package verkle

import (
	"bytes"
	"testing"

	"github.com/crate-crypto/go-ipa/banderwagon"
)

func TestParseNodeEmptyPayload(t *testing.T) {
	_, err := ParseNode([]byte{}, 0, SerializedPointCompressed{})
	if err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, "unexpected EOF")
	}
}

func TestLeafStemLength(t *testing.T) {
	// Serialize a leaf with no values, but whose stem is 32 bytes. The
	// serialization should trim the extra byte.
	toolong := make([]byte, 32)
	leaf := NewLeafNode(toolong, make([][]byte, NodeWidth))
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) != nodeTypeSize+StemSize+bitlistSize+2*SerializedPointCompressedSize {
		t.Fatalf("invalid serialization when the stem is longer than 31 bytes: %x (%d bytes)", ser, len(ser))
	}
}

func TestParseNodeEoA(t *testing.T) {
	values := make([][]byte, 256)
	values[0] = zero32[:]
	values[1] = emptyCodeHash[:] // set empty code hash as balance, because why not
	values[2] = fourtyKeyTest[:] // set nonce to 64
	values[3] = emptyCodeHash[:] // set empty code hash
	values[4] = zero32[:]        // zero-size
	ln := NewLeafNode(ffx32KeyTest[:31], values)

	commBytes := ln.commitment.Bytes()

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != eoAccountType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], eoAccountType)
	}

	t.Log(serialized)
	deserialized, err := ParseNode(serialized, 5, commBytes[:])
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

	if !bytes.Equal(lnd.values[0], zero32[:]) {
		t.Fatalf("invalid version, got %x, expected %x", lnd.values[0], zero32[:])
	}

	if !bytes.Equal(lnd.values[1], emptyCodeHash[:]) {
		t.Fatalf("invalid balance, got %x, expected %x", lnd.values[1], emptyCodeHash[:])
	}

	if !bytes.Equal(lnd.values[2], fourtyKeyTest[:]) {
		t.Fatalf("invalid nonce, got %x, expected %x", lnd.values[2], fourtyKeyTest[:])
	}

	if !bytes.Equal(lnd.values[3], emptyCodeHash[:]) {
		t.Fatalf("invalid code hash, got %x, expected %x", lnd.values[3], emptyCodeHash[:])
	}

	if !bytes.Equal(lnd.values[4], zero32[:]) {
		t.Fatalf("invalid code size, got %x, expected %x", lnd.values[4], zero32[:])
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
