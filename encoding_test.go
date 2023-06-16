package verkle

import "testing"

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
	leaf, err := NewLeafNode(toolong, make([][]byte, NodeWidth))
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) != nodeTypeSize+StemSize+bitlistSize+2*SerializedPointCompressedSize {
		t.Fatalf("invalid serialization when the stem is longer than 31 bytes: %x (%d bytes)", ser, len(ser))
	}
}

func TestInvalidNodeEncoding(t *testing.T) {
	// Test a short payload.
	if _, err := ParseNode([]byte{leafRLPType}, 0, SerializedPointCompressed{}); err != errSerializedPayloadTooShort {
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
	lnbytes[0] = leafRLPType + internalRLPType // Change the type of the node to something invalid.
	if _, err := ParseNode(lnbytes, 0, SerializedPointCompressed{}); err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}
