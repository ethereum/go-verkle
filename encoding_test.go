package verkle

import (
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
)

func TestParseNodeEmptyRLP(t *testing.T) {
	_, err := ParseNode([]byte{}, 0)
	if err.Error() != "unexpected EOF" {
		t.Fatalf("invalid error, got %v, expected %v", err, "unexpected EOF")
	}
}

func TestParseNodeNoListType(t *testing.T) {
	_, err := ParseNode([]byte{0x80}, 0)
	if err != rlp.ErrExpectedList {
		t.Fatalf("invalid error, got %v, expected %v", err, rlp.ErrExpectedList)
	}
}

func TestParseNodeTruncatedRLP(t *testing.T) {
	_, err := ParseNode([]byte{0xc1, 0x81, 255, 0x80, 0x80}, 0)
	if err != rlp.ErrValueTooLarge {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}

func TestParseNodeInvalidCount(t *testing.T) {
	_, err := ParseNode([]byte{0xc1, 1}, 0)
	if err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}

func TestParseNodeInvalidType(t *testing.T) {
	_, err := ParseNode([]byte{0xc5, 0x82, 129, 129, 0x80, 0x80}, 0)
	if err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}

func TestParseNodeInvalidLeafValuesList(t *testing.T) {
	_, err := ParseNode([]byte{0xc6, 2, 0x80, 0x83, 1, 2, 3}, 0)
	if err.Error() != "rlp: expected input list for [][]uint8" {
		t.Fatalf("invalid error, got %v, expected 'rlp: expected input list for [][]uint8'", err)
	}
}

func TestParseNodeInvalidLeafValuesLength(t *testing.T) {
	_, err := ParseNode([]byte{0xc6, 2, 0x80, 0xc3, 1, 2, 3}, 0)
	if err.Error() != "invalid number of nodes in decoded child expected 256, got 3" {
		t.Fatalf("invalid error, got %v, expected 'invalid number of nodes in decoded child expected 256, got 3'", err)
	}
}
