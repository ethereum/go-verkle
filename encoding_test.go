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

func TestParseNodeInvalidCount(t *testing.T) {
	_, err := ParseNode([]byte{0xc1, 1}, 0)
	if err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}
