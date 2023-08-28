package verkle

import (
	"encoding/binary"
	"math/big"
	"testing"
)

func TestFromBytes(t *testing.T) {
	t.Parallel()

	var fr Fr

	var beFortyTwo [8]byte
	binary.BigEndian.PutUint64(beFortyTwo[:], 42)

	FromBytes(&fr, beFortyTwo[:])

	bi := big.NewInt(0)
	if fr.ToBigIntRegular(bi).Int64() != 42 {
		t.Fatalf("got %v, want 42", bi)
	}

}
