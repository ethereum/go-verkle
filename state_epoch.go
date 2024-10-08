package verkle

import (
	"encoding/binary"
)

type StateEpoch uint64

const (
	NumActiveEpochs = 2
)

func EpochExpired(prev StateEpoch, cur StateEpoch) bool {
	return cur-prev >= NumActiveEpochs
}

// Convert epoch to bytes
func (e StateEpoch) Bytes() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(e))
	return b
}

// Get the state epoch from bytes
func StateEpochFromBytes(b []byte) StateEpoch {
	return StateEpoch(binary.BigEndian.Uint64(b))
}
