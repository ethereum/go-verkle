package verkle

import (
	"encoding/binary"
)

type StateEpoch uint64

const (
	NumActiveEpochs = 2
)

func IsExpired(prev StateEpoch, cur StateEpoch) bool {
	return cur-prev >= NumActiveEpochs
}

func StateEpochFromBytes(b []byte) StateEpoch {
	return StateEpoch(binary.BigEndian.Uint64(b))
}
