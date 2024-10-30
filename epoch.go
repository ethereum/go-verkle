package verkle

import (
	"encoding/binary"
)

type StateEpoch uint16

const (
	NumActiveEpochs = 2
)

func IsExpired(prev StateEpoch, cur StateEpoch) bool {
	return cur-prev >= NumActiveEpochs
}

func StateEpochFromBytes(b []byte) StateEpoch {
	return StateEpoch(binary.BigEndian.Uint16(b))
}
