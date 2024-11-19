package verkle

import (
	"encoding/binary"
)

type StatePeriod uint16

const (
	NumActiveEpochs = 2
)

func IsExpired(prev StatePeriod, cur StatePeriod) bool {
	return cur-prev >= NumActiveEpochs
}

func StatePeriodFromBytes(b []byte) StatePeriod {
	return StatePeriod(binary.BigEndian.Uint16(b))
}
