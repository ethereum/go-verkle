package verkle

import (
	"encoding/binary"
)

type StatePeriod uint16

const (
	NumActiveEpochs = 2
	period0 = 0
)

func IsExpired(prev, cur StatePeriod) bool {
	return cur > prev && cur - prev >= NumActiveEpochs
}

func StatePeriodFromBytes(b []byte) StatePeriod {
	return StatePeriod(binary.BigEndian.Uint16(b))
}
