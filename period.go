package verkle

import (
	"encoding/binary"
)

type StatePeriod uint16

const (
	NumActiveEpochs = 2
	period0 = StatePeriod(0)
	period1 = StatePeriod(1)
	period2 = StatePeriod(2)
)

func IsExpired(prev, cur StatePeriod) bool {
	return cur > prev && cur - prev >= NumActiveEpochs
}

func StatePeriodFromBytes(b []byte) StatePeriod {
	return StatePeriod(binary.BigEndian.Uint16(b))
}
