package verkle

import (
	"encoding/binary"
)

type StatePeriod uint16

const (
	NumActiveEpochs = 2
)

func IsExpired(prev, cur StatePeriod) bool {
	return cur > prev && cur - prev >= NumActiveEpochs // TODO(weiihann): deal with overflow
}

func StatePeriodFromBytes(b []byte) StatePeriod {
	return StatePeriod(binary.BigEndian.Uint16(b))
}
