package verkle

import (
	"encoding/binary"
)

type AccessTimestamp uint64

const (
	NumActiveTimestamps = 2
)

func IsExpired(prev AccessTimestamp, cur AccessTimestamp) bool {
	return cur-prev >= NumActiveTimestamps
}

func AccessTimestampFromBytes(b []byte) AccessTimestamp {
	return AccessTimestamp(binary.BigEndian.Uint64(b))
}
