package crypto

import (
	"errors"

	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/crate-crypto/go-ipa/banderwagon"
	"github.com/crate-crypto/go-ipa/ipa"
)

type (
	Fr                        = fr.Element
	Point                     = banderwagon.Element
	SerializedPoint           = []byte
	SerializedPointCompressed = []byte
)

const (
	SerializedPointUncompressedSize = 64
)

func CopyFr(dst, src *Fr) {
	copy(dst[:], src[:])
}

func CopyPoint(dst, src *Point) {
	dst.Set(src)
}

func ToFr(fr *Fr, p *Point) {
	p.MapToScalarField(fr)
}

func ToFrMultiple(res []*Fr, ps []*Point) {
	banderwagon.MultiMapToScalarField(res, ps)
}

func FromLEBytes(fr *Fr, data []byte) error {
	if len(data) > 32 {
		return errors.New("data is too long")
	}
	var aligned [32]byte
	copy(aligned[:], data)
	fr.SetBytesLE(aligned[:])
	return nil
}

func FromBytes(fr *Fr, data []byte) {
	var aligned [32]byte
	copy(aligned[32-len(data):], data)
	fr.SetBytes(aligned[:])
}

func Equal(self *Point, other *Point) bool {
	return other.Equal(self)
}

func NewIPASettings() (*ipa.IPAConfig, error) {
	return ipa.NewIPASettings()
}

func ElementsToBytesUncompressed(elements []*Point) [][SerializedPointUncompressedSize]byte {
	return banderwagon.ElementsToBytesUncompressed(elements)
}
