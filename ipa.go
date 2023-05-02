// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

package verkle

import (
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/crate-crypto/go-ipa/banderwagon"
)

type (
	Fr                        = fr.Element
	Point                     = banderwagon.Element
	SerializedPoint           = []byte
	SerializedPointCompressed = []byte
)

const (
	SerializedPointCompressedSize = 32
)

func CopyFr(dst, src *Fr) {
	copy(dst[:], src[:])
}

func CopyPoint(dst, src *Point) {
	dst.Set(src)
}

func toFr(fr *Fr, p *Point) {
	p.MapToScalarField(fr)
}

func toFrMultiple(res []*Fr, ps []*Point) {
	banderwagon.MultiMapToScalarField(res, ps)
}

func FromLEBytes(fr *Fr, data []byte) {
	if len(data) > 32 {
		panic("data is too long")
	}
	var aligned [32]byte
	copy(aligned[:], data)
	fr.SetBytesLE(aligned[:])
}

func StemFromBytes(fr *Fr, data []byte) {
	if len(data) != StemSize {
		panic("data length must be StemSize")
	}
	FromLEBytes(fr, data)
}

func FromBytes(fr *Fr, data []byte) {
	var aligned [32]byte
	copy(aligned[32-len(data):], data)
	fr.SetBytes(aligned[:])
}

func Equal(self *Point, other *Point) bool {
	return other.Equal(self)
}
