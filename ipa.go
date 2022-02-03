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
	"github.com/crate-crypto/go-ipa/bandersnatch"
	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
)

type Fr = fr.Element
type Point = bandersnatch.PointAffine

func CopyFr(dst, src *Fr) {
	copy(dst[:], src[:])
}

func CopyPoint(dst, src *Point) {
	bytes := src.Bytes()
	dst.SetBytes(bytes[:])
}

func toFr(fr *Fr, p *Point) {
	bytes := p.Bytes()
	fr.SetBytesLE(bytes[:])
}

func from32(fr *Fr, data [32]byte) {
	fr.SetBytes(data[:])
}

func FromLEBytes(fr *Fr, data []byte) {
	var aligned [32]byte
	for i := range data {
		aligned[31-i] = data[i]
	}
	fr.SetBytes(aligned[:])
}

func FromBytes(fr *Fr, data []byte) {
	FromLEBytes(fr, data)
}

func Equal(fr *Fr, other *Fr) bool {
	return fr.Equal(other)
}

func Generator() *Point {
	return new(Point).Identity()
}
