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

// +build kzg

package verkle

import (
	"crypto/sha256"

	"github.com/protolambda/go-kzg/bls"
)

type Fr = bls.Fr
type Point = bls.G1Point

func CopyFr(dst, src *Fr) {
	bls.CopyFr(dst, src)
}

func CopyPoint(dst, src *Point) {
	bls.CopyG1(dst, src)
}

func toFr(fr *Fr, p *Point) {
	h := sha256.Sum256(bls.ToCompressedG1(p))
	hashToFr(fr, h[:])
}

var FrZero = bls.ZERO
var FrOne = bls.ONE

func fromBytes(fr *Fr, data []byte) {
	if len(data) > 32 {
		panic("invalid length")
	}

	if len(data) == 32 {
		hashToFr(fr, data)
		return
	}

	var tmp [32]byte
	copy(tmp[32-len(data):], data)
	hashToFr(fr, tmp)
}
