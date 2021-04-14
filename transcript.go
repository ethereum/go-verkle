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
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg/bls"
)

/// The transcript is used to create challenge scalars.
/// See: Fiat-Shamir
/// XXX: ideally, this should also contain labels, however this is not included in the python implementation
// and we first want this different API to pass without modifying the tests.
type Transcript struct {
	state []byte
}

// Appends a Bls Scalar to the transcript
//
// Converts the scalar to 32 bytes, then appends it to
// the state
func (t *Transcript) AppendScalar(scalar *bls.Fr) {
	tmpBytes := bls.FrTo32(scalar)
	t.appendBytes(tmpBytes[:])
}
func (t *Transcript) AppendScalars(scalars []*bls.Fr) {
	for _, idx := range scalars {
		t.AppendScalar(idx)
	}
}

// Appends a G1 Point to the transcript
//
// Compresses the G1 Point into a 32 byte slice, then appends it to
// the state
func (t *Transcript) AppendPoint(point *bls.G1Point) {
	// XXX: Ideally, we just add the compressed bytes into
	// the transcript
	// However, so that tests do not fail, we
	// sha256 hash the compressed point
	// tmpBytes := bls.ToCompressedG1(point)
	//
	//
	tmpBytes := sha256.Sum256(bls.ToCompressedG1(point))
	t.appendBytes(tmpBytes[:])
}
func (t *Transcript) AppendPoints(points []*bls.G1Point) {
	for _, point := range points {
		t.AppendPoint(point)
	}
}

// Appends Bytes to the transcript
func (t *Transcript) appendBytes(b []byte) {
	t.state = append(t.state, b...)
}

// Computes a challenge based off of the state of the transcript
//
// Hash the transcript state, then reduce the hash modulo the size of the
// scalar field
//
// XXX: Reduction to a field element, should probably be in the bls library and not here
// with an api that just takes a slice and reduces it to an Fr
func (t *Transcript) ChallengeScalar() bls.Fr {
	digest := sha256.New()
	digest.Write(t.state)

	// XXX: Clear the state in order to be consistent with tests
	// Although I believe we should not clear
	t.state = []byte{}

	var tmp bls.Fr
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}
