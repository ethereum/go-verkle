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

// This function takes a hash and turns it into a Fr integer, making
// sure that this doesn't overflow the modulus.
// This piece of code is really ugly, and probably a performance hog, it
// needs to be rewritten more efficiently.
func hashToFr(out *Fr, h []byte) {
	// Q&D check that the hash doesn't exceed 32 bytes. hashToFr
	// should disappear in the short term, so a panic isn't a
	// big problem here.
	if len(h) != 32 {
		panic("invalid hash length ≠ 32")
	}
	h[31] &= 0x7F // mod 2^255

	// reverse endianness (little -> big)
	for i := 0; i < len(h)/2; i++ {
		h[i], h[len(h)-i-1] = h[len(h)-i-1], h[i]
	}

	// Apply modulus
	x := big.NewInt(0).SetBytes(h)
	x.Mod(x, modulus)

	// clear the buffer in case the trailing bytes were 0
	for i := 0; i < 32; i++ {
		h[i] = 0
	}

	// back to original endianness
	var processed [32]byte
	converted := x.Bytes()
	for i := 0; i < len(converted); i++ {
		processed[i] = converted[len(converted)-i-1]
	}

	if !FrFrom32(out, processed) {
		panic(fmt.Sprintf("invalid Fr number %x", processed))
	}
	// TODO(@gballet) activate when geth moves to Go 1.17
	// in replacement of what is above.
	//if !FrFrom32(out, (*[32]byte)(h)) {
	//panic(fmt.Sprintf("invalid Fr number %x", h))
	//}
}
