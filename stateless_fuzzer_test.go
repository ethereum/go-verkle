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

//go:build go1.18
// +build go1.18

package verkle

import (
	"testing"
)

func FuzzStatelessVsStateful(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		rootF := New()
		rootL := NewStateless()

		for i := 0; i < len(input)/64; i++ {
			rootF.Insert(input[i*64:i*64+32], input[i*64+32:(i+1)*64], nil)
			rootL.Insert(input[i*64:i*64+32], input[i*64+32:(i+1)*64], nil)
		}

		if !Equal(rootL.ComputeCommitment(), rootF.ComputeCommitment()) {
			t.Fatalf("root commitment for state-less != -ful %x != %x", rootF.ComputeCommitment().Bytes(), rootL.ComputeCommitment().Bytes())
		}
	})
}
