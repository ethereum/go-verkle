// +build !bignum_kilic

package verkle

const (
	// Threshold for using multi exponentiation when
	// computing commitment. Number refers to non-zero
	// children in a node.
	multiExpThreshold10 = 110
)
