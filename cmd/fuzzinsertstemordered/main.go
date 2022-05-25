package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"

	"github.com/gballet/go-verkle"
)

type stemList struct {
	stems [][]byte
}

func (kl stemList) Len() int {
	return len(kl.stems)
}

func (kl stemList) Less(i, j int) bool {
	return (bytes.Compare(kl.stems[i], kl.stems[j]) < 0)
}
func (kl stemList) Swap(i, j int) {
	kl.stems[i], kl.stems[j] = kl.stems[j], kl.stems[i]
}

func main() {
	for attempt := 0; ; attempt++ {
		fmt.Println("attempt #", attempt)

		rootRef := verkle.New()
		rootFuzz := verkle.New().(*verkle.InternalNode)
		var stems = stemList{
			stems: make([][]byte, 10000),
		}

		for i := 0; i < 10000; i++ {
			stems.stems[i] = make([]byte, 31)
			rand.Read(stems.stems[i])
		}

		sort.Sort(stems)

		for _, stem := range stems.stems {
			values := make([][]byte, 256)
			for i := range values {
				values[i] = make([]byte, 32)
				rand.Read(values[i][:])
				var key [32]byte
				copy(key[:31], stem[:])
				key[31] = byte(i)
				rootRef.Insert(key[:], values[i], nil)
			}
			leaf := verkle.NewLeafNode(stem, values)
			rootFuzz.InsertStemOrdered(stem, leaf, nil)
		}

		if rootRef.ComputeCommitment().Bytes() != rootFuzz.ComputeCommitment().Bytes() {
			panic("differing commitments")
		}
	}
}
