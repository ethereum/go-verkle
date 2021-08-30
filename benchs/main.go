package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/gballet/go-verkle"
)

func main() {
	benchmarkInsertInExisting()
}

func benchmarkInsertInExisting() {
	rand.Seed(time.Now().UnixNano())

	// Number of existing leaves in tree
	n := 1000000
	// Leaves to be inserted afterwards
	toInsert := 10000
	total := n + toInsert

	keys := make([][]byte, n)
	toInsertKeys := make([][]byte, toInsert)
	value := []byte("value")

	for i := 0; i < 4; i++ {
		// Generate set of keys once
		for i := 0; i < total; i++ {
			key := make([]byte, 32)
			rand.Read(key)
			if i < n {
				keys[i] = key
			} else {
				toInsertKeys[i-n] = key
			}
		}
		fmt.Printf("Generated key set %d\n", i)

		// Create tree from same keys multiple times
		for i := 0; i < 5; i++ {
			root := verkle.New()
			for _, k := range keys {
				if err := root.Insert(k, value); err != nil {
					panic(err)
				}
			}
			root.ComputeCommitment()

			// Now insert the 10k leaves and measure time
			start := time.Now()
			for _, k := range toInsertKeys {
				if err := root.Insert(k, value); err != nil {
					panic(err)
				}
			}
			root.ComputeCommitment()
			elapsed := time.Since(start)
			fmt.Printf("Took %v to insert and commit %d leaves\n", elapsed, toInsert)
		}
	}
}
