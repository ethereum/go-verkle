package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	"github.com/thrylos-labs/go-verkle"
)

func main() {
	benchmarkInsertInExisting()
}

func benchmarkInsertInExisting() {
	f, _ := os.Create("cpu.prof")
	g, _ := os.Create("mem.prof")
	_ = pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
	defer func() { _ = pprof.WriteHeapProfile(g) }()
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
			if _, err := rand.Read(key); err != nil {
				panic(err)
			}
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
				if err := root.Insert(k, value, nil); err != nil {
					panic(err)
				}
			}
			root.Commit()

			// Now insert the 10k leaves and measure time
			start := time.Now()
			for _, k := range toInsertKeys {
				if err := root.Insert(k, value, nil); err != nil {
					panic(err)
				}
			}
			root.Commit()
			elapsed := time.Since(start)
			fmt.Printf("Took %v to insert and commit %d leaves\n", elapsed, toInsert)
		}
	}
}
