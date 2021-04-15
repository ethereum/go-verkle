package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/gballet/go-verkle"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

var s1, lg1 []bls.G1Point

// GenerateTestingSetupWithLagrange creates a setup of n values from the given secret,
// along with the  **for testing purposes only**
func GenerateTestingSetupWithLagrange(secret string, n uint64, fftCfg *kzg.FFTSettings) ([]bls.G1Point, []bls.G2Point, []bls.G1Point, error) {
	var s bls.Fr
	bls.SetFr(&s, secret)

	var sPow bls.Fr
	bls.CopyFr(&sPow, &bls.ONE)

	s1Out := make([]bls.G1Point, n, n)
	s2Out := make([]bls.G2Point, n, n)
	for i := uint64(0); i < n; i++ {
		bls.MulG1(&s1Out[i], &bls.GenG1, &sPow)
		bls.MulG2(&s2Out[i], &bls.GenG2, &sPow)
		var tmp bls.Fr
		bls.CopyFr(&tmp, &sPow)
		bls.MulModFr(&sPow, &tmp, &s)
	}

	s1Lagrange, err := fftCfg.FFTG1(s1Out, true)

	return s1Out, s2Out, s1Lagrange, err
}

func main() {
	var err error
	fftCfg := kzg.NewFFTSettings(10)
	s1, _, lg1, err = GenerateTestingSetupWithLagrange("1927409816240961209460912649124", 1024, fftCfg)
	if err != nil {
		panic(err)
	}

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
			root := verkle.New(10, lg1)
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
