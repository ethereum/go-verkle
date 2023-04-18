package verkle

import (
	"bytes"
	"runtime"
	"sort"
	"sync"
)

// BatchNewLeafNodeData is a struct that contains the data needed to create a new leaf node.
type BatchNewLeafNodeData struct {
	Stem   []byte
	Values map[byte][]byte
}

// BatchNewLeafNode creates a new leaf node from the given data. It optimizes LeafNode creation
// by batching expensive cryptography operations. It returns the LeafNodes sorted by stem.
func BatchNewLeafNode(nodesValues []BatchNewLeafNodeData) []LeafNode {
	cfg := GetConfig()
	ret := make([]LeafNode, len(nodesValues))

	numBatches := runtime.NumCPU()
	batchSize := len(nodesValues) / numBatches

	var wg sync.WaitGroup
	wg.Add(numBatches)
	for i := 0; i < numBatches; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if i == numBatches-1 {
			end = len(nodesValues)
		}
		go func(ret []LeafNode, nodesValues []BatchNewLeafNodeData) {
			defer wg.Done()

			c1c2points := make([]*Point, 2*len(nodesValues))
			c1c2frs := make([]*Fr, 2*len(nodesValues))
			for i, nv := range nodesValues {
				valsslice := make([][]byte, NodeWidth)
				for idx := range nv.Values {
					valsslice[idx] = nv.Values[idx]
				}

				ret[i] = *NewLeafNode(nv.Stem, valsslice)

				c1c2points[2*i], c1c2points[2*i+1] = ret[i].c1, ret[i].c2
				c1c2frs[2*i], c1c2frs[2*i+1] = new(Fr), new(Fr)
			}

			toFrMultiple(c1c2frs, c1c2points)

			var poly [NodeWidth]Fr
			poly[0].SetUint64(1)
			for i, nv := range nodesValues {
				StemFromBytes(&poly[1], nv.Stem)
				poly[2] = *c1c2frs[2*i]
				poly[3] = *c1c2frs[2*i+1]

				ret[i].commitment = cfg.CommitToPoly(poly[:], 252)
			}

		}(ret[start:end], nodesValues[start:end])
	}
	wg.Wait()

	sort.Slice(ret, func(i, j int) bool {
		return bytes.Compare(ret[i].stem, ret[j].stem) < 0
	})

	return ret
}

// firstDiffByteIdx will return the first index in which the two stems differ.
// Both stems *must* be different.
func firstDiffByteIdx(stem1 []byte, stem2 []byte) int {
	for i := range stem1 {
		if stem1[i] != stem2[i] {
			return i
		}
	}
	panic("stems are equal")
}
