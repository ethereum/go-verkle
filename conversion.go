package verkle

import (
	"bytes"
	"fmt"
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

func (n *InternalNode) InsertMigratedLeaves(leaves []LeafNode, resolver NodeResolverFn) error {
	for i := range leaves {
		ln := leaves[i]
		parent := n

		// Look for the appropriate parent for the leaf node.
		for {
			if hashedNode, ok := parent.children[ln.stem[parent.depth]].(*HashedNode); ok {
				serialized, err := resolver(hashedNode.commitment)
				if err != nil {
					return fmt.Errorf("resolving node %x: %w", hashedNode.commitment, err)
				}
				resolved, err := ParseNode(serialized, parent.depth+1, hashedNode.commitment)
				if err != nil {
					return fmt.Errorf("parsing node %x: %w", serialized, err)
				}
				parent.children[ln.stem[parent.depth]] = resolved
			}

			nextParent, ok := parent.children[ln.stem[parent.depth]].(*InternalNode)
			if !ok {
				break
			}

			parent.cowChild(ln.stem[parent.depth])
			parent = nextParent
		}

		switch node := parent.children[ln.stem[parent.depth]].(type) {
		case Empty:
			parent.cowChild(ln.stem[parent.depth])
			parent.children[ln.stem[parent.depth]] = &ln
			ln.setDepth(parent.depth + 1)
		case *LeafNode:
			if bytes.Equal(node.stem, ln.stem) {
				// In `ln` we have migrated key/values which should be copied to the leaf
				// only if there isn't a value there. If there's a value, we skip it since
				// our migrated value is stale.
				nonPresentValues := make([][]byte, NodeWidth)
				for i := range ln.values {
					if node.values[i] == nil {
						nonPresentValues[i] = ln.values[i]
					}
				}

				node.updateMultipleLeaves(nonPresentValues)
				continue
			}

			// Otherwise, we need to create the missing internal nodes depending in the fork point in their stems.
			idx := firstDiffByteIdx(node.stem, ln.stem)
			// We do a sanity check to make sure that the fork point is not before the current depth.
			if byte(idx) <= parent.depth {
				return fmt.Errorf("unexpected fork point %d for nodes %x and %x", idx, node.stem, ln.stem)
			}
			// Create the missing internal nodes.
			for i := parent.depth + 1; i <= byte(idx); i++ {
				nextParent := newInternalNode(parent.depth + 1).(*InternalNode)
				parent.cowChild(ln.stem[parent.depth])
				parent.children[ln.stem[parent.depth]] = nextParent
				parent = nextParent
			}
			// Add old and new leaf node to the latest created parent.
			parent.cowChild(node.stem[parent.depth])
			parent.children[node.stem[parent.depth]] = node
			node.setDepth(parent.depth + 1)
			parent.cowChild(ln.stem[parent.depth])
			parent.children[ln.stem[parent.depth]] = &ln
			ln.setDepth(parent.depth + 1)
		default:
			return fmt.Errorf("unexpected node type %T", node)
		}
	}
	return nil
}
