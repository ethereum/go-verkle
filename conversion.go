package verkle

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
)

func batchCommitLeafNodes(leaves []*LeafNode) {
	minBatchSize := 8
	if len(leaves) < minBatchSize {
		commitLeafNodes(leaves)
		return
	}

	batchSize := len(leaves) / runtime.NumCPU()
	if batchSize < minBatchSize {
		batchSize = minBatchSize
	}

	var wg sync.WaitGroup
	for start := 0; start < len(leaves); start += batchSize {
		end := start + batchSize
		if end > len(leaves) {
			end = len(leaves)
		}
		wg.Add(1)
		go func(leaves []*LeafNode) {
			defer wg.Done()
			commitLeafNodes(leaves)
		}(leaves[start:end])
	}
	wg.Wait()
}

func commitLeafNodes(leaves []*LeafNode) {
	cfg := GetConfig()

	c1c2points := make([]*Point, 2*len(leaves))
	c1c2frs := make([]*Fr, 2*len(leaves))
	for i, n := range leaves {
		// C1.
		var c1poly [NodeWidth]Fr
		count := fillSuffixTreePoly(c1poly[:], n.values[:NodeWidth/2])
		containsEmptyCodeHash := len(c1poly) >= EmptyCodeHashSecondHalfIdx &&
			c1poly[EmptyCodeHashFirstHalfIdx].Equal(&EmptyCodeHashFirstHalfValue) &&
			c1poly[EmptyCodeHashSecondHalfIdx].Equal(&EmptyCodeHashSecondHalfValue)
		if containsEmptyCodeHash {
			// Clear out values of the cached point.
			c1poly[EmptyCodeHashFirstHalfIdx] = FrZero
			c1poly[EmptyCodeHashSecondHalfIdx] = FrZero
			// Calculate the remaining part of c1 and add to the base value.
			partialc1 := cfg.CommitToPoly(c1poly[:], NodeWidth-count-2)
			n.c1 = new(Point)
			n.c1.Add(&EmptyCodeHashPoint, partialc1)
		} else {
			n.c1 = cfg.CommitToPoly(c1poly[:], NodeWidth-count)
		}

		// C2.
		var c2poly [NodeWidth]Fr
		count = fillSuffixTreePoly(c2poly[:], n.values[NodeWidth/2:])
		n.c2 = cfg.CommitToPoly(c2poly[:], NodeWidth-count)

		c1c2points[2*i], c1c2points[2*i+1] = n.c1, n.c2
		c1c2frs[2*i], c1c2frs[2*i+1] = new(Fr), new(Fr)
	}

	toFrMultiple(c1c2frs, c1c2points)

	var poly [NodeWidth]Fr
	poly[0].SetUint64(1)
	for i, nv := range leaves {
		StemFromBytes(&poly[1], nv.stem)
		poly[2] = *c1c2frs[2*i]
		poly[3] = *c1c2frs[2*i+1]

		nv.commitment = cfg.CommitToPoly(poly[:], 252)
	}
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
