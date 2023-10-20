package verkle

import (
	"fmt"
)

func TreeWitness(tree VerkleNode, resolver NodeResolverFn, stem []byte) (int, int, int, int, int, error) {
	switch n := tree.(type) {
	case *InternalNode:
		var depthMin, depthMax, leafNodeCount, internalNodeCount, keyValueCount int
		for i := 0; i < 256; i++ {
			stem := append(stem, byte(i))
			switch n.children[i].(type) {
			case Empty:
				continue
			case HashedNode:
				serialized, err := resolver(stem[:n.depth+1])
				if err != nil {
					return 0, 0, 0, 0, 0, fmt.Errorf("verkle tree: error resolving node %x at depth %d: %w", stem, n.depth, err)
				}
				resolved, err := ParseNode(serialized, n.depth+1)
				if err != nil {
					return 0, 0, 0, 0, 0, fmt.Errorf("verkle tree: error parsing resolved node %x: %w", stem, err)
				}
				n.children[i] = resolved
			}

			branchDepthMin, branchDepthMax, branchLeafNodeCount, branchInternalNodeCount, branchKeyValueCount, err := TreeWitness(n.children[i], resolver, stem)
			if err != nil {
				return 0, 0, 0, 0, 0, fmt.Errorf("failed to get witness for branch %d: %w", i, err)
			}
			if depthMin > branchDepthMin+1 {
				depthMin = branchDepthMin + 1
			}
			if depthMax < branchDepthMax+1 {
				depthMax = branchDepthMax + 1
			}
			leafNodeCount += branchLeafNodeCount
			internalNodeCount += branchInternalNodeCount
			keyValueCount += branchKeyValueCount

		}
		return depthMin, depthMax, leafNodeCount, internalNodeCount + 1, keyValueCount, nil
	case *LeafNode:
		var keyValueCount int
		for i := 0; i < 256; i++ {
			if n.values[i] != nil {
				keyValueCount++
			}
		}
		return 0, 0, 1, 0, keyValueCount, nil
	default:
		return 0, 0, 0, 0, 0, fmt.Errorf("unknown node type: %T", n)
	}
}
