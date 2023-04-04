package verkle

import (
	"bytes"
	"fmt"
	"sort"
)

// BatchNewLeafNodeData is a struct that contains the data needed to create a new leaf node.
type BatchNewLeafNodeData struct {
	Stem   []byte
	Values map[int][]byte
}

// BatchNewLeafNode creates a new leaf node from the given data. It optimizes LeafNode creation
// by batching expensive cryptography operations. It returns the LeafNodes sorted by stem.
func BatchNewLeafNode(nodesValues []BatchNewLeafNodeData) []LeafNode {
	cfg := GetConfig()

	ret := make([]LeafNode, len(nodesValues))
	c1c2points := make([]*Point, 2*len(nodesValues))
	c1c2frs := make([]*Fr, 2*len(nodesValues))
	for i, nv := range nodesValues {
		ret[i] = LeafNode{
			values: nv.Values,
			stem:   nv.Stem,
			c1:     Generator(),
			c2:     Generator(),
		}

		var c1poly, c2poly [256]Fr

		valsslice := make([][]byte, 256)
		for idx := range nv.Values {
			valsslice[idx] = nv.Values[idx]
		}

		fillSuffixTreePoly(c1poly[:], valsslice[:128])
		ret[i].c1 = cfg.CommitToPoly(c1poly[:], 0)
		fillSuffixTreePoly(c2poly[:], valsslice[128:])
		ret[i].c2 = cfg.CommitToPoly(c2poly[:], 0)

		c1c2points[2*i], c1c2points[2*i+1] = ret[i].c1, ret[i].c2
		c1c2frs[2*i], c1c2frs[2*i+1] = new(Fr), new(Fr)
	}

	toFrMultiple(c1c2frs, c1c2points)

	var poly [256]Fr
	poly[0].SetUint64(1)
	for i, nv := range nodesValues {
		StemFromBytes(&poly[1], nv.Stem)
		poly[2] = *c1c2frs[2*i]
		poly[3] = *c1c2frs[2*i+1]

		ret[i].commitment = cfg.CommitToPoly(poly[:], 252)
	}

	sort.Slice(ret, func(i, j int) bool {
		return bytes.Compare(ret[i].stem[:], ret[j].stem[:]) < 0
	})

	return ret
}

// BatchInsertOrderedLeaves creates a tree under from an ordered and deduplicated list of leaves.
func BatchInsertOrderedLeaves(leaves []LeafNode) *InternalNode {
	// currentBranch is a representaion of the current branch we're in.
	// The length of the branch is at most StemSize, and it might only
	// have non-nil values in the first N levels.
	var currentBranch [StemSize]*InternalNode

	// Initial state is a branch with only a root node at the top, pointing to
	// the first leaf.
	currentBranch[0] = New().(*InternalNode)
	currentBranch[0].cowChild(leaves[0].stem[0])
	currentBranch[0].children[leaves[0].stem[0]] = &leaves[0]

	prevLeaf := &leaves[0]
	leaves = leaves[1:]
	// The idea is that we compare the newLeaf with the previousLeaf, and
	// depending on how their stems differ, we adjust our currentBranch structure.
	for i := range leaves {
		newLeaf := &leaves[i]

		// We get the first index in their stems that is different.
		idx := firstDiffByteIdx(prevLeaf.stem, newLeaf.stem)

		// If the currentBranch has a node at that index, we simply set the children
		// to the newLeaf.
		if currentBranch[idx] != nil {
			currentBranch[idx].cowChild(newLeaf.stem[idx])
			currentBranch[idx].children[newLeaf.stem[idx]] = newLeaf
			newLeaf.setDepth(currentBranch[idx].depth + 1)
			for i := idx + 1; i < len(currentBranch); i++ {
				currentBranch[i] = nil
			}
		} else {
			// In this case there's no InternalNode in the current branch at the index.
			// We need to "fill the gap" between the previous non-nil internal node up to
			// the idx with new internal nodes. Then we set the last created internal node
			// to the previous and new leaf.
			prevNonNilIdx := 0
			for i := idx - 1; i >= 0; i-- {
				if currentBranch[i] != nil {
					prevNonNilIdx = i
					break
				}
			}
			for k := prevNonNilIdx + 1; k <= idx; k++ {
				currentBranch[k] = newInternalNode(currentBranch[k-1].depth + 1).(*InternalNode)
				currentBranch[k-1].cowChild(newLeaf.stem[k-1])
				currentBranch[k-1].children[newLeaf.stem[k-1]] = currentBranch[k]
			}

			currentBranch[idx].cowChild(prevLeaf.stem[idx])
			currentBranch[idx].children[prevLeaf.stem[idx]] = prevLeaf
			prevLeaf.setDepth(currentBranch[idx].depth + 1)
			currentBranch[idx].cowChild(newLeaf.stem[idx])
			currentBranch[idx].children[newLeaf.stem[idx]] = newLeaf

			for i := idx + 1; i < len(currentBranch); i++ {
				currentBranch[i] = nil
			}
		}

		prevLeaf = newLeaf
	}

	return currentBranch[0]
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

// GetInternalNodeCommitment returns the commitment of the internal node at
// the partialStem. e.g: if partialStem is [a, b] it will walk to the a-th
// children of the node, and then to the b-th children of that node, returning
// its commitment..
func GetInternalNodeCommitment(node *InternalNode, partialStem []byte) (*Point, error) {
	for i := range partialStem {
		var ok bool
		node, ok = node.children[partialStem[i]].(*InternalNode)
		if !ok {
			return nil, fmt.Errorf("partial stem is not a prefix of the tree")
		}
	}

	return node.commitment, nil
}

// BuildFirstTwoLayers builds the first two layers of the tree from all the precalculated
// commitments of the children of the second level. This method is generally used if tree
// construction was done in partitions, and you want to glue them together without having
// the whole tree in memory.
func BuildFirstTwoLayers(commitments [256][256][32]byte) *InternalNode {
	var secondLevelInternalNodes [256]*InternalNode
	for stemFirstByte := range commitments {
		for stemSecondByte := range commitments[stemFirstByte] {
			if commitments[stemFirstByte][stemSecondByte] == [32]byte{} {
				continue
			}
			if secondLevelInternalNodes[stemFirstByte] == nil {
				secondLevelInternalNodes[stemFirstByte] = newInternalNode(1).(*InternalNode)
			}
			hashedNode := HashedNode{commitment: commitments[stemFirstByte][stemSecondByte][:]}
			secondLevelInternalNodes[stemFirstByte].cowChild(byte(stemSecondByte))
			secondLevelInternalNodes[stemFirstByte].SetChild(stemSecondByte, &hashedNode)
		}
	}
	root := newInternalNode(0).(*InternalNode)
	for i, node := range secondLevelInternalNodes {
		if node == nil {
			continue
		}
		root.cowChild(byte(i))
		root.SetChild(i, node)
	}

	return root
}
