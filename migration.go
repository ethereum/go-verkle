package verkle

import (
	"bytes"
	"fmt"
	"sort"
)

type BatchNewLeafNodeData struct {
	Stem   []byte
	Values map[int][]byte
}

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

func BatchInsertOrderedLeaves(leaves []LeafNode) *InternalNode {
	var currentBranch [31]*InternalNode

	// Initial state.
	currentBranch[0] = New().(*InternalNode)
	currentBranch[0].cowChild(leaves[0].stem[0])
	currentBranch[0].children[leaves[0].stem[0]] = &leaves[0]

	prevLeaf := &leaves[0]
	leaves = leaves[1:]
	for i := range leaves {
		leaf := &leaves[i]
		idx := firstDiffByteIdx(prevLeaf.stem, leaf.stem)

		if currentBranch[idx] != nil {
			currentBranch[idx].cowChild(leaf.stem[idx])
			currentBranch[idx].children[leaf.stem[idx]] = leaf
			leaf.setDepth(currentBranch[idx].depth + 1)
			for i := idx + 1; i < len(currentBranch); i++ {
				currentBranch[i] = nil
			}
		} else {
			// Create the new internal node.
			// Make the immediate previous internal node point to this new node.
			prevNonNilIdx := 0
			for i := idx - 1; i >= 0; i-- {
				if currentBranch[i] != nil {
					prevNonNilIdx = i
					break
				}
			}
			for k := prevNonNilIdx + 1; k <= idx; k++ {
				currentBranch[k] = newInternalNode(currentBranch[k-1].depth + 1).(*InternalNode)
				currentBranch[k-1].cowChild(leaf.stem[k-1])
				currentBranch[k-1].children[leaf.stem[k-1]] = currentBranch[k]
			}

			currentBranch[idx].cowChild(prevLeaf.stem[idx])
			currentBranch[idx].children[prevLeaf.stem[idx]] = prevLeaf
			prevLeaf.setDepth(currentBranch[idx].depth + 1)
			currentBranch[idx].cowChild(leaf.stem[idx])
			currentBranch[idx].children[leaf.stem[idx]] = leaf

			for i := idx + 1; i < len(currentBranch); i++ {
				currentBranch[i] = nil
			}
		}

		prevLeaf = leaf
	}

	return currentBranch[0]
}

func firstDiffByteIdx(stem1 []byte, stem2 []byte) int {
	for i := range stem1 {
		if stem1[i] != stem2[i] {
			return i
		}
	}
	panic("stems are equal")
}

func MergeLevelTwoPartitions(roots []*InternalNode) *InternalNode {
	firstLevelIdx := 0
	for i := 0; i < NodeWidth; i++ {
		if _, ok := roots[0].children[i].(*InternalNode); !ok {
			continue
		}
		firstLevelIdx = i
		break
	}
	secondLevelRoot := newInternalNode(1).(*InternalNode)
	for i := 0; i < NodeWidth; i++ {
		for j := range roots {
			proot := roots[j].children[firstLevelIdx].(*InternalNode)
			in, ok := proot.children[i].(*InternalNode)
			if !ok {
				continue
			}
			secondLevelRoot.cowChild(byte(i))
			secondLevelRoot.children[i] = in
			break
		}
	}

	root := newInternalNode(0).(*InternalNode)
	root.cowChild(byte(firstLevelIdx))
	root.children[firstLevelIdx] = secondLevelRoot

	return root
}

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
