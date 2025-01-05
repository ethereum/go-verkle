package verkle

import (
	"bytes"
	"errors"
	"testing"
)

func TestInsertSameLeafNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if err := root.Insert(oneKeyTest, testValue, period1, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.values[zeroKeyTest[StemSize]], testValue) {
		t.Fatalf("expected value %x, got %x", testValue, leaf.values[zeroKeyTest[StemSize]])
	}

	if !bytes.Equal(leaf.values[oneKeyTest[StemSize]], testValue) {
		t.Fatalf("expected value %x, got %x", testValue, leaf.values[oneKeyTest[StemSize]])
	}

	if leaf.period != period1 {
		t.Fatalf("expected last accessed to be 1, got %d", leaf.period)
	}
}

func TestInsertSameLeafExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	err := root.Insert(oneKeyTest, testValue, period2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected period expired error when inserting, got %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.values[zeroKeyTest[StemSize]], testValue) {
		t.Fatalf("expected value %x, got %x", testValue, leaf.values[zeroKeyTest[StemSize]])
	}

	if leaf.period != period0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.period)
	}
}

func TestInsertDiffLeaf(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if err := root.Insert(ffx32KeyTest, testValue, period2, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf0, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	leaff, ok := root.(*InternalNode).children[255].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[255])
	}

	if !bytes.Equal(leaf0.values[zeroKeyTest[StemSize]], testValue) {
		t.Fatalf("expected value %x, got %x", testValue, leaf0.values[zeroKeyTest[StemSize]])
	}

	if !bytes.Equal(leaff.values[ffx32KeyTest[StemSize]], testValue) {
		t.Fatalf("expected value %x, got %x", testValue, leaff.values[ffx32KeyTest[StemSize]])
	}

	if leaf0.period != period0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf0.period)
	}

	if leaff.period != period2 {
		t.Fatalf("expected last accessed to be 2, got %d", leaff.period)
	}
}

func TestInsertExpiredLeafSibling(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	root.(*InternalNode).children[0] = NewExpiredLeafNode(leaf.stem, leaf.commitment)

	if err := root.Insert(forkOneKeyTest, testValue, period2, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	c1 := root.Commit()

	// Reconstruct a new tree with the same key-values but without the expired leaf node
	root2 := New()
	if err := root2.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if err := root2.Insert(forkOneKeyTest, testValue, period2, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	c2 := root2.Commit()

	// The two trees should have the same commitment
	if !c1.Equal(c2) {
		t.Fatalf("expected commitment to be %x, got %x", c1, c2)
	}
}

func TestGetNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	val, err := root.Get(zeroKeyTest, period1, nil)
	if err != nil {
		t.Fatalf("error getting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("expected value %x, got %x", testValue, val)
	}

	if leaf.period != period0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.period)
	}
}

func TestGetExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	val, err := root.Get(zeroKeyTest, period2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected period expired error when getting, got %v", err)
	}

	if val != nil {
		t.Fatalf("expected value to be nil, got %x", val)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if leaf.period != period0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.period)
	}
}

func TestDelLeafNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if _, err := root.Delete(zeroKeyTest, period1, nil); err != nil {
		t.Fatalf("error deleting: %v", err)
	}

	_, ok := root.(*InternalNode).children[0].(Empty)
	if !ok {
		t.Fatalf("expected empty node, got %T", root.(*InternalNode).children[0])
	}
}

func TestDelLeafExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	_, err := root.Delete(zeroKeyTest, period2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected period expired error when deleting, got %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected empty node, got %T", root.(*InternalNode).children[0])
	}

	if leaf.period != period0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.period)
	}
}

func TestUpdatePeriod(t *testing.T) {
	values := make([][]byte, NodeWidth)
	values[0] = testValue
	leaf1, err := NewLeafNode(zeroKeyTest, values, period1)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	leaf1.updatePeriod(period2)

	leaf2, err := NewLeafNode(zeroKeyTest, values, period2)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	if !leaf1.Commitment().Equal(leaf2.Commitment()) {
		t.Fatalf("expected commitment to be %x, got %x", leaf1.Commitment(), leaf2.Commitment())
	}
}

func TestReviveExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf := root.(*InternalNode).children[0].(*LeafNode)
	expiredLeaf := NewExpiredLeafNode(leaf.stem, new(Point).Set(leaf.commitment))
	expiredLeaf.setDepth(1)
	root.(*InternalNode).children[0] = expiredLeaf

	if err := root.Revive(leaf.stem, leaf.values, leaf.period, period2, false, nil); err != nil {
		t.Fatalf("error reviving: %v", err)
	}
	comm1 := root.Commit()

	rLeaf := root.(*InternalNode).children[0].(*LeafNode)
	if rLeaf.period != period2 {
		t.Fatalf("expected last accessed to be 2, got %d", rLeaf.period)
	}

	// Create a new root and insert the same key-value with the post-revive period
	root2 := New()
	if err := root2.Insert(zeroKeyTest, testValue, period2, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}
	comm2 := root2.Commit()

	if !comm1.Equal(comm2) {
		t.Fatalf("expected commitment to be %x, got %x", comm1, comm2)
	}
}

func TestReviveNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	comm := root.Commit()

	if err := root.Revive(leaf.stem, leaf.values, leaf.period, period0, false, nil); err != nil {
		t.Fatalf("error reviving: %v", err)
	}

	rLeaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if rLeaf.period != period0 {
		t.Fatalf("expected last accessed to be 0, got %d", rLeaf.period)
	}

	rComm := root.Commit()
	if !rComm.Equal(comm) {
		t.Fatalf("expected commitment to be %x, got %x", comm, rComm)
	}
}

func TestRootCommitExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	var init Point
	init.Set(root.Commit())

	expiredLeaf := NewExpiredLeafNode(leaf.stem, leaf.commitment)
	root.(*InternalNode).children[0] = expiredLeaf

	comm := root.Commit()
	if !comm.Equal(&init) {
		t.Fatalf("expected commitment to be %x, got %x", &init, comm)
	}
}

func TestRootCommitDiffEpoch(t *testing.T) {
	t.Parallel()

	root1 := New()
	if err := root1.Insert(zeroKeyTest, testValue, period0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}
	comm1 := root1.Commit()

	root2 := New()
	if err := root2.Insert(zeroKeyTest, testValue, period2, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}
	comm2 := root2.Commit()

	if comm1.Equal(comm2) {
		t.Fatalf("expected different commitments, got %x", comm1)
	}
}