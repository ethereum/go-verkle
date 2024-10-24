package verkle

import (
	"bytes"
	"errors"
	"testing"
)

func TestInsertSameLeafNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if err := root.Insert(oneKeyTest, testValue, 1, nil); err != nil {
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

	if leaf.lastTs != 1 {
		t.Fatalf("expected last accessed to be 1, got %d", leaf.lastTs)
	}
}

func TestInsertSameLeafExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	err := root.Insert(oneKeyTest, testValue, 2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected epoch expired error when inserting, got %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.values[zeroKeyTest[StemSize]], testValue) {
		t.Fatalf("expected value %x, got %x", testValue, leaf.values[zeroKeyTest[StemSize]])
	}

	if leaf.lastTs != 0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.lastTs)
	}
}

func TestInsertDiffLeaf(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if err := root.Insert(ffx32KeyTest, testValue, 2, nil); err != nil {
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

	if leaf0.lastTs != 0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf0.lastTs)
	}

	if leaff.lastTs != 2 {
		t.Fatalf("expected last accessed to be 2, got %d", leaff.lastTs)
	}
}

func TestGetNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	val, err := root.Get(zeroKeyTest, 1, nil)
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

	if leaf.lastTs != 0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.lastTs)
	}
}

func TestGetExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	val, err := root.Get(zeroKeyTest, 2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected epoch expired error when getting, got %v", err)
	}

	if val != nil {
		t.Fatalf("expected value to be nil, got %x", val)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", root.(*InternalNode).children[0])
	}

	if leaf.lastTs != 0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.lastTs)
	}
}

func TestDelLeafNoExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	if _, err := root.Delete(zeroKeyTest, 1, nil); err != nil {
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
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	_, err := root.Delete(zeroKeyTest, 2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected epoch expired error when deleting, got %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("expected empty node, got %T", root.(*InternalNode).children[0])
	}

	if leaf.lastTs != 0 {
		t.Fatalf("expected last accessed to be 0, got %d", leaf.lastTs)
	}
}

func TestRootCommitExpired(t *testing.T) {
	t.Parallel()

	root := New()
	if err := root.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
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

func TestRootCommitDiffTimestamp(t *testing.T) {
	t.Parallel()

	root1 := New()
	if err := root1.Insert(zeroKeyTest, testValue, 0, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}
	comm1 := root1.Commit()

	root2 := New()
	if err := root2.Insert(zeroKeyTest, testValue, 2, nil); err != nil {
		t.Fatalf("error inserting: %v", err)
	}
	comm2 := root2.Commit()

	if comm1.Equal(comm2) {
		t.Fatalf("expected different commitments, got %x", comm1)
	}
}
