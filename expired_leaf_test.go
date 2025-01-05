package verkle

import (
	"errors"
	"testing"
)

func TestExpiredLeafBasic(t *testing.T) {
	t.Parallel()

	cfg := GetConfig()
	srs := cfg.conf.SRS
	comm := srs[0]
	leaf := NewExpiredLeafNode(zeroKeyTest[:StemSize], &comm)

	err := leaf.Insert(zeroKeyTest, zeroKeyTest, period2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected period expired error when inserting, got %v", err)
	}

	_, err = leaf.Delete(zeroKeyTest, period2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected period expired error when deleting, got %v", err)
	}

	v, err := leaf.Get(zeroKeyTest, period2, nil)
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected period expired error when getting, got %v", err)
	}
	if v != nil {
		t.Fatal("expected nil value when getting")
	}

	if !leaf.Commitment().Equal(leaf.Commit()) {
		t.Fatal("expected commitment and commit to be equal")
	}
}
