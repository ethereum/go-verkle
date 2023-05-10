package verkle

import "testing"

func TestUnknownFuncs(t *testing.T) {
	un := UnknownNode{}

	if err := un.Insert(nil, nil, nil); err != errMissingNodeInStateless {
		t.Errorf("got %v, want %v", err, errMissingNodeInStateless)
	}
	if err := un.Delete(nil, nil); err == nil {
		t.Errorf("got nil error when deleting from a hashed node")
	}
	if _, err := un.Get(nil, nil); err != nil {
		t.Errorf("got %v, want nil", err)
	}
	var identity Point
	identity.Identity()
	if comm := un.Commit(); !comm.Equal(&identity) {
		t.Errorf("got %v, want identity", comm)
	}
	if comm := un.Commitment(); !comm.Equal(&identity) {
		t.Errorf("got %v, want identity", comm)
	}
	if _, _, _, err := un.GetProofItems(nil); err == nil {
		t.Errorf("got nil error when getting proof items from a hashed node")
	}
	if _, err := un.Serialize(); err == nil {
		t.Errorf("got nil error when serializing a hashed node")
	}
	if un != un.Copy() {
		t.Errorf("copy returned a different node")
	}
	if un.toDot("", "") != "" {
		t.Errorf("toDot returned a non-empty string")
	}
	if !un.Hash().Equal(&FrZero) {
		t.Errorf("hash returned non-zero")
	}
}
