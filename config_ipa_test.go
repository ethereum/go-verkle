package verkle

import (
	"os"
	"testing"
)

func TestGeneratePrecompFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	cfg = nil // Side-effects of the package having globals, yuck.

	// Restore the default after this test.
	defer func(originalPath string) {
		precompFileName = originalPath
		cfg = nil
	}(precompFileName)

	precompFileName = t.TempDir() + "/precomp"
	if conf := GetConfig(); conf == nil {
		t.Fatal("GetConfig() returned nil")
	}
	stat, err := os.Stat(precompFileName)
	if err != nil {
		t.Fatalf("file stat failed: %s", err)
	}
	if stat.Size() == 0 {
		t.Fatal("precomp file is empty")
	}
}
