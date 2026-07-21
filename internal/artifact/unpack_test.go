package artifact

import (
	"bytes"
	"testing"

	"github.com/joncooper/detonator/internal/testutil"
	"github.com/joncooper/detonator/internal/verdict"
)

func TestUnpackNPMStripsPackagePrefix(t *testing.T) {
	data := testutil.NPMTarball(map[string]string{
		"package.json": `{"name":"foo"}`,
		"lib/index.js": `x`,
	})
	u, err := UnpackAuto(verdict.NPM, data)
	if err != nil {
		t.Fatalf("UnpackAuto: %v", err)
	}
	if u.Lookup("package.json") == nil {
		t.Fatal("package.json not found (prefix not stripped)")
	}
	if u.Lookup("lib/index.js") == nil {
		t.Fatal("nested file not found")
	}
	if u.Lookup("package/package.json") != nil {
		t.Fatal("prefix not stripped")
	}
}

func TestLogicalPathDefangsTraversal(t *testing.T) {
	if got := logicalPath("package/../../etc/passwd", "package/"); bytes.Contains([]byte(got), []byte("..")) {
		t.Fatalf("traversal not defanged: %q", got)
	}
}
