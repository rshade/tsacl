package coded_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyCodedBuildsContractErrors keeps every policycore error on the one
// constructor that pins exit code 2, retryable false, and empty runtime
// metadata. A direct contract.NewError elsewhere would default to exit 1,
// which tsacl reads as a failed verdict.
func TestOnlyCodedBuildsContractErrors(t *testing.T) {
	t.Parallel()

	pkgRoot := filepath.Join("..", "..", "..")
	err := filepath.WalkDir(pkgRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) == "coded" {
			return nil
		}
		for _, position := range newErrorCalls(t, path) {
			t.Errorf("%s calls contract.NewError; use internal/coded instead", position)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func newErrorCalls(t *testing.T, path string) []token.Position {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var calls []token.Position
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "NewError" {
			return true
		}
		if pkg, isIdent := selector.X.(*ast.Ident); isIdent && pkg.Name == "contract" {
			calls = append(calls, fset.Position(selector.Pos()))
		}
		return true
	})
	return calls
}
