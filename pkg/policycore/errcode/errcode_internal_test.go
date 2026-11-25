package errcode

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"testing"
)

// TestVocabularyIsClosed fails when a code constant is missing from Fix's
// cases or from All's list, so a new code cannot ship without a fix.
func TestVocabularyIsClosed(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "errcode.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	constants := map[string]bool{}
	fixCases := map[string]bool{}
	listed := map[string]bool{}
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.GenDecl:
			if decl.Tok != token.CONST {
				continue
			}
			for _, spec := range decl.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					constants[name.Name] = true
				}
			}
		case *ast.FuncDecl:
			collectIdents(decl, fixCases, listed)
		}
	}

	want := slices.Sorted(maps.Keys(constants))
	if got := slices.Sorted(maps.Keys(fixCases)); !slices.Equal(got, want) {
		t.Errorf("Fix cases = %v, want every constant %v", got, want)
	}
	if got := slices.Sorted(maps.Keys(listed)); !slices.Equal(got, want) {
		t.Errorf("All() entries = %v, want every constant %v", got, want)
	}
}

func collectIdents(decl *ast.FuncDecl, fixCases, listed map[string]bool) {
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.CaseClause:
			if decl.Name.Name == "Fix" {
				for _, expr := range node.List {
					fixCases[expr.(*ast.Ident).Name] = true
				}
			}
		case *ast.CompositeLit:
			if decl.Name.Name == "All" {
				for _, expr := range node.Elts {
					listed[expr.(*ast.Ident).Name] = true
				}
			}
		}
		return true
	})
}
