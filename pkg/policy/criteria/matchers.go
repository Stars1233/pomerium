package criteria

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	"github.com/pomerium/pomerium/pkg/policy/parser"
)

type matcher func(*ast.Body, *ast.Term, parser.Value) error

func matchString(dst *ast.Body, left *ast.Term, right parser.Value) error {
	obj, ok := right.(parser.Object)
	if !ok {
		obj = parser.Object{
			"is": right,
		}
	}

	lookup := map[string]matcher{
		"contains":    matchStringContains,
		"ends_with":   matchStringEndsWith,
		"not":         matchStringNot,
		"is":          matchStringIs,
		"starts_with": matchStringStartsWith,
		"in":          matchStringIn,
	}
	for k, v := range obj {
		f, ok := lookup[k]
		if !ok {
			return fmt.Errorf("unknown string matcher operator: %s", k)
		}
		err := f(dst, left, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func matchStringContains(dst *ast.Body, left *ast.Term, right parser.Value) error {
	*dst = append(*dst, ast.Contains.Expr(left, ast.NewTerm(right.RegoValue())))
	return nil
}

func matchStringEndsWith(dst *ast.Body, left *ast.Term, right parser.Value) error {
	*dst = append(*dst, ast.EndsWith.Expr(left, ast.NewTerm(right.RegoValue())))
	return nil
}

func matchStringNot(dst *ast.Body, left *ast.Term, right parser.Value) error {
	*dst = append(*dst, ast.NotEqual.Expr(left, ast.NewTerm(right.RegoValue())))
	return nil
}

func matchStringIs(dst *ast.Body, left *ast.Term, right parser.Value) error {
	*dst = append(*dst, ast.Equal.Expr(left, ast.NewTerm(right.RegoValue())))
	return nil
}

func matchStringStartsWith(dst *ast.Body, left *ast.Term, right parser.Value) error {
	*dst = append(*dst, ast.StartsWith.Expr(left, ast.NewTerm(right.RegoValue())))
	return nil
}

func matchStringIn(dst *ast.Body, left *ast.Term, right parser.Value) error {
	arr, ok := right.(parser.Array)
	if !ok {
		return fmt.Errorf("in matcher requires an array of strings")
	}
	*dst = append(*dst, ast.Member.Expr(left, ast.NewTerm(arr.RegoValue())))
	return nil
}

func matchStringList(dst *ast.Body, left *ast.Term, right parser.Value) error {
	obj, ok := right.(parser.Object)
	if !ok {
		obj = parser.Object{
			"has": right,
		}
	}

	lookup := map[string]matcher{
		"has":     matchStringListHas,
		"is":      matchStringListIs,
		"exclude": matchStringListExclude,
	}
	for k, v := range obj {
		f, ok := lookup[k]
		if !ok {
			return fmt.Errorf("unknown string list matcher operator: %s", k)
		}
		err := f(dst, left, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func matchStringListHas(dst *ast.Body, left *ast.Term, right parser.Value) error {
	body := ast.Body{
		ast.MustParseExpr("some v"),
		ast.Equality.Expr(ast.VarTerm("v"), ast.RefTerm(left, ast.VarTerm("$0"))),
	}
	err := matchStringIs(&body, ast.VarTerm("v"), right)
	if err != nil {
		return err
	}
	*dst = append(*dst, ast.GreaterThan.Expr(
		ast.Count.Call(
			ast.ArrayComprehensionTerm(
				ast.BooleanTerm(true),
				body,
			),
		),
		ast.IntNumberTerm(0),
	))
	return nil
}

func matchStringListIs(dst *ast.Body, left *ast.Term, right parser.Value) error {
	*dst = append(*dst,
		ast.Equal.Expr(
			ast.Count.Call(left),
			ast.IntNumberTerm(1),
		),
	)
	return matchStringListHas(dst, left, right)
}

func matchStringListExclude(dst *ast.Body, left *ast.Term, right parser.Value) error {
	body := ast.Body{
		ast.MustParseExpr("some v"),
		ast.Equality.Expr(ast.VarTerm("v"), ast.RefTerm(left, ast.VarTerm("$0"))),
	}
	err := matchStringIs(&body, ast.VarTerm("v"), right)
	if err != nil {
		return err
	}
	*dst = append(*dst, ast.Equal.Expr(
		ast.Count.Call(
			ast.ArrayComprehensionTerm(
				ast.BooleanTerm(true),
				body,
			),
		),
		ast.IntNumberTerm(0),
	))
	return nil
}
