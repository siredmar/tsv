// Package tsv is a tolerant SQL validator for AWS Timestream queries.
// It ensures that every SELECT which directly reads from a base table
// (not just from a subquery) has a time predicate in WHERE.
//
// Heuristics (by design, not a full SQL parser):
//   - We lex tokens, track parentheses depth, and find SELECT blocks.
//   - For each SELECT, we locate FROM and WHERE at the same depth.
//   - A SELECT is considered "hits DB" if the FROM source starts with an identifier
//     (possibly quoted) rather than '(' (i.e., not a subquery). This covers most
//     common Timestream queries. If FROM starts with '(', we assume it pulls
//     from a subquery and skip the time check for that SELECT (inner SELECTs
//     are validated separately).
//   - A valid time filter is any predicate in WHERE that references one of
//     the allowed time columns and uses BETWEEN / < / <= / = / >= / >.
//     Examples that pass:
//     WHERE time BETWEEN ago(1d) AND now()
//     WHERE time >= ago(15m)
//     WHERE measure_time > from_iso8601_timestamp('2025-08-01T00:00:00Z')
//   - Works with CTEs (WITH ... AS (SELECT ...)), nested subqueries, joins,
//     and most practical formatting, comments, or string literals.
//
// If *any* relevant SELECT lacks a time filter, Validate returns false.
package tsv

import (
	"strings"
	"unicode"
)

type Options struct {
	// TimeColumns lists identifiers that count as the "time" column.
	// Defaults to []string{"time", "measure_time"} if nil/empty.
	TimeColumns []string
}

type Issue struct {
	// Snippet is a short excerpt of the offending SELECT (lowercased, trimmed).
	Snippet string
	// Reason explains why validation failed for this SELECT.
	Reason string
	// AtDepth is the parentheses nesting depth where the SELECT was found (debugging aid).
	AtDepth int
}

// Validate returns true if every SELECT that directly reads from a table
// has a WHERE time filter; otherwise returns false and the list of issues.
func Validate(sql string, opts *Options) (bool, []Issue) {
	timeCols := []string{"time", "measure_time"}
	if opts != nil && len(opts.TimeColumns) > 0 {
		timeCols = make([]string, len(opts.TimeColumns))
		for i, c := range opts.TimeColumns {
			timeCols[i] = strings.ToLower(c)
		}
	}

	// Preprocess: strip comments, normalize whitespace (without touching string literals).
	src := stripComments(sql)
	toks := lex(src)

	type sel struct {
		selIdx int // index into toks where "select" appears
		depth  int
	}
	var selects []sel
	for i := 0; i < len(toks); i++ {
		if toks[i].kind == tkKeyword && toks[i].val == "select" {
			selects = append(selects, sel{selIdx: i, depth: toks[i].depth})
		}
	}

	var issues []Issue

	for _, s := range selects {
		// Find FROM at same depth after this SELECT
		fromIdx := findNextKeywordAtDepth(toks, s.selIdx+1, s.depth, "from")
		if fromIdx == -1 {
			// SELECT without FROM (e.g., SELECT 1): ignore (doesn't hit DB)
			continue
		}

		// Determine the span of the FROM clause (until WHERE/GROUP/ORDER/HAVING/UNION or depth change)
		stopIdx := findNextTerminatorAtDepth(toks, fromIdx+1, s.depth)

		// Decide if this SELECT directly reads from a table (not a subquery-first source).
		hitsDB := fromStartsWithIdentifier(toks, fromIdx+1, stopIdx, s.depth)

		// If it doesn't hit DB at this level (starts with '('), inner SELECTs will be validated separately.
		if !hitsDB {
			continue
		}

		// Must have WHERE at same depth between FROM and the terminator (or end of statement).
		whereIdx := findNextKeywordBetweenAtDepth(toks, fromIdx+1, stopIdx, s.depth, "where")
		if whereIdx == -1 {
			issues = append(issues, Issue{
				Snippet: snippetAroundTokens(toks, s.selIdx, stopIdx),
				Reason:  "missing WHERE clause with time filter",
				AtDepth: s.depth,
			})
			continue
		}

		// WHERE span: from whereIdx+1 until next clause keyword or terminator at same depth.
		whereStop := findNextTerminatorAtDepth(toks, whereIdx+1, s.depth)

		if !whereHasTimePredicate(toks, whereIdx+1, whereStop, s.depth, timeCols) {
			issues = append(issues, Issue{
				Snippet: snippetAroundTokens(toks, s.selIdx, whereStop),
				Reason:  "WHERE clause lacks a time predicate on allowed time columns",
				AtDepth: s.depth,
			})
		}
	}

	return len(issues) == 0, issues
}

/* -------------------- internal: lexer & helpers -------------------- */

type tokenKind int

const (
	tkIdent tokenKind = iota
	tkKeyword
	tkString
	tkNumber
	tkSymbol
)

type token struct {
	val   string
	kind  tokenKind
	depth int
}

var keywords = map[string]struct{}{
	"select": {}, "from": {}, "where": {}, "group": {}, "by": {}, "order": {}, "having": {},
	"union": {}, "intersect": {}, "except": {}, "join": {}, "left": {}, "right": {}, "full": {},
	"outer": {}, "inner": {}, "cross": {}, "on": {}, "as": {}, "with": {}, "lateral": {},
	"between": {}, "and": {}, "or": {}, "not": {}, "in": {}, "exists": {},
}

func stripComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inLine, inBlock := false, false
	for i := 0; i < len(s); i++ {
		if inLine {
			if s[i] == '\n' {
				inLine = false
				b.WriteByte(s[i])
			}
			continue
		}
		if inBlock {
			if s[i] == '*' && i+1 < len(s) && s[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		}
		if s[i] == '-' && i+1 < len(s) && s[i+1] == '-' {
			inLine = true
			i++
			continue
		}
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '*' {
			inBlock = true
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func lex(s string) []token {
	var out []token
	depth := 0

	readString := func(i int, quote byte) (string, int) {
		j := i + 1
		for j < len(s) {
			if s[j] == quote {
				// handle escaped '' (SQL) or "" inside quoted identifiers
				if j+1 < len(s) && s[j+1] == quote {
					j += 2
					continue
				}
				return s[i : j+1], j + 1
			}
			j++
		}
		return s[i:], len(s)
	}

	for i := 0; i < len(s); {
		r := s[i]
		// whitespace
		if unicode.IsSpace(rune(r)) {
			i++
			continue
		}
		// parentheses adjust depth (emit as symbol)
		if r == '(' {
			out = append(out, token{val: "(", kind: tkSymbol, depth: depth})
			depth++
			i++
			continue
		}
		if r == ')' {
			depth--
			if depth < 0 {
				depth = 0
			}
			out = append(out, token{val: ")", kind: tkSymbol, depth: depth})
			i++
			continue
		}
		// strings: single quotes = literals, double quotes = quoted identifiers in many SQL dialects
		if r == '\'' || r == '"' {
			str, nx := readString(i, r)
			kind := tkString
			// Treat quoted identifiers (") as identifiers to help FROM detection.
			if r == '"' {
				out = append(out, token{val: strings.ToLower(str), kind: tkIdent, depth: depth})
			} else {
				out = append(out, token{val: str, kind: kind, depth: depth})
			}
			i = nx
			continue
		}
		// numbers
		if isNumStart(r) {
			j := i + 1
			for j < len(s) && (isNum(s[j]) || s[j] == '.') {
				j++
			}
			out = append(out, token{val: s[i:j], kind: tkNumber, depth: depth})
			i = j
			continue
		}
		// identifiers / keywords (include dots and $ to allow db.schema.table, functions, etc.)
		if isIdentStart(r) {
			j := i + 1
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			word := strings.ToLower(s[i:j])
			if _, ok := keywords[word]; ok {
				out = append(out, token{val: word, kind: tkKeyword, depth: depth})
			} else {
				out = append(out, token{val: word, kind: tkIdent, depth: depth})
			}
			i = j
			continue
		}
		// symbols/operators
		out = append(out, token{val: strings.ToLower(string(r)), kind: tkSymbol, depth: depth})
		i++
	}
	return out
}

func isIdentStart(b byte) bool { return unicode.IsLetter(rune(b)) || b == '_' }
func isIdentPart(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b)) || b == '_' || b == '.' || b == '$'
}
func isNumStart(b byte) bool { return unicode.IsDigit(rune(b)) }
func isNum(b byte) bool      { return unicode.IsDigit(rune(b)) }

func findNextKeywordAtDepth(toks []token, start, depth int, word string) int {
	for i := start; i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}
		if toks[i].kind == tkKeyword && toks[i].val == word {
			return i
		}
		// statement terminators: stop scanning for this block
		if toks[i].depth < depth {
			return -1
		}
	}
	return -1
}

func findNextKeywordBetweenAtDepth(toks []token, start, stop, depth int, word string) int {
	if stop < 0 {
		stop = len(toks)
	}
	for i := start; i < stop && i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}
		if toks[i].kind == tkKeyword && toks[i].val == word {
			return i
		}
	}
	return -1
}

func findNextTerminatorAtDepth(toks []token, start, depth int) int {
	for i := start; i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}
		if toks[i].kind == tkKeyword {
			switch toks[i].val {
			case "where", "group", "order", "having", "union", "intersect", "except":
				return i
			}
		}
	}
	return len(toks)
}

// fromStartsWithIdentifier returns true if FROM's first source token at this depth
// looks like a table name (identifier or quoted ident), not a subquery '('.
func fromStartsWithIdentifier(toks []token, start, stop, depth int) bool {
	for i := start; i < stop && i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}
		// skip AS/alias/joins appearing right after FROM due to malformed SQL
		if toks[i].kind == tkKeyword {
			// If we immediately see SELECT, it’s a subquery via LATERAL (rare) -> not a base table.
			if toks[i].val == "select" {
				return false
			}
			// skip join keywords until we see a real source token
			continue
		}
		// '(' means subquery/derived table
		if toks[i].kind == tkSymbol && toks[i].val == "(" {
			return false
		}
		// identifier that is not followed immediately by '(' (which would look like a function call)
		if toks[i].kind == tkIdent {
			// peek next non-space token at same depth
			j := i + 1
			for j < stop && toks[j].depth != depth {
				j++
			}
			if j < stop && toks[j].kind == tkSymbol && toks[j].val == "(" {
				// something like func_name( ... ) right after FROM -> likely not a table
				return false
			}
			return true
		}
		// numbers or others as first token -> assume not a base table
		if toks[i].kind == tkNumber {
			return false
		}
	}
	return false
}

func whereHasTimePredicate(toks []token, start, stop, depth int, timeCols []string) bool {
	if stop < 0 {
		stop = len(toks)
	}
	// scan for any occurrence of <timeCol> <op> ... or BETWEEN ... on <timeCol>
	for i := start; i < stop && i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}
		// simple comparison operators
		if toks[i].kind == tkIdent && isIn(toks[i].val, timeCols) {
			// look ahead for operator at same depth
			j := i + 1
			for j < stop && toks[j].depth != depth {
				j++
			}
			if j < stop && toks[j].kind == tkSymbol && isCompareOp(toks[j].val) {
				return true
			}
			// BETWEEN pattern: time BETWEEN ...
			if j < stop && toks[j].kind == tkKeyword && toks[j].val == "between" {
				return true
			}
		}

		// Also handle BETWEEN with column potentially after NOT (rare): "NOT time BETWEEN ..." is still a time predicate
		// We simplify by: if we see 'between', look left within a small window for time column.
		if toks[i].kind == tkKeyword && toks[i].val == "between" {
			for k := i - 1; k >= start && k >= i-4; k-- {
				if toks[k].depth != depth {
					continue
				}
				if toks[k].kind == tkIdent && isIn(toks[k].val, timeCols) {
					return true
				}
			}
		}
	}
	return false
}

func isCompareOp(s string) bool {
	switch s {
	case "=", "<", ">", "<=", ">=", "<>":
		return true
	}
	return false
}

func isIn(s string, arr []string) bool {
	for _, v := range arr {
		if s == v {
			return true
		}
	}
	return false
}

func snippetAroundTokens(toks []token, start, stop int) string {
	if start < 0 {
		start = 0
	}
	if stop < 0 || stop > len(toks) {
		stop = len(toks)
	}
	var b strings.Builder
	limit := 220
	for i := start; i < stop; i++ {
		if len(b.String()) > limit {
			b.WriteString(" ...")
			break
		}
		b.WriteString(toks[i].val)
		if i+1 < stop {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}
