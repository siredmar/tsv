package tsv

// A tolerant SQL validator for AWS Timestream queries.
// It ensures that every SELECT which directly reads from a base table
// (not just from a subquery/CTE alias) has a time predicate in WHERE.
//
// Heuristics (no full SQL parse):
//   - We lex tokens, track parentheses depth, and find SELECT blocks.
//   - For each SELECT, we locate FROM and WHERE at the same depth.
//   - A SELECT is considered "hits DB" if the FROM source looks like a base
//     table name (db.table, "db"."table", or macros like $__database.$__table).
//     If it's just an alias (e.g. a), or starts with '(' (subquery), we skip it
//     at that level; inner SELECTs are validated separately.
//   - A valid time filter is any predicate in WHERE that references one of
//     the allowed time columns (default: time, measure_time) and uses BETWEEN
//     (with optional NOT) or comparison operators (=, <, <=, >, >=, <>, !=).
//   - WHERE also counts as valid if it contains the Grafana macro $__timeFilter
//     (case-insensitive; we lowercase tokens).
//
// Note: This is intentionally heuristic and aims to be practical for Timestream.

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
	Snippet string
	Reason  string
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

	src := stripComments(sql)
	toks := lex(src)

	type sel struct {
		selIdx int
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
		// Find FROM at same depth after this SELECT.
		fromIdx := findNextKeywordAtDepth(toks, s.selIdx+1, s.depth, "from")
		if fromIdx == -1 {
			// SELECT without FROM (e.g., SELECT 1): ignore (doesn't hit DB).
			continue
		}

		// FROM clause ends at next clause keyword (excluding WHERE) or when depth drops.
		stopIdx := findNextTerminatorAtDepth(toks, fromIdx+1, s.depth)

		// Decide if this SELECT directly reads from a base table (not subquery or CTE alias).
		hitsDB := fromStartsWithBaseTable(toks, fromIdx+1, stopIdx, s.depth)
		if !hitsDB {
			// Outer SELECT over CTE/derived table — inner SELECTs will be validated separately.
			continue
		}

		// WHERE must be present at same depth between FROM and its terminator.
		whereIdx := findNextKeywordBetweenAtDepth(toks, fromIdx+1, stopIdx, s.depth, "where")
		if whereIdx == -1 {
			issues = append(issues, Issue{
				Snippet: snippetAroundTokens(toks, s.selIdx, stopIdx),
				Reason:  "missing WHERE clause with time filter",
				AtDepth: s.depth,
			})
			continue
		}

		// WHERE body ends at next clause (group/order/having/union/...) or on depth drop.
		whereStop := findNextTerminatorAtDepth(toks, whereIdx+1, s.depth)

		// Malformed WHERE like "WHERE\n AND ..." (no predicate before conjunction) should fail.
		if whereStartsWithConjunction(toks, whereIdx+1, whereStop, s.depth) {
			issues = append(issues, Issue{
				Snippet: snippetAroundTokens(toks, s.selIdx, whereStop),
				Reason:  "WHERE clause starts with AND/OR; no predicate before it",
				AtDepth: s.depth,
			})
			continue
		}

		// Check for time predicate or $__timeFilter macro.
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
				// handle escaped '' or "" inside literals/quoted idents
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

		// Handle literal escape sequences often present in serialized SQL (e.g., "\n", \"Device\")
		if r == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n', 'r', 't':
				// treat as whitespace: skip both
				i += 2
				continue
			case '"', '\'', '\\':
				// skip the backslash; next loop will process the quoted char
				i++
				continue
			}
			// fall through: treat '\' as a symbol if not a known escape
		}

		// whitespace
		if unicode.IsSpace(rune(r)) {
			i++
			continue
		}
		// parentheses adjust depth
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
		// strings / quoted identifiers
		if r == '\'' || r == '"' {
			str, nx := readString(i, r)
			if r == '"' {
				// treat "ident" as identifier (lowercased, quotes kept for context)
				out = append(out, token{val: strings.ToLower(str), kind: tkIdent, depth: depth})
			} else {
				out = append(out, token{val: str, kind: tkString, depth: depth})
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
		// identifiers / keywords
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
		// multi-char operators (>=, <=, <>, !=)
		if (r == '>' || r == '<' || r == '!') && i+1 < len(s) {
			n := s[i+1]
			if (r == '>' && n == '=') || (r == '<' && (n == '=' || n == '>')) || (r == '!' && n == '=') {
				out = append(out, token{val: strings.ToLower(s[i : i+2]), kind: tkSymbol, depth: depth})
				i += 2
				continue
			}
		}
		// single-char symbols
		out = append(out, token{val: strings.ToLower(string(r)), kind: tkSymbol, depth: depth})
		i++
	}
	return out
}

// allow '$' so macros like $__database.$__table and $__timeFilter tokenize as identifiers
func isIdentStart(b byte) bool { return unicode.IsLetter(rune(b)) || b == '_' || b == '$' }
func isIdentPart(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b)) || b == '_' || b == '.' || b == '$'
}
func isNumStart(b byte) bool { return unicode.IsDigit(rune(b)) }
func isNum(b byte) bool      { return unicode.IsDigit(rune(b)) }

func findNextKeywordAtDepth(toks []token, start, depth int, word string) int {
	for i := start; i < len(toks); i++ {
		// If we exited this block, abort.
		if toks[i].depth < depth {
			return -1
		}
		if toks[i].depth != depth {
			continue
		}
		if toks[i].kind == tkKeyword && toks[i].val == word {
			return i
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

// Do NOT treat WHERE as a terminator when scanning FROM.
// Terminate on other clause keywords at same depth or when the depth drops.
func findNextTerminatorAtDepth(toks []token, start, depth int) int {
	for i := start; i < len(toks); i++ {
		// Block ended (e.g., we hit a closing parenthesis).
		if toks[i].depth < depth {
			return i
		}
		// Clause terminators at the same depth.
		if toks[i].depth == depth && toks[i].kind == tkKeyword {
			switch toks[i].val {
			case "group", "order", "having", "union", "intersect", "except":
				return i
			}
		}
	}
	return len(toks)
}

// Returns true if FROM's first source at this depth looks like a base table:
//   - single identifier containing a dot (db.table or $__db.$__table) and not a function call
//   - pattern: ident '.' ident  (covers "db"."table" and unquoted db.table split into parts)
//
// Skips over stray symbols/keywords (e.g., serialized "\n").
// Returns false for '(' (subquery) or single-part identifier (likely CTE alias).
func fromStartsWithBaseTable(toks []token, start, stop, depth int) bool {
	i := start

	// Advance to first meaningful token at this depth
	for i < stop && i < len(toks) {
		if toks[i].depth != depth {
			i++
			continue
		}
		// Skip stray symbols except '(' (which indicates subquery).
		if toks[i].kind == tkSymbol {
			if toks[i].val == "(" {
				return false
			}
			i++
			continue
		}
		// Skip keywords like LATERAL/AS/ON etc. If we hit SELECT, it's a subquery-ish form.
		if toks[i].kind == tkKeyword {
			if toks[i].val == "select" {
				return false
			}
			i++
			continue
		}
		break
	}

	if i >= stop || i >= len(toks) {
		return false
	}

	// identifier?
	if toks[i].kind == tkIdent {
		// ident containing '.' => qualified name (db.table or $__db.$__table)
		if strings.Contains(stripQuotes(toks[i].val), ".") {
			// Ensure it's not immediately a function call ident(...)
			j := i + 1
			for j < stop && toks[j].depth != depth {
				j++
			}
			if j < stop && toks[j].kind == tkSymbol && toks[j].val == "(" {
				return false
			}
			return true
		}
		// ident '.' ident (covers "db"."table" or db . table)
		if i+2 < stop &&
			toks[i+1].depth == depth && toks[i+1].kind == tkSymbol && toks[i+1].val == "." &&
			toks[i+2].depth == depth && toks[i+2].kind == tkIdent {
			return true
		}
		// Single-part identifier => likely CTE alias; not base table.
		return false
	}

	return false
}

// True if WHERE body is empty or begins with AND/OR (malformed "WHERE\n AND ...").
// Skips stray serialized escape tokens like "\n" (backslash + 'n').
func whereStartsWithConjunction(toks []token, start, stop, depth int) bool {
	// find first meaningful token at this depth
	i := start
	for i < stop && i < len(toks) {
		if toks[i].depth != depth {
			i++
			continue
		}
		// Skip serialized escape pair "\n"
		if toks[i].kind == tkSymbol && toks[i].val == `\` {
			// if next token is 'n' identifier, skip both
			if i+1 < stop && toks[i+1].depth == depth && toks[i+1].kind == tkIdent && toks[i+1].val == "n" {
				i += 2
				continue
			}
			// otherwise just skip the stray symbol
			i++
			continue
		}
		// Skip other stray symbols at this depth
		if toks[i].kind == tkSymbol {
			i++
			continue
		}
		break
	}
	if i >= stop || i >= len(toks) {
		return true // empty WHERE body
	}
	return toks[i].kind == tkKeyword && (toks[i].val == "and" || toks[i].val == "or")
}

func whereHasTimePredicate(toks []token, start, stop, depth int, timeCols []string) bool {
	if stop < 0 {
		stop = len(toks)
	}
	// Accept Grafana $__timeFilter macro anywhere in WHERE.
	for i := start; i < stop && i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}
		if toks[i].kind == tkIdent && strings.Contains(toks[i].val, "$__timefilter") {
			return true
		}
	}

	for i := start; i < stop && i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}

		// Simple comparisons: time [op] ...
		if ok, _ := isTimeIdentifierAt(toks, i, depth, timeCols); ok {
			j := i + 1
			for j < stop && toks[j].depth != depth {
				j++
			}
			// NOT BETWEEN
			if j < stop && toks[j].kind == tkKeyword && toks[j].val == "not" {
				k := j + 1
				for k < stop && toks[k].depth != depth {
					k++
				}
				if k < stop && toks[k].kind == tkKeyword && toks[k].val == "between" {
					return true
				}
			}
			// BETWEEN
			if j < stop && toks[j].kind == tkKeyword && toks[j].val == "between" {
				return true
			}
			// Comparison operator
			if j < stop && toks[j].kind == tkSymbol && isCompareOp(toks[j].val) {
				return true
			}
		}

		// BETWEEN first, then look back for time column
		if toks[i].kind == tkKeyword && toks[i].val == "between" {
			for k := i - 1; k >= start && k >= i-6; k-- {
				if toks[k].depth != depth {
					continue
				}
				if toks[k].kind == tkKeyword && toks[k].val == "not" {
					continue
				}
				if ok, _ := isTimeIdentifierAt(toks, k, depth, timeCols); ok {
					return true
				}
			}
		}
	}
	return false
}

func isCompareOp(s string) bool {
	switch s {
	case "=", "<", ">", "<=", ">=", "<>", "!=":
		return true
	}
	return false
}

func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return strings.ToLower(s[1 : len(s)-1])
	}
	return strings.ToLower(s)
}

// isTimeIdentifierAt checks if tokens at position i denote a time column.
// Supports: time, measure_time, alias.time, "alias"."time", and ident tokens with dot (e.g., s1.time).
func isTimeIdentifierAt(toks []token, i, depth int, timeCols []string) (bool, string) {
	if i < 0 || i >= len(toks) {
		return false, ""
	}
	if toks[i].depth != depth || toks[i].kind != tkIdent {
		return false, ""
	}

	cur := stripQuotes(toks[i].val)

	// ident containing dot
	if strings.Contains(cur, ".") {
		last := cur[strings.LastIndex(cur, ".")+1:]
		if inStrSlice(last, timeCols) {
			return true, last
		}
	}

	// ident '.' ident (handles "s1"."time")
	if i+2 < len(toks) &&
		toks[i+1].depth == depth && toks[i+1].kind == tkSymbol && toks[i+1].val == "." &&
		toks[i+2].depth == depth && toks[i+2].kind == tkIdent {
		last := stripQuotes(toks[i+2].val)
		if inStrSlice(last, timeCols) {
			return true, last
		}
	}

	// single-part identifier
	if inStrSlice(cur, timeCols) {
		return true, cur
	}

	return false, ""
}

func inStrSlice(s string, arr []string) bool {
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
		if b.Len() > limit {
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
