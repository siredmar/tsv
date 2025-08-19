package tsv

// A tolerant SQL validator for AWS Timestream queries.
// It ensures that every SELECT which directly reads from a base table
// (not just from a subquery/CTE alias) has a time predicate in WHERE.
//
// Heuristics (no full SQL parse):
//   - We lex tokens, track parentheses depth, and find SELECT blocks.
//   - For each SELECT, we locate FROM and WHERE at the same depth.
//   - A SELECT is considered "hits DB" if the FROM source looks like a base
//     table name (db.table or "db"."table"). If it's just an alias (e.g. a),
//     or starts with '(' (subquery), we skip it at that level; inner SELECTs
//     are validated separately.
//   - A valid time filter is any predicate in WHERE that references one of
//     the allowed time columns (default: time, measure_time) and uses BETWEEN
//     (with optional NOT) or comparison operators (=, <, <=, >, >=, <>, !=).

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

	// Preprocess: strip comments, then lex.
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
		// Find FROM at same depth after this SELECT.
		fromIdx := findNextKeywordAtDepth(toks, s.selIdx+1, s.depth, "from")
		if fromIdx == -1 {
			// SELECT without FROM (e.g., SELECT 1): ignore (doesn't hit DB).
			continue
		}

		// Determine the span of the FROM clause (until GROUP/ORDER/HAVING/UNION/INTERSECT/EXCEPT,
		// or when the block closes: depth drops below this select's depth).
		stopIdx := findNextTerminatorAtDepth(toks, fromIdx+1, s.depth)

		// Decide if this SELECT directly reads from a base table (not a subquery-first source or CTE alias).
		hitsDB := fromStartsWithBaseTable(toks, fromIdx+1, stopIdx, s.depth)

		// If it doesn't hit DB at this level, inner SELECTs (if any) will be validated separately.
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

		// WHERE span: from whereIdx+1 until next clause keyword or terminator at same depth,
		// or when block closes (depth drops below this select's depth).
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
			// Treat quoted identifiers (") as identifiers to help FROM/column detection.
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
		// multi-char operators (>=, <=, <>, !=)
		if (r == '>' || r == '<' || r == '!') && i+1 < len(s) {
			n := s[i+1]
			if (r == '>' && n == '=') || (r == '<' && (n == '=' || n == '>')) || (r == '!' && n == '=') {
				out = append(out, token{val: strings.ToLower(s[i : i+2]), kind: tkSymbol, depth: depth})
				i += 2
				continue
			}
		}
		// single-char symbols/operators (including =, <, >, ., , etc.)
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

// IMPORTANT: Do NOT treat WHERE as a terminator when scanning FROM.
// We want to be able to find WHERE after scanning the FROM block.
// However, if the block closes (depth drops below 'depth'), we must stop
// to avoid bleeding into the following CTE/subquery.
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

// fromStartsWithBaseTable returns true if FROM's first source token at this depth
// looks like a base table name (db.table or "db"."table"), not a subquery '(',
// not a function call, and not just a CTE alias (single identifier without dot).
func fromStartsWithBaseTable(toks []token, start, stop, depth int) bool {
	i := start
	// find first token at same depth
	for i < stop && i < len(toks) && toks[i].depth != depth {
		i++
	}
	if i >= stop || i >= len(toks) {
		return false
	}
	// '(' means subquery/derived table
	if toks[i].kind == tkSymbol && toks[i].val == "(" {
		return false
	}
	// First ident?
	if toks[i].kind == tkIdent {
		// If ident contains '.', assume qualified name -> base table.
		if strings.Contains(stripQuotes(toks[i].val), ".") {
			// Ensure it's not immediately a function call (name(...))
			j := i + 1
			for j < stop && toks[j].depth != depth {
				j++
			}
			if j < stop && toks[j].kind == tkSymbol && toks[j].val == "(" {
				return false
			}
			return true
		}
		// If pattern is ident '.' ident (for quoted identifiers), treat as table.
		if i+2 < stop &&
			toks[i+1].depth == depth && toks[i+1].kind == tkSymbol && toks[i+1].val == "." &&
			toks[i+2].depth == depth && toks[i+2].kind == tkIdent {
			return true
		}
		// Single-part identifier (e.g., alias/CTE name) -> assume NOT a base table.
		return false
	}
	return false
}

func whereHasTimePredicate(toks []token, start, stop, depth int, timeCols []string) bool {
	if stop < 0 {
		stop = len(toks)
	}
	for i := start; i < stop && i < len(toks); i++ {
		if toks[i].depth != depth {
			continue
		}

		// Check for simple comparison on time column:
		if ok, _ := isTimeIdentifierAt(toks, i, depth, timeCols); ok {
			// Look ahead for operator at same depth (optionally allow NOT before BETWEEN).
			j := i + 1
			// skip any non-depth tokens
			for j < stop && toks[j].depth != depth {
				j++
			}
			// If NOT BETWEEN pattern: time NOT BETWEEN ...
			if j < stop && toks[j].kind == tkKeyword && toks[j].val == "not" {
				k := j + 1
				for k < stop && toks[k].depth != depth {
					k++
				}
				if k < stop && toks[k].kind == tkKeyword && toks[k].val == "between" {
					return true
				}
			}
			// If BETWEEN pattern: time BETWEEN ...
			if j < stop && toks[j].kind == tkKeyword && toks[j].val == "between" {
				return true
			}
			// Comparison operator pattern
			if j < stop && toks[j].kind == tkSymbol && isCompareOp(toks[j].val) {
				return true
			}
		}

		// Also handle encountering BETWEEN first, then look back for time column within a small window.
		if toks[i].kind == tkKeyword && toks[i].val == "between" {
			// Look left within a small window for a time identifier (consider optional NOT).
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
// It supports forms: time, measure_time, alias.time, "alias"."time", and ident tokens
// that already contain a dot (e.g., s1.time).
func isTimeIdentifierAt(toks []token, i, depth int, timeCols []string) (bool, string) {
	if i < 0 || i >= len(toks) {
		return false, ""
	}
	if toks[i].depth != depth || toks[i].kind != tkIdent {
		return false, ""
	}

	// Normalize this identifier (strip quotes).
	cur := stripQuotes(toks[i].val)

	// If token already contains a dot (e.g., s1.time), check the last part.
	if strings.Contains(cur, ".") {
		last := cur[strings.LastIndex(cur, ".")+1:]
		if inStrSlice(last, timeCols) {
			return true, last
		}
	}

	// Pattern: ident '.' ident (handles "s1"."time")
	if i+2 < len(toks) &&
		toks[i+1].depth == depth && toks[i+1].kind == tkSymbol && toks[i+1].val == "." &&
		toks[i+2].depth == depth && toks[i+2].kind == tkIdent {
		last := stripQuotes(toks[i+2].val)
		if inStrSlice(last, timeCols) {
			return true, last
		}
	}

	// Single-part identifier: compare directly.
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
