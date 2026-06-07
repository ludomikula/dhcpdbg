package attrs

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/ludomikula/dhcpdbg/internal/dict"
)

// ReadList parses the `Attr = value` form (one per line, blank-line-separated
// records, `#` comments) into a slice of Pair lists — one per record. The
// reader resolves names against proto. Comma-separated continuations on a
// single line are NOT supported (matches radclient input).
//
// Errors include the offending line number and attribute name.
func ReadList(r io.Reader, proto *dict.Protocol) ([][]Pair, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out [][]Pair
	var current []Pair
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := stripLineComment(raw)
		if line == "" {
			if len(current) > 0 {
				out = append(out, current)
				current = nil
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: missing '=' in %q", lineNo, raw)
		}
		name := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Strip ":=" / "+=" variants — treat all as assignment.
		if strings.HasSuffix(name, ":") || strings.HasSuffix(name, "+") {
			name = strings.TrimRight(name, ":+")
			name = strings.TrimSpace(name)
		}
		a, ok := proto.AttrByName(name)
		if !ok {
			return nil, fmt.Errorf("line %d: unknown attribute %q", lineNo, name)
		}
		v, err := Parse(a, val, proto)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo, err)
		}
		current = append(current, Pair{Attr: a, Value: v})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no packets in input")
	}
	return out, nil
}

func stripLineComment(s string) string {
	// FreeRADIUS treats '#' as comment only outside of quoted strings.
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inQ = !inQ
		}
		if c == '#' && !inQ {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
}

// WriteList prints a single record to w in the same notation ReadList
// accepts, suitable for round-trip use.
func WriteList(w io.Writer, list []Pair) error {
	for _, p := range list {
		_, err := fmt.Fprintf(w, "%s = %s\n", p.Attr.Name, Format(p.Attr, p.Value))
		if err != nil {
			return err
		}
	}
	return nil
}
