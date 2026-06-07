package dict

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// dictSource opens dictionary files for the parser. Each source has its own
// path namespace — names passed to Open are interpreted by the source.
//
// For the embedded tree, names look like `dhcpv4/dictionary.rfc2131`. For a
// user-supplied directory, names are file basenames inside that directory.
// The parser keeps the current source for the file it's parsing and lets
// $INCLUDE resolve relative to that file within the same source.
type dictSource interface {
	Open(name string) (io.ReadCloser, error)
	Name() string
}

// embeddedSource serves dictionary files out of an embed.FS rooted at root.
type embeddedSource struct {
	fs   embed.FS
	root string
}

func (s *embeddedSource) Open(name string) (io.ReadCloser, error) {
	return s.fs.Open(path.Join(s.root, name))
}

func (s *embeddedSource) Name() string { return "embedded" }

// fileSource serves dictionary files from a real directory on disk. The
// parser opens a file by its basename inside dir.
type fileSource struct {
	dir string
}

func (s *fileSource) Open(name string) (io.ReadCloser, error) {
	full := filepath.Join(s.dir, name)
	// Refuse path-escape attempts so the source is a real filesystem
	// sandbox, matching embed.FS's behaviour.
	if !strings.HasPrefix(filepath.Clean(full), filepath.Clean(s.dir)) {
		return nil, fmt.Errorf("path escapes source root: %q", name)
	}
	return os.Open(full)
}

func (s *fileSource) Name() string { return "custom:" + s.dir }

// customLayer pairs a source with the root file the parser should kick off
// at within that source. Expanding a single --dict path produces one or
// more layers (a directory expands into one layer per `dictionary*` file
// in lex order).
type customLayer struct {
	source   dictSource
	rootFile string
}

// expandDictPath turns a user-supplied --dict path into one or more
// customLayer values. A directory produces one layer per matching file; a
// file produces a single layer.
func expandDictPath(p string) ([]customLayer, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("dictionary %q: %v", p, err)
	}
	if info.IsDir() {
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("dictionary directory %q: %v", p, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			// Convention from FreeRADIUS: load files whose name starts
			// with "dictionary". Anything else is ignored so users can
			// keep notes / scripts in the same directory.
			if !strings.HasPrefix(n, "dictionary") {
				continue
			}
			names = append(names, n)
		}
		sort.Strings(names)
		if len(names) == 0 {
			return nil, fmt.Errorf("dictionary directory %q: no dictionary* files", p)
		}
		src := &fileSource{dir: p}
		out := make([]customLayer, 0, len(names))
		for _, n := range names {
			out = append(out, customLayer{source: src, rootFile: n})
		}
		return out, nil
	}
	// Single file — rooted at the file's directory.
	src := &fileSource{dir: filepath.Dir(p)}
	return []customLayer{{source: src, rootFile: filepath.Base(p)}}, nil
}
