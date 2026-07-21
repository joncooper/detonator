// Package artifact unpacks npm and PyPI distribution files into an in-memory
// file list for static analysis and diffing. It never writes package contents
// to disk and never executes them — unpacking is pure inspection.
//
// Every reader is bounded: a hostile artifact can't exhaust memory via a zip
// bomb, a giant member, or too many entries.
package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/joncooper/detonator/internal/verdict"
)

const (
	maxFiles       = 20000
	maxFileSize    = 32 << 20  // 32 MiB per member
	maxTotalSize   = 512 << 20 // 512 MiB uncompressed total
	maxContentKeep = 4 << 20   // only retain the first 4 MiB of a file's bytes for analysis
)

// File is one entry from an unpacked artifact. Content may be truncated to
// maxContentKeep bytes; Size is the true uncompressed size.
type File struct {
	Path      string
	Content   []byte
	Size      int64
	Truncated bool
}

// Unpacked is the result of unpacking one artifact.
type Unpacked struct {
	Files []File
	// byPath indexes Files for lookup; built by index().
	byPath map[string]*File
}

// Lookup returns the file at logical path p (after ecosystem prefix
// normalization), or nil.
func (u *Unpacked) Lookup(p string) *File {
	if u.byPath == nil {
		u.index()
	}
	return u.byPath[p]
}

// Paths returns all logical file paths.
func (u *Unpacked) Paths() []string {
	ps := make([]string, len(u.Files))
	for i := range u.Files {
		ps[i] = u.Files[i].Path
	}
	return ps
}

func (u *Unpacked) index() {
	u.byPath = make(map[string]*File, len(u.Files))
	for i := range u.Files {
		u.byPath[u.Files[i].Path] = &u.Files[i]
	}
}

// Unpack dispatches on ecosystem and filename. npm publishes gzipped tarballs
// with everything under "package/"; PyPI ships sdists (gzipped tar) and wheels
// (zip). The ecosystem-specific top-level prefix is stripped so callers see
// stable logical paths (e.g. "package.json", "setup.py").
func Unpack(eco verdict.Ecosystem, filename string, data []byte) (*Unpacked, error) {
	switch {
	case eco == verdict.NPM:
		return unpackTarGz(data, "package/")
	case eco == verdict.PyPI && strings.HasSuffix(filename, ".whl"):
		return unpackZip(data)
	case eco == verdict.PyPI:
		// sdist: strip the top "<name>-<version>/" directory.
		return unpackTarGz(data, "")
	default:
		return nil, fmt.Errorf("artifact: unsupported %s file %q", eco, filename)
	}
}

// UnpackAuto unpacks an artifact using only its ecosystem and bytes, sniffing
// the container format by magic number. npm is always a gzipped tar; PyPI is a
// zip (wheel) or gzipped tar (sdist). This lets callers that hold only the
// bytes (the gate) unpack without the original filename.
func UnpackAuto(eco verdict.Ecosystem, data []byte) (*Unpacked, error) {
	switch {
	case eco == verdict.NPM:
		return unpackTarGz(data, "package/")
	case eco == verdict.PyPI && isZip(data):
		return unpackZip(data)
	case eco == verdict.PyPI:
		return unpackTarGz(data, "")
	default:
		return nil, fmt.Errorf("artifact: unsupported ecosystem %q", eco)
	}
}

func isZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04
}

func unpackTarGz(data []byte, stripPrefix string) (*Unpacked, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("artifact: gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var (
		u     Unpacked
		total int64
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("artifact: tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if len(u.Files) >= maxFiles {
			return nil, fmt.Errorf("artifact: too many files (>%d)", maxFiles)
		}
		if hdr.Size > maxFileSize {
			return nil, fmt.Errorf("artifact: member %q exceeds %d bytes", hdr.Name, maxFileSize)
		}
		total += hdr.Size
		if total > maxTotalSize {
			return nil, fmt.Errorf("artifact: uncompressed total exceeds %d bytes", maxTotalSize)
		}
		content, truncated, err := readCapped(tr)
		if err != nil {
			return nil, err
		}
		u.Files = append(u.Files, File{
			Path:      logicalPath(hdr.Name, stripPrefix),
			Content:   content,
			Size:      hdr.Size,
			Truncated: truncated,
		})
	}
	u.index()
	return &u, nil
}

func unpackZip(data []byte) (*Unpacked, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("artifact: zip: %w", err)
	}
	var (
		u     Unpacked
		total int64
	)
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if len(u.Files) >= maxFiles {
			return nil, fmt.Errorf("artifact: too many files (>%d)", maxFiles)
		}
		if zf.UncompressedSize64 > maxFileSize {
			return nil, fmt.Errorf("artifact: member %q exceeds %d bytes", zf.Name, maxFileSize)
		}
		total += int64(zf.UncompressedSize64)
		if total > maxTotalSize {
			return nil, fmt.Errorf("artifact: uncompressed total exceeds %d bytes", maxTotalSize)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("artifact: open %q: %w", zf.Name, err)
		}
		content, truncated, err := readCapped(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		u.Files = append(u.Files, File{
			Path:      logicalPath(zf.Name, ""),
			Content:   content,
			Size:      int64(zf.UncompressedSize64),
			Truncated: truncated,
		})
	}
	u.index()
	return &u, nil
}

// readCapped reads up to maxContentKeep+1 bytes, reporting truncation, and
// drains the rest so size accounting stays correct.
func readCapped(r io.Reader) (content []byte, truncated bool, err error) {
	b, err := io.ReadAll(io.LimitReader(r, maxContentKeep+1))
	if err != nil {
		return nil, false, fmt.Errorf("artifact: read: %w", err)
	}
	if len(b) > maxContentKeep {
		b = b[:maxContentKeep]
		truncated = true
		_, _ = io.Copy(io.Discard, r) // drain remainder
	}
	return b, truncated, nil
}

// logicalPath normalizes an archive member name: it cleans traversal, strips a
// known ecosystem prefix (npm's "package/"), and for sdists strips the leading
// "<name>-<version>/" component so paths are comparable across versions.
func logicalPath(name, stripPrefix string) string {
	name = strings.TrimPrefix(name, "./")
	name = path.Clean("/" + name)[1:] // defang ".." and absolute paths
	if stripPrefix != "" {
		return strings.TrimPrefix(name, stripPrefix)
	}
	// sdist: drop the first path segment (the "<name>-<version>" dir).
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}
