// Package testutil builds synthetic package artifacts for tests. It is imported
// only by test code; nothing in the shipped binary depends on it.
package testutil

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
)

// NPMTarball builds a gzipped npm tarball with the given files placed under the
// conventional "package/" prefix.
func NPMTarball(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		_ = tw.WriteHeader(&tar.Header{
			Name: "package/" + name, Mode: 0o644,
			Size: int64(len(content)), Typeflag: tar.TypeReg,
		})
		_, _ = tw.Write([]byte(content))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// PyPISdist builds a gzipped sdist with files under a "<name>-<version>/" root.
func PyPISdist(root string, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		_ = tw.WriteHeader(&tar.Header{
			Name: root + "/" + name, Mode: 0o644,
			Size: int64(len(content)), Typeflag: tar.TypeReg,
		})
		_, _ = tw.Write([]byte(content))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// Wheel builds a zip-format wheel with the given files.
func Wheel(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	_ = zw.Close()
	return buf.Bytes()
}
