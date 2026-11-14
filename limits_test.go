package archives

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zip"
)

// makeTar builds a tar archive in memory containing the given files.
// Names ending in "/" are written as directory entries.
func makeTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if strings.HasSuffix(name, "/") {
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makeTarGz builds a gzipped tar archive in memory containing the given files.
func makeTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makeManyFileTar builds a tar archive with n small files in memory.
func makeManyFileTar(t *testing.T, n int) []byte {
	t.Helper()
	files := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		files[fmt.Sprintf("file%04d.txt", i)] = []byte("x")
	}
	return makeTar(t, files)
}

// makeZip builds a zip archive in memory with n small files.
func makeZip(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		f, err := zw.Create(fmt.Sprintf("file%04d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractMaxEntriesTar(t *testing.T) {
	archive := makeManyFileTar(t, 10)
	ctx := WithLimits(context.Background(), Limits{MaxEntries: 3})

	var handled int
	err := Tar{}.Extract(ctx, bytes.NewReader(archive), func(ctx context.Context, info FileInfo) error {
		handled++
		return nil
	})
	if err == nil {
		t.Fatal("expected error when entry limit is exceeded, got nil")
	}
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit, got: %v", err)
	}
	var rlErr *ResourceLimitError
	if !errors.As(err, &rlErr) {
		t.Fatalf("expected ResourceLimitError, got: %T", err)
	}
	if rlErr.Limit != "entries" {
		t.Errorf("expected limit kind 'entries', got '%s'", rlErr.Limit)
	}
	if handled > 3 {
		t.Errorf("expected at most 3 handled entries, got %d", handled)
	}
}

func TestExtractMaxEntriesZip(t *testing.T) {
	archive := makeZip(t, 10)
	ctx := WithLimits(context.Background(), Limits{MaxEntries: 2})

	err := Zip{}.Extract(ctx, bytes.NewReader(archive), func(ctx context.Context, info FileInfo) error {
		return nil
	})
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit, got: %v", err)
	}
}

func TestExtractMaxDecompressedBytes(t *testing.T) {
	content := bytes.Repeat([]byte("a"), 4096)
	archive := makeTar(t, map[string][]byte{"big.txt": content})

	ctx := WithLimits(context.Background(), Limits{MaxDecompressedBytes: 1024})
	err := Tar{}.Extract(ctx, bytes.NewReader(archive), func(ctx context.Context, info FileInfo) error {
		file, err := info.Open()
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(io.Discard, file)
		return err
	})
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit, got: %v", err)
	}
	var rlErr *ResourceLimitError
	if errors.As(err, &rlErr) && rlErr.Limit != "decompressed bytes" {
		t.Errorf("expected limit kind 'decompressed bytes', got '%s'", rlErr.Limit)
	}
}

func TestExtractMaxCompressionRatioTarGz(t *testing.T) {
	// 1 MB of zeros compresses to roughly 1 KB: a ratio of ~1000
	archive := makeTarGz(t, map[string][]byte{"zeros.bin": make([]byte, 1<<20)})
	if int64(len(archive))*100 > 1<<20 {
		t.Skipf("test archive not compressible enough: %d bytes", len(archive))
	}

	format := CompressedArchive{Archival: Tar{}, Extraction: Tar{}, Compression: Gz{}}
	ctx := WithLimits(context.Background(), Limits{MaxCompressionRatio: 100})
	err := format.Extract(ctx, bytes.NewReader(archive), func(ctx context.Context, info FileInfo) error {
		file, err := info.Open()
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(io.Discard, file)
		return err
	})
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit, got: %v", err)
	}
}

func TestExtractNormalArchiveWithinLimits(t *testing.T) {
	files := map[string][]byte{
		"a.txt":     []byte("hello"),
		"dir/b.txt": []byte("world"),
	}
	archive := makeTar(t, files)

	// generous limits must not interfere with normal archives
	ctx := WithLimits(context.Background(), Limits{
		MaxEntries:           100,
		MaxDecompressedBytes: 1 << 20,
		MaxCompressionRatio:  100,
	})
	seen := make(map[string]string)
	err := Tar{}.Extract(ctx, bytes.NewReader(archive), func(ctx context.Context, info FileInfo) error {
		if info.IsDir() {
			return nil
		}
		file, err := info.Open()
		if err != nil {
			return err
		}
		defer file.Close()
		content, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		seen[info.NameInArchive] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("normal archive should extract within limits: %v", err)
	}
	if len(seen) != 2 || seen["a.txt"] != "hello" || seen["dir/b.txt"] != "world" {
		t.Errorf("unexpected extracted contents: %v", seen)
	}
}

func TestExtractNormalTarGzWithinLimits(t *testing.T) {
	files := map[string][]byte{
		"a.txt": []byte("hello, this is a normal file"),
		"b.txt": []byte("and another one"),
	}
	archive := makeTarGz(t, files)

	format := CompressedArchive{Archival: Tar{}, Extraction: Tar{}, Compression: Gz{}}
	ctx := WithLimits(context.Background(), Limits{
		MaxEntries:           10,
		MaxDecompressedBytes: 1 << 20,
		MaxCompressionRatio:  1000,
	})
	var count int
	err := format.Extract(ctx, bytes.NewReader(archive), func(ctx context.Context, info FileInfo) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("normal compressed archive should extract within limits: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 entries, got %d", count)
	}
}

func TestArchiveFSReadDirEntryLimit(t *testing.T) {
	archive := makeManyFileTar(t, 10)
	archivePath := filepath.Join(t.TempDir(), "many.tar")
	if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := WithLimits(context.Background(), Limits{MaxEntries: 5})
	fsys, err := FileSystem(ctx, archivePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	// directory access must fail with a distinguishable error, and must
	// not present a partial listing as if it were complete
	entries, err := fs.ReadDir(fsys, ".")
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit from ReadDir, got: %v", err)
	}
	if entries != nil {
		t.Errorf("expected no entries on failure, got %d", len(entries))
	}

	// walking must also fail rather than silently truncate
	walkErr := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		return err
	})
	if !errors.Is(walkErr, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit from WalkDir, got: %v", walkErr)
	}
}

func TestArchiveFSOpenDecompressedByteLimit(t *testing.T) {
	archive := makeTarGz(t, map[string][]byte{"big.txt": bytes.Repeat([]byte("z"), 8192)})
	archivePath := filepath.Join(t.TempDir(), "big.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := WithLimits(context.Background(), Limits{MaxDecompressedBytes: 1024})
	fsys, err := FileSystem(ctx, archivePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	file, err := fsys.Open("big.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = io.Copy(io.Discard, file)
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("expected ErrResourceLimit while reading, got: %v", err)
	}
}

func TestArchiveFSNestedAccessWithinLimits(t *testing.T) {
	archive := makeTar(t, map[string][]byte{
		"dir/":          nil,
		"dir/sub/":      nil,
		"dir/sub/c.txt": []byte("nested content"),
		"dir/other.txt": []byte("other"),
		"toplevel.txt":  []byte("top"),
	})
	archivePath := filepath.Join(t.TempDir(), "nested.tar")
	if err := os.WriteFile(archivePath, archive, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := WithLimits(context.Background(), Limits{
		MaxEntries:           100,
		MaxDecompressedBytes: 1 << 20,
		MaxCompressionRatio:  100,
	})
	fsys, err := FileSystem(ctx, archivePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	// nested directory access must retain its original semantics
	subFS, ok := fsys.(fs.SubFS)
	if !ok {
		t.Fatal("expected fs.SubFS")
	}
	sub, err := subFS.Sub("dir")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(sub, "sub")
	if err != nil {
		t.Fatalf("nested ReadDir failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "c.txt" {
		t.Fatalf("unexpected nested entries: %v", entries)
	}

	content, err := fs.ReadFile(sub, "sub/c.txt")
	if err != nil {
		t.Fatalf("nested ReadFile failed: %v", err)
	}
	if string(content) != "nested content" {
		t.Errorf("unexpected nested content: %q", content)
	}
}
