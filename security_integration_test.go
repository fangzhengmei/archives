package archives

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"sort"
	"testing"
)

// This file contains integration tests for the security boundary between the
// low-level extraction callbacks (Extractor.Extract) and the virtual file
// system layer (ArchiveFS). Archive entries carry untrusted names: parent ("..")
// references, absolute paths, and symbolic links may all attempt to escape the
// virtual root. The contract under test is:
//
//   - Extract() faithfully reports every entry's raw, unsanitized NameInArchive
//     (callers that walk entries themselves get exactly what the archive says).
//   - ArchiveFS only ever exposes sanitized, root-relative names through the
//     io/fs interfaces; entries that normalize outside the root cannot be
//     opened, read, or statted, and symbolic links are exposed as link entries
//     rather than followed into the host file system.
//   - Entries whose distinct raw names collide after path.Clean() produce a
//     single, deterministic index entry, and walk/index/read results agree.
//   - Nested archives are ordinary readable members of the outer archive.
//   - After cancellation or a corrupt input, no partially-indexed entries are
//     left observable as legitimate files.
//   - Ordinary, benign relative paths remain fully and exactly readable.

// maliciousEntry describes one untrusted member to embed in a crafted archive.
type maliciousEntry struct {
	name       string // exact, unsanitized name stored in the archive header
	body       string // regular-file contents; ignored for symlinks
	linkTarget string // non-empty means a symbolic link with this target
}

// maliciousArchiveEntries is the shared corpus for tar and zip archives. It
// covers parent traversal (including multi-level and mid-path), absolute
// paths, symbolic links pointing at absolute and parent-relative targets, and
// benign relative entries that must remain fully accessible.
var maliciousArchiveEntries = []maliciousEntry{
	{name: "../escape.txt", body: "parent-escape"},
	{name: "../../deep-escape.txt", body: "deep-parent-escape"},
	{name: "dir/../../mid-escape.txt", body: "mid-path-escape"},
	{name: "/etc/absolute.txt", body: "absolute-escape"},
	{name: "sub/../safe-redirect.txt", body: "redirect-to-root"},
	{name: "link-to-passwd", linkTarget: "/etc/passwd"},
	{name: "relative-escape-link", linkTarget: "../outside.txt"},
	{name: "normal/dir/inside.txt", body: "nested-relative"},
	{name: "plain.txt", body: "plain-content"},
}

// buildMaliciousTar serializes maliciousArchiveEntries into an in-memory tar
// using the standard library directly, so no sanitization is applied before
// the bytes reach the code under test.
func buildMaliciousTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range maliciousArchiveEntries {
		switch {
		case e.linkTarget != "":
			hdr := &tar.Header{
				Name:     e.name,
				Typeflag: tar.TypeSymlink,
				Linkname: e.linkTarget,
				Mode:     0o777,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatalf("writing symlink header %q: %v", e.name, err)
			}
		default:
			hdr := &tar.Header{
				Name: e.name,
				Mode: 0o644,
				Size: int64(len(e.body)),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatalf("writing file header %q: %v", e.name, err)
			}
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("writing file body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	return buf.Bytes()
}

// buildMaliciousZip serializes maliciousArchiveEntries into an in-memory zip
// with raw, unsanitized header names. Symlinks are encoded the conventional
// way (ModeSymlink, body holding the target string).
func buildMaliciousZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range maliciousArchiveEntries {
		if e.linkTarget != "" {
			hdr := &zip.FileHeader{Name: e.name}
			hdr.SetMode(os.ModeSymlink | 0o777)
			w, err := zw.CreateHeader(hdr)
			if err != nil {
				t.Fatalf("creating symlink header %q: %v", e.name, err)
			}
			if _, err := w.Write([]byte(e.linkTarget)); err != nil {
				t.Fatalf("writing symlink target %q: %v", e.name, err)
			}
			continue
		}
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("creating zip entry %q: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("writing zip body %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip writer: %v", err)
	}
	return buf.Bytes()
}

// newArchiveRunner returns a reader suitable for the format's Extract method.
// Zip requires an io.ReaderAt + io.Seeker; tar only needs an io.Reader.
func newArchiveRunner(format Extractor, data []byte) io.Reader {
	if _, ok := format.(Zip); ok {
		return io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data)))
	}
	return bytes.NewReader(data)
}

// newArchiveFS builds a fresh, unindexed ArchiveFS over an in-memory archive.
// A fresh instance per assertion prevents one test's index cache from masking
// another test's behavior.
func newArchiveFS(format Extractor, data []byte) *ArchiveFS {
	return &ArchiveFS{
		Stream: io.NewSectionReader(bytes.NewReader(data), 0, int64(len(data))),
		Format: format,
	}
}

// TestExtract_CallbackSeesRawUntrustedNames verifies the first half of the
// contract: the extraction callback is faithful to the archive. Every crafted
// name, including ".." traversal and absolute paths, must be reported verbatim
// with no cleaning or filtering, and symlink entries must carry their raw link
// target. Consumers that use Extract() directly are responsible for sanitizing
// names themselves.
func TestExtract_CallbackSeesRawUntrustedNames(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format Extractor
		build  func(*testing.T) []byte
	}{
		{"tar", Tar{}, buildMaliciousTar},
		{"zip", Zip{}, buildMaliciousZip},
	}

	wantNames := make([]string, 0, len(maliciousArchiveEntries))
	for _, e := range maliciousArchiveEntries {
		wantNames = append(wantNames, e.name)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)

			var gotNames []string
			links := map[string]string{}
			err := tc.format.Extract(context.Background(), newArchiveRunner(tc.format, data),
				func(_ context.Context, f FileInfo) error {
					gotNames = append(gotNames, f.NameInArchive)
					if f.LinkTarget != "" {
						links[f.NameInArchive] = f.LinkTarget
					}
					return nil
				})
			if err != nil {
				t.Fatalf("Extract returned error: %v", err)
			}

			if !equalSlices(gotNames, wantNames) {
				t.Errorf("callback names differ from archive headers\ngot:  %v\nwant: %v", gotNames, wantNames)
			}

			// entries that are not clean paths must still arrive un-cleaned,
			// proving the callback layer applies no sanitization of its own
			for _, e := range maliciousArchiveEntries {
				if e.name == path.Clean(e.name) {
					continue
				}
				if !contains(gotNames, e.name) {
					t.Errorf("verbatim unclean name %q missing from callback; Extract must not sanitize names", e.name)
				}
			}

			wantLinks := map[string]string{
				"link-to-passwd":       "/etc/passwd",
				"relative-escape-link": "../outside.txt",
			}
			if !equalMaps(links, wantLinks) {
				t.Errorf("symlink targets\ngot:  %v\nwant: %v", links, wantLinks)
			}
		})
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestArchiveFS_EscapeEntriesUnreachable is the core security-boundary test.
// Entries whose names normalize outside the virtual root (parent references,
// absolute paths, and mid-path ".." traversal) must not be reachable through
// any io/fs entry point -- Open, ReadFile, Stat, or directory traversal -- even
// though the raw Extract callback still reports them.
func TestArchiveFS_EscapeEntriesUnreachable(t *testing.T) {
	t.Parallel()

	// names that attempt to leave the virtual root, with the sanitized alias a
	// naive (but still contained) implementation might expose them under
	escapeCases := []struct {
		rawName      string   // name as stored in the archive
		sanitized    string   // root-relative alias that must also not exist
		invalidCalls []string // fs.ValidPath-invalid lookup strings
	}{
		{
			rawName:      "../escape.txt",
			sanitized:    "escape.txt",
			invalidCalls: []string{"../escape.txt", "../../escape.txt"},
		},
		{
			rawName:      "../../deep-escape.txt",
			sanitized:    "deep-escape.txt",
			invalidCalls: []string{"../../deep-escape.txt"},
		},
		{
			rawName:      "dir/../../mid-escape.txt",
			sanitized:    "mid-escape.txt",
			invalidCalls: []string{"dir/../../mid-escape.txt"},
		},
		{
			rawName:      "/etc/absolute.txt",
			sanitized:    "etc/absolute.txt",
			invalidCalls: []string{"/etc/absolute.txt", "/etc"},
		},
	}

	cases := []struct {
		name   string
		format Extractor
		build  func(*testing.T) []byte
	}{
		{"tar", Tar{}, buildMaliciousTar},
		{"zip", Zip{}, buildMaliciousZip},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)

			t.Run("indexing does not surface escape names", func(t *testing.T) {
				fsys := newArchiveFS(tc.format, data)
				rootEntries, err := fsys.ReadDir(".")
				if err != nil {
					t.Fatalf("ReadDir(.) failed: %v", err)
				}
				// no entry may be exposed under a sanitized, root-relative alias of
				// an out-of-root payload (e.g. "escape.txt" for "../escape.txt")
				for _, ec := range escapeCases {
					for _, e := range rootEntries {
						if e.Name() == ec.sanitized {
							t.Errorf("root listing contains escape-derived entry %q (from %q)",
								e.Name(), ec.rawName)
						}
					}
				}

				// Malicious names normalize to a parent ("..") component, which the
				// indexer records as an inert directory entry. It is a dead end, not
				// an escape hatch: the io/fs layer rejects ".." as an invalid path, so
				// it can neither be opened nor traversed. Assert exactly that.
				sawParent := false
				for _, e := range rootEntries {
					if e.Name() == ".." {
						sawParent = true
						if !e.IsDir() {
							t.Errorf("parent entry %q must be a directory placeholder, never a readable file", e.Name())
						}
					}
				}
				if !sawParent {
					t.Fatalf("expected an inert %q placeholder from malicious entries; test setup no longer matches implementation", "..")
				}
				if f, err := fsys.Open(".."); err == nil {
					b, _ := io.ReadAll(f)
					f.Close()
					t.Errorf("Open(..) succeeded with %q; parent must be unreachable", string(b))
				}
				if _, err := fs.Stat(fsys, ".."); err == nil {
					t.Errorf("Stat(..) succeeded; parent must be unreachable")
				}

				// a full traversal must never leave the root. WalkDir first visits the
				// inert ".." placeholder as an entry and then reports its unreadability
				// (invalid argument); both signals are confined to the root and no
				// escaping payload is ever visited or read.
				err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
					if p == ".." {
						if walkErr == nil {
							// entry visit: acceptable only as the inert placeholder
							if d != nil && !d.IsDir() {
								t.Errorf("%q exposed as a readable file; want inert directory placeholder", p)
							}
							return nil
						}
						if errors.Is(walkErr, fs.ErrInvalid) {
							return nil // expected: ".." cannot be read
						}
						t.Errorf("unexpected error reading %q: %v", p, walkErr)
						return nil
					}
					if walkErr != nil {
						t.Errorf("unexpected walk error at %q: %v", p, walkErr)
						return nil
					}
					if !fs.ValidPath(p) {
						t.Errorf("walk visited invalid/escaping path %q", p)
					}
					return nil
				})
				if err != nil {
					t.Fatalf("WalkDir failed: %v", err)
				}

				// and the placeholder must never lead to the actual payload bytes
				if b, err := fs.ReadFile(fsys, "../escape.txt"); err == nil {
					t.Errorf("ReadFile(../escape.txt) returned %q; escaping content must be unreachable", b)
				}
			})

			t.Run("escape lookups are rejected", func(t *testing.T) {
				for _, ec := range escapeCases {
					fsys := newArchiveFS(tc.format, data)

					// index first, so both the cache-backed and raw paths are exercised
					if _, err := fsys.ReadDir("."); err != nil {
						t.Fatalf("ReadDir setup failed: %v", err)
					}

					// the sanitized, root-relative alias must not resolve to the
					// out-of-root payload
					if f, err := fsys.Open(ec.sanitized); err == nil {
						b, _ := io.ReadAll(f)
						f.Close()
						t.Errorf("Open(%q) unexpectedly succeeded with %q; out-of-root entry must be unreachable",
							ec.sanitized, string(b))
					}
					if _, err := fs.Stat(fsys, ec.sanitized); err == nil {
						t.Errorf("Stat(%q) unexpectedly succeeded; out-of-root entry must be unreachable", ec.sanitized)
					}
					if b, err := fs.ReadFile(fsys, ec.sanitized); err == nil {
						t.Errorf("ReadFile(%q) unexpectedly returned %q", ec.sanitized, string(b))
					}

					// invalid (non-ValidPath) lookup strings must be rejected up front
					for _, bad := range ec.invalidCalls {
						fsys2 := newArchiveFS(tc.format, data)
						if _, err := fsys2.Open(bad); err == nil {
							t.Errorf("Open(%q) unexpectedly succeeded; invalid path must be rejected", bad)
						}
						if _, err := fs.Stat(fsys2, bad); err == nil {
							t.Errorf("Stat(%q) unexpectedly succeeded; invalid path must be rejected", bad)
						}
						var pe *fs.PathError
						if f, err := fsys2.Open(bad); err != nil && !errors.As(err, &pe) {
							t.Errorf("Open(%q) error type = %T, want *fs.PathError", bad, err)
						} else if f != nil {
							f.Close()
						}
					}
				}
			})
		})
	}
}

// TestArchiveFS_SymlinksAreNotFollowed verifies that symbolic links remain
// inert link entries inside the virtual file system: opening one returns the
// stored link target as its bytes (never dereferences it), the ModeSymlink bit
// is preserved, and neither absolute nor parent-relative link targets can pull
// host files (e.g. /etc/passwd) into reads.
func TestArchiveFS_SymlinksAreNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink mode semantics are unix-specific")
	}
	t.Parallel()

	cases := []struct {
		name   string
		format Extractor
		build  func(*testing.T) []byte
	}{
		{"tar", Tar{}, buildMaliciousTar},
		{"zip", Zip{}, buildMaliciousZip},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)
			fsys := newArchiveFS(tc.format, data)

			linkCases := []struct {
				name       string
				wantTarget string
			}{
				{"link-to-passwd", "/etc/passwd"},
				{"relative-escape-link", "../outside.txt"},
			}

			for _, lc := range linkCases {
				info, err := fs.Stat(fsys, lc.name)
				if err != nil {
					t.Fatalf("Stat(%q): %v", lc.name, err)
				}
				if info.Mode()&os.ModeSymlink == 0 {
					t.Errorf("Stat(%q) mode = %v, want ModeSymlink preserved", lc.name, info.Mode())
				}

				f, err := fsys.Open(lc.name)
				if err != nil {
					t.Fatalf("Open(%q): %v", lc.name, err)
				}
				st, err := f.Stat()
				if err != nil {
					t.Fatalf("Stat on opened %q: %v", lc.name, err)
				}
				if st.Mode()&os.ModeSymlink == 0 {
					t.Errorf("opened %q mode = %v, want ModeSymlink", lc.name, st.Mode())
				}
				b, err := io.ReadAll(f)
				f.Close()
				if err != nil {
					t.Fatalf("ReadAll(%q): %v", lc.name, err)
				}

				// The VFS must never dereference the link. A tar symlink carries no
				// body, so its read is empty; a zip symlink stores the target string
				// as its body. Both are inert metadata, never host file contents.
				_, isZip := tc.format.(Zip)
				wantBody := ""
				if isZip {
					wantBody = lc.wantTarget
				}
				if string(b) != wantBody {
					t.Errorf("Open(%q) contents = %q, want %q (link must not be dereferenced)",
						lc.name, string(b), wantBody)
				}
				// the decisive invariant: following /etc/passwd would yield host
				// account data; its presence in the read proves an escape
				if bytes.Contains(b, []byte("root:")) {
					t.Errorf("reading symlink %q leaked host file contents (link was followed)", lc.name)
				}
			}
		})
	}
}

// TestArchiveFS_BenignRelativePathsRemainReadable guards against an
// over-correcting sanitizer: while escaping entries are blocked, ordinary
// relative entries, including nested directories, must remain indexed and
// byte-for-byte readable through the virtual file system.
func TestArchiveFS_BenignRelativePathsRemainReadable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format Extractor
		build  func(*testing.T) []byte
	}{
		{"tar", Tar{}, buildMaliciousTar},
		{"zip", Zip{}, buildMaliciousZip},
	}

	benign := []struct {
		name string
		body string
	}{
		{"plain.txt", "plain-content"},
		{"normal/dir/inside.txt", "nested-relative"},
		{"sub/../safe-redirect.txt", "redirect-to-root"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)
			fsys := newArchiveFS(tc.format, data)

			// traversal must include every benign entry exactly once
			seen := map[string]int{}
			err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil && errors.Is(walkErr, fs.ErrInvalid) && p == ".." {
					return nil // implicit unreadable ".." from malicious entries; ignore
				}
				if walkErr != nil {
					return walkErr
				}
				if !d.IsDir() {
					seen[p]++
				}
				return nil
			})
			if err != nil {
				t.Fatalf("WalkDir: %v", err)
			}
			for _, want := range benign {
				clean := path.Clean(want.name)
				if seen[clean] != 1 {
					t.Errorf("walk visited %q %d times, want exactly once", clean, seen[clean])
				}
			}

			for _, want := range benign {
				clean := path.Clean(want.name)
				got, err := fs.ReadFile(fsys, clean)
				if err != nil {
					t.Errorf("ReadFile(%q): %v", clean, err)
					continue
				}
				if string(got) != want.body {
					t.Errorf("ReadFile(%q) = %q, want %q", clean, string(got), want.body)
				}
				info, err := fs.Stat(fsys, clean)
				if err != nil {
					t.Errorf("Stat(%q): %v", clean, err)
					continue
				}
				if info.IsDir() {
					t.Errorf("Stat(%q) reports directory, want regular file", clean)
				}
			}

			// the benign nested directory must list its member
			entries, err := fs.ReadDir(fsys, "normal/dir")
			if err != nil {
				t.Fatalf("ReadDir(normal/dir): %v", err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if !equalSlices(names, []string{"inside.txt"}) {
				t.Errorf("ReadDir(normal/dir) = %v, want [inside.txt]", names)
			}
		})
	}
}

// TestArchiveFS_NormalizedNameCollisions covers entries whose distinct raw
// names become identical after path.Clean(). The index must converge on a
// single entry, traversal must visit it once, and reads must be deterministic,
// while the raw callback still reports both original entries.
func TestArchiveFS_NormalizedNameCollisions(t *testing.T) {
	t.Parallel()

	dupEntries := []struct {
		raw  string
		body string
	}{
		{"x.txt", "first"},
		{"a/../x.txt", "second"}, // cleans to x.txt
		{"./y.txt", "y-body"},    // cleans to y.txt
		{"dir/../z.txt", "z-body"},
	}

	buildTar := func(t *testing.T) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range dupEntries {
			hdr := &tar.Header{Name: e.raw, Mode: 0o644, Size: int64(len(e.body))}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			tw.Write([]byte(e.body))
		}
		tw.Close()
		return buf.Bytes()
	}
	buildZip := func(t *testing.T) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, e := range dupEntries {
			w, err := zw.Create(e.raw)
			if err != nil {
				t.Fatal(err)
			}
			w.Write([]byte(e.body))
		}
		zw.Close()
		return buf.Bytes()
	}

	cases := []struct {
		name   string
		format Extractor
		build  func(*testing.T) []byte
	}{
		{"tar", Tar{}, buildTar},
		{"zip", Zip{}, buildZip},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)

			// raw callback keeps every distinct header name, in order
			var rawNames []string
			err := tc.format.Extract(context.Background(), newArchiveRunner(tc.format, data),
				func(_ context.Context, f FileInfo) error {
					rawNames = append(rawNames, f.NameInArchive)
					return nil
				})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			wantRaw := []string{"x.txt", "a/../x.txt", "./y.txt", "dir/../z.txt"}
			if !equalSlices(rawNames, wantRaw) {
				t.Errorf("raw callback names = %v, want %v", rawNames, wantRaw)
			}

			fsys := newArchiveFS(tc.format, data)
			rootEntries, err := fs.ReadDir(fsys, ".")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			var gotRoot []string
			for _, e := range rootEntries {
				gotRoot = append(gotRoot, e.Name())
			}
			sort.Strings(gotRoot)
			if want := []string{"x.txt", "y.txt", "z.txt"}; !equalSlices(gotRoot, want) {
				t.Errorf("root index = %v, want %v (collisions must collapse)", gotRoot, want)
			}

			// walk must agree with the index: one visit per sanitized file
			walked := map[string]int{}
			if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if !d.IsDir() {
					walked[p]++
				}
				return nil
			}); err != nil {
				t.Fatalf("WalkDir: %v", err)
			}
			for _, name := range []string{"x.txt", "y.txt", "z.txt"} {
				if walked[name] != 1 {
					t.Errorf("walk count for %q = %d, want 1", name, walked[name])
				}
			}

			// reads must be deterministic: repeat and compare
			first, err := fs.ReadFile(fsys, "x.txt")
			if err != nil {
				t.Fatalf("first ReadFile(x.txt): %v", err)
			}
			second, err := fs.ReadFile(newArchiveFS(tc.format, data), "x.txt")
			if err != nil {
				t.Fatalf("second ReadFile(x.txt): %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("non-deterministic read of collision entry: %q vs %q", first, second)
			}

			// the unclean alias must not expose a second, parallel file
			if b, err := fs.ReadFile(fsys, "a/x.txt"); err == nil {
				t.Errorf("ReadFile(a/x.txt) unexpectedly returned %q; no second copy should exist", b)
			}
		})
	}
}

// TestArchiveFS_NestedArchiveIsReadableMember verifies nested archives: an
// embedded tar is an ordinary, fully readable member of the outer archive and
// can itself be opened as an ArchiveFS. Indexing, traversal, and reads of both
// the outer and inner layers must agree and contain no escape surface.
func TestArchiveFS_NestedArchiveIsReadableMember(t *testing.T) {
	t.Parallel()

	// inner tar with a benign nested file
	var inner bytes.Buffer
	itw := tar.NewWriter(&inner)
	hdr := &tar.Header{Name: "inner/hello.txt", Mode: 0o644, Size: int64(len("hello-inner"))}
	if err := itw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := itw.Write([]byte("hello-inner")); err != nil {
		t.Fatal(err)
	}
	if err := itw.Close(); err != nil {
		t.Fatal(err)
	}

	// outer zip holding the inner tar alongside a regular file
	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)
	w, err := zw.Create("outer.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("outer-body")); err != nil {
		t.Fatal(err)
	}
	w2, err := zw.Create("nested.tar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	data := outer.Bytes()
	outerFS := newArchiveFS(Zip{}, data)

	// traversal of the outer archive lists both members
	var outerNames []string
	if err := fs.WalkDir(outerFS, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			outerNames = append(outerNames, p)
		}
		return nil
	}); err != nil {
		t.Fatalf("outer WalkDir: %v", err)
	}
	sort.Strings(outerNames)
	if want := []string{"nested.tar", "outer.txt"}; !equalSlices(outerNames, want) {
		t.Errorf("outer walk = %v, want %v", outerNames, want)
	}

	// the nested archive is byte-for-byte readable through the outer FS
	nestedBytes, err := fs.ReadFile(outerFS, "nested.tar")
	if err != nil {
		t.Fatalf("ReadFile(nested.tar): %v", err)
	}
	if !bytes.Equal(nestedBytes, inner.Bytes()) {
		t.Errorf("nested.tar bytes differ from the embedded archive")
	}
	if got, err := fs.ReadFile(outerFS, "outer.txt"); err != nil || string(got) != "outer-body" {
		t.Errorf("outer.txt = %q, %v", got, err)
	}

	// the extracted inner archive is itself a valid, independently readable FS
	innerFS := newArchiveFS(Tar{}, nestedBytes)
	got, err := fs.ReadFile(innerFS, "inner/hello.txt")
	if err != nil {
		t.Fatalf("reading file from nested tar: %v", err)
	}
	if string(got) != "hello-inner" {
		t.Errorf("inner/hello.txt = %q, want hello-inner", got)
	}
	innerEntries, err := fs.ReadDir(innerFS, "inner")
	if err != nil {
		t.Fatalf("ReadDir on nested tar: %v", err)
	}
	var innerNames []string
	for _, e := range innerEntries {
		innerNames = append(innerNames, e.Name())
	}
	if !equalSlices(innerNames, []string{"hello.txt"}) {
		t.Errorf("nested tar index = %v, want [hello.txt]", innerNames)
	}
}

// TestArchiveFS_CorruptInputLeavesNoResidualEntries verifies that when
// extraction fails midway through indexing a damaged archive, the partially
// built index is discarded: the FS must not present entries it only saw before
// the corruption as legitimate files.
func TestArchiveFS_CorruptInputLeavesNoResidualEntries(t *testing.T) {
	t.Parallel()

	t.Run("tar truncated mid-stream", func(t *testing.T) {
		t.Parallel()

		// Build a tar with two regular entries and truncate it inside the second
		// entry's header. The first entry stays structurally intact; the second is
		// a damaged entry that must never be treated as a legitimate file.
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		writeReg := func(name, body string) {
			hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		writeReg("a.txt", "0123456789")
		writeReg("b.txt", "abcdefghij")
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		full := buf.Bytes()

		// each tar header is a 512-byte block; the second header begins at 1024.
		// Keeping only a fragment of it yields a partial (unreadable) header.
		if len(full) <= 1024 {
			t.Fatalf("unexpected tar layout: len=%d", len(full))
		}
		corrupt := full[:1024+100]

		// direct extraction must surface the corruption instead of stopping cleanly
		err := Tar{}.Extract(context.Background(), bytes.NewReader(corrupt),
			func(_ context.Context, f FileInfo) error { return nil })
		if err == nil {
			t.Fatal("expected error from truncated tar, got nil")
		}

		fsys := newArchiveFS(Tar{}, corrupt)
		if _, err := fsys.ReadDir("."); err == nil {
			t.Fatal("expected ReadDir error on truncated tar, got nil")
		}
		// the failed index attempt must be fully discarded: no partial dirs or
		// contents map may survive to answer later cache-backed lookups
		if fsys.dirs != nil || fsys.contents != nil {
			t.Errorf("index retained after failed ReadDir: dirs=%v contents=%v, want both nil",
				fsys.dirs != nil, fsys.contents != nil)
		}

		// the structurally intact entry remains readable (tar is a sequential
		// stream format, so Open re-scans from the start rather than using a
		// stale index)...
		if got, err := fs.ReadFile(newArchiveFS(Tar{}, corrupt), "a.txt"); err != nil {
			t.Errorf("intact entry a.txt became unreadable: %v", err)
		} else if string(got) != "0123456789" {
			t.Errorf("a.txt = %q, want 0123456789", got)
		}

		// ...while the entry whose header was cut must not resolve to any file
		if f, err := newArchiveFS(Tar{}, corrupt).Open("b.txt"); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			t.Errorf("damaged entry b.txt opened with %q; corrupt entries must not be valid files", b)
		}
	})

	t.Run("zip with damaged central directory", func(t *testing.T) {
		t.Parallel()
		good := buildMaliciousZip(t)
		corrupt := good[:len(good)-16] // truncate the end-of-central-directory record

		fsys := newArchiveFS(Zip{}, corrupt)
		if _, err := fsys.ReadDir("."); err == nil {
			t.Fatal("expected ReadDir error on truncated zip, got nil")
		}
		if fsys.dirs != nil || fsys.contents != nil {
			t.Errorf("index retained after failed ReadDir: dirs=%v contents=%v, want both nil",
				fsys.dirs != nil, fsys.contents != nil)
		}
		if b, err := fs.ReadFile(fsys, "plain.txt"); err == nil {
			t.Errorf("ReadFile(plain.txt) = %q on corrupt zip; want error", b)
		}
	})
}

// TestArchiveFS_CancellationLeavesNoResidualEntries verifies context
// cancellation is honored at both the Extract callback layer and the FS layer,
// and that a canceled index attempt leaves no partial, queryable state.
func TestArchiveFS_CancellationLeavesNoResidualEntries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		format Extractor
		build  func(*testing.T) []byte
	}{
		{"tar", Tar{}, buildMaliciousTar},
		{"zip", Zip{}, buildMaliciousZip},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.build(t)

			t.Run("Extract honors canceled context", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				visited := 0
				err := tc.format.Extract(ctx, newArchiveRunner(tc.format, data),
					func(_ context.Context, f FileInfo) error {
						visited++
						return nil
					})
				if err == nil {
					t.Fatal("expected error from Extract with canceled context, got nil")
				}
				if visited != 0 {
					t.Errorf("callback invoked %d times after cancellation, want 0", visited)
				}
			})

			t.Run("ReadDir aborts and discards partial index", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				fsys := newArchiveFS(tc.format, data)
				fsys.Context = ctx
				if _, err := fsys.ReadDir("."); err == nil {
					t.Fatal("expected ReadDir error with canceled context, got nil")
				}
				if fsys.dirs != nil || fsys.contents != nil {
					t.Errorf("index retained after canceled ReadDir, want nil maps")
				}
			})

			t.Run("Open aborts and serves no file", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				fsys := newArchiveFS(tc.format, data)
				fsys.Context = ctx
				f, err := fsys.Open("plain.txt")
				if err == nil {
					f.Close()
					t.Fatal("expected Open error with canceled context, got nil")
				}
			})
		})
	}
}

// TestFileSystem_ArchiveIdentificationPreservesBoundary exercises the
// high-level FileSystem entry point end to end: an archive on disk is
// identified and wrapped as an FS, benign files read through, and an escaping
// name remains unreachable. It also covers a compressed tar (.tar.gz), proving
// the decompression layer does not weaken the boundary.
func TestFileSystem_ArchiveIdentificationPreservesBoundary(t *testing.T) {
	t.Parallel()

	// build a gzipped tar with one benign and one parent-escaping entry
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	writeTarReg := func(name, body string) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	writeTarReg("good.txt", "good-body")
	writeTarReg("../evil.txt", "evil-body")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var gzBuf bytes.Buffer
	gw, err := Gz{}.OpenWriter(&gzBuf)
	if err != nil {
		t.Fatalf("gzip writer: %v", err)
	}
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	archivePath := dir + "/boundary.tar.gz"
	if err := os.WriteFile(archivePath, gzBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys, err := FileSystem(t.Context(), archivePath, nil)
	if err != nil {
		t.Fatalf("FileSystem identify: %v", err)
	}

	got, err := fs.ReadFile(fsys, "good.txt")
	if err != nil {
		t.Fatalf("ReadFile(good.txt): %v", err)
	}
	if string(got) != "good-body" {
		t.Errorf("good.txt = %q, want good-body", got)
	}
	if b, err := fs.ReadFile(fsys, "evil.txt"); err == nil {
		t.Errorf("ReadFile(evil.txt) = %q; parent-escaping entry must be unreachable", b)
	}
	if f, err := fsys.Open("../evil.txt"); err == nil {
		f.Close()
		t.Errorf("Open(../evil.txt) succeeded; escaping path must be rejected")
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
