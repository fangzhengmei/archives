package archives

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
)

// ErrResourceLimit is a sentinel error that is returned (wrapped) whenever
// an archive exceeds one of the configured [Limits]. Use errors.Is with this
// value to distinguish resource limit violations from other kinds of errors:
//
//	err := format.Extract(ctx, archive, handler)
//	if errors.Is(err, archives.ErrResourceLimit) {
//		// the archive was hostile or simply too big: stop processing it
//	}
var ErrResourceLimit = errors.New("archive resource limit exceeded")

// ResourceLimitError describes which resource limit was exceeded while
// reading an archive, and by how much. It unwraps to [ErrResourceLimit].
type ResourceLimitError struct {
	// Limit is the name of the limit that was exceeded: "entries",
	// "decompressed bytes", or "compression ratio".
	Limit string

	// Max is the configured upper bound.
	Max float64

	// Actual is the value observed when the limit was exceeded.
	Actual float64
}

// Error implements the error interface.
func (e *ResourceLimitError) Error() string {
	if math.IsInf(e.Actual, 1) {
		return fmt.Sprintf("%s: %s limit of %g exceeded", ErrResourceLimit, e.Limit, e.Max)
	}
	return fmt.Sprintf("%s: %s limit of %g exceeded (currently %g)", ErrResourceLimit, e.Limit, e.Max, e.Actual)
}

// Is reports whether target is [ErrResourceLimit], so that callers can
// use errors.Is(err, ErrResourceLimit) to recognize limit violations.
func (e *ResourceLimitError) Is(target error) bool { return target == ErrResourceLimit }

// Limits configures upper bounds on the resources that may be consumed
// while traversing, extracting, or reading directory listings from an
// archive. They protect readers from malicious archives that attempt to
// exhaust memory, disk, or CPU through a huge number of entries or an
// extreme compression ratio ("decompression bombs").
//
// The zero value of each field means "no limit". Limits are carried by a
// context; use [WithLimits] to attach them. All extraction entry points
// that accept a context honor these limits consistently: the Extract
// methods of the archive formats (tar, zip, rar, 7z, and compressed
// archives such as tar.gz), as well as [ArchiveFS] directory and file
// access, which evaluates the limits using its Context field.
//
// When a limit is reached, the operation aborts and returns an error
// matching errors.Is(err, [ErrResourceLimit]). A partially-read archive
// is never reported as a complete extraction or a complete directory
// listing.
type Limits struct {
	// MaxEntries is the maximum number of entries (files, directories,
	// links, etc.) that may be traversed in an archive.
	MaxEntries int

	// MaxDecompressedBytes is the maximum cumulative number of
	// decompressed bytes that may be produced while reading an
	// archive. This counts the bytes delivered by decompression
	// streams and by file content readers handed to handlers.
	MaxDecompressedBytes int64

	// MaxCompressionRatio is the maximum allowed ratio of cumulative
	// decompressed bytes to compressed (archive) bytes consumed.
	// For example, a value of 100 allows archives that expand to at
	// most 100 times their compressed size. Values <= 0 disable the
	// check. The ratio is only enforced when the compressed byte
	// stream is observable (it is not, for example, when a rar
	// archive is opened directly by file name).
	MaxCompressionRatio float64
}

// limitsContextKey is the context key for [Limits] values.
type limitsContextKey struct{}

// WithLimits returns a context that carries the given resource limits.
// Pass the resulting context to Extract, or set it as the Context field
// of an [ArchiveFS] (or [DeepFS]), to bound the resources consumed by
// hostile archives.
func WithLimits(ctx context.Context, limits Limits) context.Context {
	return context.WithValue(ctx, limitsContextKey{}, limits)
}

// LimitsFromContext returns the resource limits attached to ctx by
// [WithLimits], and whether any were attached at all.
func LimitsFromContext(ctx context.Context) (Limits, bool) {
	limits, ok := ctx.Value(limitsContextKey{}).(Limits)
	return limits, ok
}

// extractGuard tracks resource consumption during a single extraction
// or traversal and aborts when a configured limit is exceeded. A nil
// guard is valid and means "no limits"; all its methods are no-ops.
type extractGuard struct {
	limits       Limits
	entries      int
	decompressed int64
	compressed   int64
	ratio        bool // whether compressed bytes are actually being counted
}

// newExtractGuard returns a guard enforcing the limits attached to ctx,
// or nil if ctx carries no limits.
func newExtractGuard(ctx context.Context) *extractGuard {
	limits, ok := LimitsFromContext(ctx)
	if !ok {
		return nil
	}
	return &extractGuard{limits: limits}
}

// addEntry accounts for one traversed archive entry.
func (g *extractGuard) addEntry() error {
	if g == nil {
		return nil
	}
	g.entries++
	if max := g.limits.MaxEntries; max > 0 && g.entries > max {
		return &ResourceLimitError{Limit: "entries", Max: float64(max), Actual: float64(g.entries)}
	}
	return nil
}

// addEntries accounts for n traversed archive entries at once.
func (g *extractGuard) addEntries(n int) error {
	if g == nil {
		return nil
	}
	g.entries += n
	if max := g.limits.MaxEntries; max > 0 && g.entries > max {
		return &ResourceLimitError{Limit: "entries", Max: float64(max), Actual: float64(g.entries)}
	}
	return nil
}

// addDecompressed accounts for n decompressed bytes delivered to the consumer.
func (g *extractGuard) addDecompressed(n int64) error {
	if g == nil {
		return nil
	}
	g.decompressed += n
	if max := g.limits.MaxDecompressedBytes; max > 0 && g.decompressed > max {
		return &ResourceLimitError{Limit: "decompressed bytes", Max: float64(max), Actual: float64(g.decompressed)}
	}
	return g.checkRatio()
}

// addCompressed accounts for n bytes consumed from the compressed archive stream.
func (g *extractGuard) addCompressed(n int64) error {
	if g == nil || !g.ratio {
		return nil
	}
	g.compressed += n
	return g.checkRatio()
}

// checkRatio enforces the maximum compression ratio, if it is configured
// and compressed bytes are being counted.
func (g *extractGuard) checkRatio() error {
	if g == nil || !g.ratio || g.limits.MaxCompressionRatio <= 0 {
		return nil
	}
	if g.compressed <= 0 {
		if g.decompressed > 0 {
			return &ResourceLimitError{Limit: "compression ratio", Max: g.limits.MaxCompressionRatio, Actual: math.Inf(1)}
		}
		return nil
	}
	if ratio := float64(g.decompressed) / float64(g.compressed); ratio > g.limits.MaxCompressionRatio {
		return &ResourceLimitError{Limit: "compression ratio", Max: g.limits.MaxCompressionRatio, Actual: ratio}
	}
	return nil
}

// wrapCompressedReader wraps r so that bytes read from it count as
// compressed (archive) bytes for the purpose of ratio enforcement. If
// no compression ratio limit is configured, r is returned unchanged.
func (g *extractGuard) wrapCompressedReader(r io.Reader) io.Reader {
	if g == nil || g.limits.MaxCompressionRatio <= 0 {
		return r
	}
	g.ratio = true
	return &countingReader{r: r, add: g.addCompressed}
}

// wrapCompressedSeekReaderAt is like wrapCompressedReader but preserves
// the io.ReaderAt and io.Seeker interfaces required by the zip and 7z
// formats.
func (g *extractGuard) wrapCompressedSeekReaderAt(sra seekReaderAt) seekReaderAt {
	if g == nil || g.limits.MaxCompressionRatio <= 0 {
		return sra
	}
	g.ratio = true
	return &countingSeekReaderAt{seekReaderAt: sra, add: g.addCompressed}
}

// wrapDecompressedReader wraps r so that bytes read from it count as
// decompressed bytes, enforcing the cumulative decompressed-bytes and
// compression-ratio limits. If neither limit is configured, r is
// returned unchanged.
func (g *extractGuard) wrapDecompressedReader(r io.Reader) io.Reader {
	if g == nil || (g.limits.MaxDecompressedBytes <= 0 && g.limits.MaxCompressionRatio <= 0) {
		return r
	}
	return &countingReader{r: r, add: g.addDecompressed}
}

// wrapDecompressedReadCloser is like wrapDecompressedReader but
// preserves the io.Closer of rc.
func (g *extractGuard) wrapDecompressedReadCloser(rc io.ReadCloser) io.ReadCloser {
	if g == nil || (g.limits.MaxDecompressedBytes <= 0 && g.limits.MaxCompressionRatio <= 0) {
		return rc
	}
	return struct {
		io.Reader
		io.Closer
	}{&countingReader{r: rc, add: g.addDecompressed}, rc}
}

// wrapFileInfo wraps the Open callback of file so that any content read
// from the opened file counts toward the cumulative decompressed-bytes
// and compression-ratio limits.
func (g *extractGuard) wrapFileInfo(file FileInfo) FileInfo {
	if g == nil || file.Open == nil {
		return file
	}
	open := file.Open
	file.Open = func() (fs.File, error) {
		opened, err := open()
		if err != nil {
			return nil, err
		}
		return &guardedFile{File: opened, guard: g}, nil
	}
	return file
}

// countingReader counts the bytes read from r and reports them to add;
// if add returns an error, reading aborts with that error.
type countingReader struct {
	r   io.Reader
	add func(int64) error
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if addErr := c.add(int64(n)); addErr != nil {
			return n, addErr
		}
	}
	return n, err
}

// countingSeekReaderAt counts compressed bytes consumed through ReadAt
// while preserving the seekReaderAt interface.
type countingSeekReaderAt struct {
	seekReaderAt
	add func(int64) error
}

func (c *countingSeekReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.seekReaderAt.ReadAt(p, off)
	if n > 0 {
		if addErr := c.add(int64(n)); addErr != nil {
			return n, addErr
		}
	}
	return n, err
}

// guardedFile is an fs.File whose reads count toward the cumulative
// decompressed-bytes and compression-ratio limits.
type guardedFile struct {
	fs.File
	guard *extractGuard
}

func (f *guardedFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	if n > 0 {
		if addErr := f.guard.addDecompressed(int64(n)); addErr != nil {
			return n, addErr
		}
	}
	return n, err
}
