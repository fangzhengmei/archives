package archives

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
)

// RegisterFormat registers a format. It should be called during init.
// Duplicate formats by name are not allowed and will panic.
func RegisterFormat(format Format) {
	name := strings.Trim(strings.ToLower(format.Extension()), ".")
	if _, ok := formats[name]; ok {
		panic("format " + name + " is already registered")
	}
	formats[name] = format
}

// Identify iterates the registered formats and returns the one that
// matches the given filename and/or stream. It is capable of identifying
// compressed files (.gz, .xz...), archive files (.tar, .zip...), and
// compressed archive files (tar.gz, tar.bz2...). The returned Format
// value can be type-asserted to ascertain its capabilities.
//
// If no matching formats were found, special error NoMatch is returned.
//
// If stream is nil then it will only match on file name and the
// returned io.Reader will be nil.
//
// If stream is non-nil, it will be returned in the same read position
// as it was before Identify() was called, by virtue of buffering the
// peeked bytes. However, if the stream is an io.Seeker, Seek() must
// work, no extra buffering will be performed, and the original input
// value will be returned at the original position by seeking.
//
// Identify does not limit how many bytes may be read from the stream
// while matching; use IdentifyWithMaxBytes to bound the cost of probing.
func Identify(ctx context.Context, filename string, stream io.Reader) (Format, io.Reader, error) {
	return IdentifyWithMaxBytes(ctx, filename, stream, 0)
}

// IdentifyWithMaxBytes is like Identify, but it limits how many bytes may
// be read from the stream while probing for a matching format. This allows
// callers to bound the cost of identification before committing to reading
// the stream. A maxBytes value of 0 or less means no limit, in which case
// the results are the same as Identify.
//
// The limit only applies while identifying the format; the returned stream
// is not limited and still contains all the bytes of the original stream,
// including any that were buffered while probing, so it can be read in full
// by the caller afterward (for example, to extract each file entry) without
// repeating or skipping any data. This holds even when an error is returned.
//
// If the limit is reached before a conclusive match could be made, the
// returned error wraps ErrMaxBytesReached, which is distinct from NoMatch:
// NoMatch means the input was probed and no format matched, whereas
// ErrMaxBytesReached means the byte budget ran out first and the caller
// may retry with a larger budget.
func IdentifyWithMaxBytes(ctx context.Context, filename string, stream io.Reader, maxBytes int64) (Format, io.Reader, error) {
	var compression Compression
	var archival Archival
	var extraction Extraction

	filename = path.Base(filepath.ToSlash(filename))

	// if a byte budget was given, count the bytes read from the stream
	// while probing; the limiter is lifted before returning so the
	// caller gets an unbounded, complete stream to read afterward
	var limiter *byteLimitReader
	if stream != nil && maxBytes > 0 {
		limiter = &byteLimitReader{r: stream, remaining: maxBytes}
		if seeker, ok := stream.(io.Seeker); ok {
			stream = &byteLimitSeekReader{byteLimitReader: limiter, seeker: seeker}
		} else {
			stream = limiter
		}
		defer limiter.lift()
	}

	rewindableStream, err := newRewindReader(stream)
	if err != nil {
		return nil, nil, err
	}

	// try compression format first, since that's the outer "layer" if combined
	for name, format := range formats {
		cf, isCompression := format.(Compression)
		if !isCompression {
			continue
		}

		matchResult, err := identifyOne(ctx, format, filename, rewindableStream, nil)
		if err != nil {
			return nil, rewindableStream.reader(), fmt.Errorf("matching %s: %w", name, err)
		}
		if err := limiter.errIfExceeded(); err != nil {
			return nil, rewindableStream.reader(), fmt.Errorf("matching %s: %w", name, err)
		}

		// if matched, wrap input stream with decompression
		// so we can see if it contains an archive within
		if matchResult.Matched() {
			compression = cf
			break
		}
	}

	// try archival and extraction formats next
	for name, format := range formats {
		ar, isArchive := format.(Archival)
		ex, isExtract := format.(Extraction)
		if !isArchive && !isExtract {
			continue
		}

		matchResult, err := identifyOne(ctx, format, filename, rewindableStream, compression)
		if err != nil {
			return nil, rewindableStream.reader(), fmt.Errorf("matching %s: %w", name, err)
		}
		if err := limiter.errIfExceeded(); err != nil {
			return nil, rewindableStream.reader(), fmt.Errorf("matching %s: %w", name, err)
		}

		if matchResult.Matched() {
			archival = ar
			extraction = ex
			break
		}
	}

	// the stream should be rewound by identifyOne; then return the most specific type of match
	bufferedStream := rewindableStream.reader()
	switch {
	case compression != nil && archival == nil && extraction == nil:
		return compression, bufferedStream, nil
	case compression == nil && archival != nil && extraction == nil:
		return archival, bufferedStream, nil
	case compression == nil && archival == nil && extraction != nil:
		return extraction, bufferedStream, nil
	case compression == nil && archival != nil && extraction != nil:
		// archival and extraction are always set together, so they must be the same
		return archival, bufferedStream, nil
	case compression != nil && extraction != nil:
		// in practice, this is only used for compressed tar files, and the tar format can
		// both read and write, so the archival value should always work too; but keep in
		// mind that Identify() is used on existing files to be read, not new files to write
		return CompressedArchive{archival, extraction, compression}, bufferedStream, nil
	default:
		return nil, bufferedStream, NoMatch
	}
}

func identifyOne(ctx context.Context, format Format, filename string, stream *rewindReader, comp Compression) (mr MatchResult, err error) {
	defer stream.rewind()

	if filename == "." {
		filename = ""
	}

	// if looking within a compressed format, wrap the stream in a
	// reader that can decompress it so we can match the "inner" format
	// (yes, we have to make a new reader every time we do a match,
	// because we reset/seek the stream each time and that can mess up
	// the compression reader's state if we don't discard it also)
	if comp != nil && stream != nil {
		decompressedStream, openErr := comp.OpenReader(stream)
		if openErr != nil {
			return MatchResult{}, openErr
		}
		defer decompressedStream.Close()
		mr, err = format.Match(ctx, filename, decompressedStream)
	} else {
		// Make sure we pass a nil io.Reader not a *rewindReader(nil)
		var r io.Reader
		if stream != nil {
			r = stream
		}
		mr, err = format.Match(ctx, filename, r)
	}

	// if the error is EOF, we can just ignore it.
	// Just means we have a small input file.
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return mr, err
}

// readAtMost reads at most n bytes from the stream. A nil, empty, or short
// stream is not an error. The returned slice of bytes may have length < n
// without an error.
func readAtMost(stream io.Reader, n int) ([]byte, error) {
	if stream == nil || n <= 0 {
		return []byte{}, nil
	}

	buf := make([]byte, n)
	nr, err := io.ReadFull(stream, buf)

	// Return the bytes read if there was no error OR if the
	// error was EOF (stream was empty) or UnexpectedEOF (stream
	// had less than n). We ignore those errors because we aren't
	// required to read the full n bytes; so an empty or short
	// stream is not actually an error.
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return buf[:nr], nil
	}

	return nil, err
}

// CompressedArchive represents an archive which is compressed externally
// (for example, a gzipped tar file, .tar.gz.) It combines a compression
// format on top of an archival/extraction format and provides both
// functionalities in a single type, allowing archival and extraction
// operations transparently through compression and decompression. However,
// compressed archives have some limitations; for example, files cannot be
// inserted/appended because of complexities with modifying existing
// compression state (perhaps this could be overcome, but I'm not about to
// try it).
type CompressedArchive struct {
	Archival
	Extraction
	Compression
}

// Name returns a concatenation of the archive and compression format extensions.
func (ca CompressedArchive) Extension() string {
	var name string
	if ca.Archival != nil {
		name += ca.Archival.Extension()
	} else if ca.Extraction != nil {
		name += ca.Extraction.Extension()
	}
	name += ca.Compression.Extension()
	return name
}

// MediaType returns the compression format's MIME type, since
// a compressed archive is fundamentally a compressed file.
func (ca CompressedArchive) MediaType() string { return ca.Compression.MediaType() }

// Match matches if the input matches both the compression and archival/extraction format.
func (ca CompressedArchive) Match(ctx context.Context, filename string, stream io.Reader) (MatchResult, error) {
	var conglomerate MatchResult

	if ca.Compression != nil {
		matchResult, err := ca.Compression.Match(ctx, filename, stream)
		if err != nil {
			return MatchResult{}, err
		}
		if !matchResult.Matched() {
			return matchResult, nil
		}

		// wrap the reader with the decompressor so we can
		// attempt to match the archive by reading the stream
		rc, err := ca.Compression.OpenReader(stream)
		if err != nil {
			return matchResult, err
		}
		defer rc.Close()
		stream = rc

		conglomerate = matchResult
	}

	if ca.Archival != nil {
		matchResult, err := ca.Archival.Match(ctx, filename, stream)
		if err != nil {
			return MatchResult{}, err
		}
		if !matchResult.Matched() {
			return matchResult, nil
		}
		conglomerate.ByName = conglomerate.ByName || matchResult.ByName
		conglomerate.ByStream = conglomerate.ByStream || matchResult.ByStream
	}

	return conglomerate, nil
}

// Archive writes an archive to the output stream while compressing the result.
func (ca CompressedArchive) Archive(ctx context.Context, output io.Writer, files []FileInfo) error {
	if ca.Archival == nil {
		return fmt.Errorf("no archival format")
	}
	if ca.Compression != nil {
		wc, err := ca.Compression.OpenWriter(output)
		if err != nil {
			return err
		}
		defer wc.Close()
		output = wc
	}
	return ca.Archival.Archive(ctx, output, files)
}

// ArchiveAsync adds files to the output archive while compressing the result asynchronously.
func (ca CompressedArchive) ArchiveAsync(ctx context.Context, output io.Writer, jobs <-chan ArchiveAsyncJob) error {
	if ca.Archival == nil {
		return fmt.Errorf("no archival format")
	}
	do, ok := ca.Archival.(ArchiverAsync)
	if !ok {
		return fmt.Errorf("%T archive does not support async writing", ca.Archival)
	}
	if ca.Compression != nil {
		wc, err := ca.Compression.OpenWriter(output)
		if err != nil {
			return err
		}
		defer wc.Close()
		output = wc
	}
	return do.ArchiveAsync(ctx, output, jobs)
}

// Extract reads files out of a compressed archive while decompressing the results.
func (ca CompressedArchive) Extract(ctx context.Context, sourceArchive io.Reader, handleFile FileHandler) error {
	if ca.Extraction == nil {
		return fmt.Errorf("no extraction format")
	}
	if ca.Compression != nil {
		rc, err := ca.Compression.OpenReader(sourceArchive)
		if err != nil {
			return err
		}
		defer rc.Close()
		sourceArchive = rc
	}
	return ca.Extraction.Extract(ctx, sourceArchive, handleFile)
}

// MatchResult returns true if the format was matched either
// by name, stream, or both. Name usually refers to matching
// by file extension, and stream usually refers to reading
// the first few bytes of the stream (its header). A stream
// match is generally stronger, as filenames are not always
// indicative of their contents if they even exist at all.
type MatchResult struct {
	ByName, ByStream bool
}

// Matched returns true if a match was made by either name or stream.
func (mr MatchResult) Matched() bool { return mr.ByName || mr.ByStream }

func (mr MatchResult) String() string {
	return fmt.Sprintf("{ByName=%v ByStream=%v}", mr.ByName, mr.ByStream)
}

// rewindReader is a Reader that can be rewound (reset) to re-read what
// was already read and then continue to read more from the underlying
// stream. When no more rewinding is necessary, call reader() to get a
// new reader that first reads the buffered bytes, then continues to
// read from the stream. This is useful for "peeking" a stream an
// arbitrary number of bytes. Loosely based on the Connection type
// from https://github.com/mholt/caddy-l4.
//
// If the reader is also an io.Seeker, no buffer is used, and instead
// the stream seeks back to the starting position.
type rewindReader struct {
	io.Reader
	start     int64
	buf       *bytes.Buffer
	bufReader io.Reader
}

func newRewindReader(r io.Reader) (*rewindReader, error) {
	if r == nil {
		return nil, nil
	}

	rr := &rewindReader{Reader: r}

	// avoid buffering if we have a seeker we can use
	if seeker, ok := r.(io.Seeker); ok {
		var err error
		rr.start, err = seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("seek to determine current position: %w", err)
		}
	} else {
		rr.buf = new(bytes.Buffer)
	}

	return rr, nil
}

func (rr *rewindReader) Read(p []byte) (n int, err error) {
	if rr == nil {
		panic("reading from nil rewindReader")
	}

	// if there is a buffer we should read from, start
	// with that; we only read from the underlying stream
	// after the buffer has been "depleted"
	if rr.bufReader != nil {
		n, err = rr.bufReader.Read(p)
		if err == io.EOF {
			rr.bufReader = nil
			err = nil
		}
		if n == len(p) {
			return
		}
	}

	// buffer has been depleted or we are not using one,
	// so read from underlying stream
	nr, err := rr.Reader.Read(p[n:])

	// anything that was read needs to be written to
	// the buffer (if used), even if there was an error
	if nr > 0 && rr.buf != nil {
		if nw, errw := rr.buf.Write(p[n : n+nr]); errw != nil {
			return nw, errw
		}
	}

	// up to now, n was how many bytes were read from
	// the buffer, and nr was how many bytes were read
	// from the stream; add them to return total count
	n += nr

	return
}

// rewind resets the stream to the beginning by causing
// Read() to start reading from the beginning of the
// stream, or, if buffering, the buffered bytes.
func (rr *rewindReader) rewind() {
	if rr == nil {
		return
	}
	if ras, ok := rr.Reader.(io.Seeker); ok {
		if _, err := ras.Seek(rr.start, io.SeekStart); err == nil {
			return
		}
	}
	rr.bufReader = bytes.NewReader(rr.buf.Bytes())
}

// reader returns a reader that reads first from the buffered
// bytes (if buffering), then from the underlying stream; if a
// Seeker, the stream will be seeked back to the start. After
// calling this, no more rewinding is allowed since reads from
// the stream are not recorded, so rewinding properly is impossible.
// If the underlying reader implements io.Seeker, then the
// underlying reader will be used directly.
func (rr *rewindReader) reader() io.Reader {
	if rr == nil {
		return nil
	}
	if ras, ok := rr.Reader.(io.Seeker); ok {
		if _, err := ras.Seek(rr.start, io.SeekStart); err == nil {
			return rr.Reader
		}
	}
	return io.MultiReader(bytes.NewReader(rr.buf.Bytes()), rr.Reader)
}

// NoMatch is a special error returned if there are no matching formats.
var NoMatch = fmt.Errorf("no formats matched")

// ErrMaxBytesReached is returned by IdentifyWithMaxBytes when the byte
// budget for probing was exhausted before a conclusive match could be
// made. It is distinct from NoMatch, which means the input was probed
// and no registered format matched it.
var ErrMaxBytesReached = errors.New("maximum number of bytes reached while identifying format")

// byteLimitReader wraps a reader and allows at most a certain number of
// bytes to be read from it. Once the budget is exhausted, Read returns
// ErrMaxBytesReached (unless the underlying stream is at its end anyway,
// in which case EOF is reported truthfully). The limit can be lifted,
// after which the wrapped reader behaves like the underlying reader again,
// without losing any bytes. It is used to bound the cost of format
// identification without consuming the caller's stream.
type byteLimitReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
	lifted    bool
	stash     []byte // a byte read past the budget while probing for EOF
}

func (blr *byteLimitReader) Read(p []byte) (int, error) {
	if blr.lifted {
		if len(blr.stash) > 0 {
			n := copy(p, blr.stash)
			blr.stash = blr.stash[n:]
			return n, nil
		}
		return blr.r.Read(p)
	}
	if blr.exceeded {
		return 0, ErrMaxBytesReached
	}
	if blr.remaining == 0 {
		return blr.probe()
	}
	if int64(len(p)) > blr.remaining {
		p = p[:blr.remaining]
	}
	n, err := blr.r.Read(p)
	blr.remaining -= int64(n)
	return n, err
}

// probe is called when the budget is exactly exhausted. If the underlying
// stream has no more data either, the budget was sufficient after all and
// EOF (or whatever the underlying reader returns) is reported truthfully.
// Otherwise the budget is genuinely exceeded; the byte read while probing
// is stashed so no data is lost once the limit is lifted.
func (blr *byteLimitReader) probe() (int, error) {
	var b [1]byte
	n, err := blr.r.Read(b[:])
	if n > 0 {
		blr.stash = append(blr.stash, b[:n]...)
		blr.exceeded = true
		return 0, ErrMaxBytesReached
	}
	return 0, err
}

// lift removes the read limit so the rest of the stream can be read freely.
func (blr *byteLimitReader) lift() {
	if blr != nil {
		blr.lifted = true
	}
}

// errIfExceeded returns ErrMaxBytesReached if the budget was exhausted
// during probing. Some format matchers ignore read errors (treating them
// as a non-match), so this lets the caller still tell an exhausted budget
// apart from a genuine non-match.
func (blr *byteLimitReader) errIfExceeded() error {
	if blr != nil && blr.exceeded {
		return ErrMaxBytesReached
	}
	return nil
}

// byteLimitSeekReader is a byteLimitReader that also implements io.Seeker
// by delegating to the underlying stream, so that seekable inputs keep
// their seek-based (unbuffered) identification behavior. Seeking does not
// consume the budget; instead of counting cumulative reads, the budget
// bounds how far past the starting position probing may read (its
// high-water mark), since previously read positions can be re-seeked to.
type byteLimitSeekReader struct {
	*byteLimitReader
	seeker   io.Seeker
	pos      int64 // current position in the stream
	start    int64 // position where identification started
	posKnown bool
}

func (blsr *byteLimitSeekReader) Seek(offset int64, whence int) (int64, error) {
	pos, err := blsr.seeker.Seek(offset, whence)
	if err != nil {
		return pos, err
	}
	if !blsr.posKnown {
		blsr.start = pos
		blsr.posKnown = true
	}
	blsr.pos = pos
	return pos, nil
}

func (blsr *byteLimitSeekReader) Read(p []byte) (int, error) {
	if blsr.lifted {
		if len(blsr.stash) > 0 {
			n := copy(p, blsr.stash)
			blsr.stash = blsr.stash[n:]
			return n, nil
		}
		return blsr.r.Read(p)
	}
	if blsr.exceeded {
		return 0, ErrMaxBytesReached
	}
	allowed := blsr.remaining - (blsr.pos - blsr.start)
	if allowed <= 0 {
		// probe for EOF like byteLimitReader does, but a seeker can
		// simply un-read the probed byte by seeking back
		var b [1]byte
		n, err := blsr.r.Read(b[:])
		if n > 0 {
			if _, serr := blsr.seeker.Seek(int64(-n), io.SeekCurrent); serr == nil {
				blsr.exceeded = true
				return 0, ErrMaxBytesReached
			}
			// could not un-read; stash the bytes so they are not
			// lost once the limit is lifted
			blsr.stash = append(blsr.stash, b[:n]...)
			blsr.exceeded = true
			return 0, ErrMaxBytesReached
		}
		return 0, err
	}
	if int64(len(p)) > allowed {
		p = p[:allowed]
	}
	n, err := blsr.r.Read(p)
	blsr.pos += int64(n)
	return n, err
}

// Registered formats.
var formats = make(map[string]Format)

// Interface guards
var (
	_ Format        = (*CompressedArchive)(nil)
	_ Archiver      = (*CompressedArchive)(nil)
	_ ArchiverAsync = (*CompressedArchive)(nil)
	_ Extractor     = (*CompressedArchive)(nil)
	_ Compressor    = (*CompressedArchive)(nil)
	_ Decompressor  = (*CompressedArchive)(nil)
)
