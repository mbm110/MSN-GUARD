package issue

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/log"
)

func TestSnapshotLogFile(t *testing.T) {
	t.Run("reads full file when small", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "test.log")
		content := "line1\nline2\nline3\n"
		require.NoError(t, os.WriteFile(logPath, []byte(content), 0644))

		data, err := snapshotLogFile(logPath, 1024*1024)
		require.NoError(t, err)
		assert.Equal(t, content, string(data))
	})

	t.Run("reads only tail when file exceeds cap", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "test.log")

		// maxCompressed=100 → maxRead = 100*20 = 2000
		// Write 5040 bytes of 120-byte lines so the file exceeds the cap and
		// the read starts at byte 3040, 40 bytes into a line.
		full := bytes.Repeat(append(bytes.Repeat([]byte("X"), 119), '\n'), 42)
		require.NoError(t, os.WriteFile(logPath, full, 0644))

		data, err := snapshotLogFile(logPath, 100)
		require.NoError(t, err)
		// The tail of the file, without the line the read cut.
		assert.Equal(t, string(full[3120:]), string(data))
	})

	t.Run("returns nil for empty file", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "empty.log")
		require.NoError(t, os.WriteFile(logPath, nil, 0644))

		data, err := snapshotLogFile(logPath, 1024*1024)
		require.NoError(t, err)
		assert.Nil(t, data)
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := snapshotLogFile("/nonexistent/path.log", 1024*1024)
		assert.Error(t, err)
	})

	t.Run("snapshot is stable after file rotation", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "test.log")
		original := "original log content\n"
		require.NoError(t, os.WriteFile(logPath, []byte(original), 0644))

		// Open and snapshot size (simulating what snapshotLogFile does internally).
		f, err := os.Open(logPath)
		require.NoError(t, err)
		defer f.Close()

		fi, err := f.Stat()
		require.NoError(t, err)
		size := fi.Size()

		// Simulate rotation: rename the file and create a new one.
		require.NoError(t, os.Rename(logPath, logPath+".1"))
		require.NoError(t, os.WriteFile(logPath, []byte("new log content\n"), 0644))

		// The original fd should still read the original data.
		data := make([]byte, size)
		n, err := f.Read(data)
		require.NoError(t, err)
		assert.Equal(t, original, string(data[:n]))
	})
}

func TestGlobFiles(t *testing.T) {
	t.Run("returns matching .log files", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("main"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-crash.log"), []byte("crash"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), []byte("not a log"), 0644))

		files := globFiles(log.NoOpLogger(), dir, "*.log")
		require.Len(t, files, 2)
		bases := make([]string, len(files))
		for i, f := range files {
			bases[i] = filepath.Base(f)
		}
		assert.ElementsMatch(t, []string{"lantern-crash.log", "lantern.log"}, bases)
	})

	t.Run("returns nil for empty dir", func(t *testing.T) {
		dir := t.TempDir()
		files := globFiles(log.NoOpLogger(), dir, "*.log")
		assert.Nil(t, files)
	})

	t.Run("returns nil for nonexistent dir", func(t *testing.T) {
		files := globFiles(log.NoOpLogger(), "/nonexistent/dir", "*.log")
		assert.Nil(t, files)
	})
}

func TestReadExtraFiles(t *testing.T) {
	t.Run("reads existing files", func(t *testing.T) {
		dir := t.TempDir()
		f1 := filepath.Join(dir, "a.txt")
		f2 := filepath.Join(dir, "b.txt")
		require.NoError(t, os.WriteFile(f1, []byte("aaa"), 0644))
		require.NoError(t, os.WriteFile(f2, []byte("bbb"), 0644))

		files := readExtraFiles(log.NoOpLogger(), []string{f1, f2})
		require.Len(t, files, 2)
		assert.Equal(t, "a.txt", files[0].name)
		assert.Equal(t, "aaa", string(files[0].data))
		assert.Equal(t, "b.txt", files[1].name)
		assert.Equal(t, "bbb", string(files[1].data))
	})

	t.Run("skips missing files", func(t *testing.T) {
		dir := t.TempDir()
		existing := filepath.Join(dir, "exists.txt")
		require.NoError(t, os.WriteFile(existing, []byte("data"), 0644))

		files := readExtraFiles(log.NoOpLogger(), []string{"/no/such/file", existing})
		require.Len(t, files, 1)
		assert.Equal(t, "exists.txt", files[0].name)
	})

	t.Run("nil input returns nil", func(t *testing.T) {
		files := readExtraFiles(log.NoOpLogger(), nil)
		assert.Nil(t, files)
	})
}

func TestWriteArchive(t *testing.T) {
	t.Run("log only", func(t *testing.T) {
		logs := []extraFile{{name: logArchiveName, data: []byte("some log content")}}
		buf, err := writeArchive(logs, nil)
		require.NoError(t, err)

		entries := readZipEntries(t, buf.Bytes())
		require.Len(t, entries, 1)
		assert.Equal(t, logArchiveName, entries[0].name)
		assert.Equal(t, "some log content", entries[0].content)
	})

	t.Run("multiple logs with attachments", func(t *testing.T) {
		logs := []extraFile{
			{name: "lantern.log", data: []byte("main log")},
			{name: "lantern-crash.log", data: []byte("crash log")},
		}
		attachments := []extraFile{
			{name: "config.json", data: []byte(`{"key":"val"}`)},
		}
		buf, err := writeArchive(logs, attachments)
		require.NoError(t, err)

		entries := readZipEntries(t, buf.Bytes())
		require.Len(t, entries, 3)
		assert.Equal(t, "lantern.log", entries[0].name)
		assert.Equal(t, "lantern-crash.log", entries[1].name)
		assert.Equal(t, "attachments/config.json", entries[2].name)
	})

	t.Run("attachments only", func(t *testing.T) {
		attachments := []extraFile{{name: "file.txt", data: []byte("hello")}}
		buf, err := writeArchive(nil, attachments)
		require.NoError(t, err)

		entries := readZipEntries(t, buf.Bytes())
		require.Len(t, entries, 1)
		assert.Equal(t, "attachments/file.txt", entries[0].name)
	})

	t.Run("empty inputs", func(t *testing.T) {
		buf, err := writeArchive(nil, nil)
		require.NoError(t, err)
		// Should produce a valid but empty zip.
		entries := readZipEntries(t, buf.Bytes())
		assert.Empty(t, entries)
	})
}

func TestFitArchive(t *testing.T) {
	t.Run("everything fits", func(t *testing.T) {
		logData := []byte("small log")
		secondary := []extraFile{{name: "crash.log", data: []byte("crash")}}
		attachments := []extraFile{{name: "a.txt", data: []byte("small")}}
		result, err := fitArchive(logData, secondary, attachments, 1024*1024)
		require.NoError(t, err)
		require.NotNil(t, result)

		entries := readZipEntries(t, result)
		assert.Len(t, entries, 3)
	})

	t.Run("nil log and nil extras returns nil", func(t *testing.T) {
		result, err := fitArchive(nil, nil, nil, 1024*1024)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("attachments dropped when too large", func(t *testing.T) {
		logData := []byte("log data")
		// Make an attachment that's big enough to push past a small maxSize.
		bigAttachment := extraFile{name: "big.bin", data: bytes.Repeat([]byte{0xFF}, 50*1024)}

		// Find the compressed size of just the log.
		logs := []extraFile{{name: logArchiveName, data: logData}}
		logOnly, err := writeArchive(logs, nil)
		require.NoError(t, err)
		maxSize := int64(logOnly.Len()) + 100 // just barely enough for log, not the extra

		result, err := fitArchive(logData, nil, []extraFile{bigAttachment}, maxSize)
		require.NoError(t, err)

		entries := readZipEntries(t, result)
		require.Len(t, entries, 1)
		assert.Equal(t, logArchiveName, entries[0].name)
		assert.Equal(t, "log data", entries[0].content)
	})

	t.Run("log truncated to tail when too large", func(t *testing.T) {
		// Use incompressible random data (2MB) with a budget that fits ~1-2
		// chunks (256KB each) but not the full log.
		logData := randomBytes(t, 2*1024*1024) // 2MB random

		maxSize := int64(512 * 1024) // 512KB

		result, err := fitArchive(logData, nil, nil, maxSize)
		require.NoError(t, err)
		assert.LessOrEqual(t, int64(len(result)), maxSize)

		entries := readZipEntries(t, result)
		require.Len(t, entries, 1)
		assert.Equal(t, logArchiveName, entries[0].name)

		// The included content should be a tail of the original.
		content := entries[0].content
		assert.True(t, len(content) < len(logData), "log should be truncated")
		assert.Equal(t, string(logData[len(logData)-len(content):]), content,
			"included content should be the tail of the original log")
	})

	t.Run("secondary logs and attachments only when no primary", func(t *testing.T) {
		secondary := []extraFile{{name: "crash.log", data: []byte("crash")}}
		attachments := []extraFile{{name: "a.txt", data: []byte("aaa")}}
		result, err := fitArchive(nil, secondary, attachments, 1024*1024)
		require.NoError(t, err)

		entries := readZipEntries(t, result)
		assert.Len(t, entries, 2)
	})
}

func TestSearchMaxLogTail(t *testing.T) {
	t.Run("all fits", func(t *testing.T) {
		logData := []byte("small log data")
		tailSize := searchMaxLogTail(logData, 1024*1024)
		assert.Equal(t, len(logData), tailSize)
	})

	t.Run("truncates incompressible data", func(t *testing.T) {
		logData := randomBytes(t, 1024*1024) // 1MB random

		maxSize := int64(300 * 1024) // 300KB
		tailSize := searchMaxLogTail(logData, maxSize)
		assert.Greater(t, tailSize, 0)
		assert.Less(t, tailSize, len(logData))

		// Verify the result actually fits.
		logs := []extraFile{{name: logArchiveName, data: logData[len(logData)-tailSize:]}}
		buf, err := writeArchive(logs, nil)
		require.NoError(t, err)
		assert.LessOrEqual(t, int64(buf.Len()), maxSize)
	})
}

func TestAddExtrasGreedily(t *testing.T) {
	t.Run("adds all when they fit", func(t *testing.T) {
		baseLogs := []extraFile{{name: logArchiveName, data: []byte("log")}}
		secondary := []extraFile{{name: "crash.log", data: []byte("crash")}}
		attachments := []extraFile{{name: "a.txt", data: []byte("aaa")}}
		result, err := addExtrasGreedily(baseLogs, secondary, attachments, 1024*1024)
		require.NoError(t, err)

		entries := readZipEntries(t, result)
		assert.Len(t, entries, 3)
	})

	t.Run("skips extras that would exceed limit", func(t *testing.T) {
		baseLogs := []extraFile{{name: logArchiveName, data: []byte("log")}}
		small := extraFile{name: "small.txt", data: []byte("s")}
		big := extraFile{name: "big.bin", data: bytes.Repeat([]byte{0xFF}, 50*1024)}

		// Budget enough for log + small, but not big.
		bufWithSmall, err := writeArchive(baseLogs, []extraFile{small})
		require.NoError(t, err)
		maxSize := int64(bufWithSmall.Len()) + 50 // tight budget

		result, err := addExtrasGreedily(baseLogs, nil, []extraFile{small, big}, maxSize)
		require.NoError(t, err)

		entries := readZipEntries(t, result)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.name
		}
		assert.Contains(t, names, logArchiveName)
		assert.Contains(t, names, "attachments/small.txt")
		assert.NotContains(t, names, "attachments/big.bin")
	})

	t.Run("no extras returns log only", func(t *testing.T) {
		baseLogs := []extraFile{{name: logArchiveName, data: []byte("log content")}}
		result, err := addExtrasGreedily(baseLogs, nil, nil, 1024*1024)
		require.NoError(t, err)

		entries := readZipEntries(t, result)
		require.Len(t, entries, 1)
		assert.Equal(t, logArchiveName, entries[0].name)
	})
}

func TestBuildIssueArchive(t *testing.T) {
	t.Run("end to end with log and extras", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("log line 1\nlog line 2\n"), 0644))

		extra := filepath.Join(dir, "extra.txt")
		require.NoError(t, os.WriteFile(extra, []byte("extra content"), 0644))

		result, err := buildIssueArchive(log.NoOpLogger(), dir, []string{extra}, 1024*1024)
		require.NoError(t, err)
		require.NotNil(t, result)

		entries := readZipEntries(t, result)
		require.Len(t, entries, 2)
		assert.Equal(t, logArchiveName, entries[0].name)
		assert.Equal(t, "log line 1\nlog line 2\n", entries[0].content)
		assert.Equal(t, "attachments/extra.txt", entries[1].name)
	})

	t.Run("includes all log files in directory", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("main log"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-crash.log"), []byte("crash log"), 0644))

		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, 1024*1024)
		require.NoError(t, err)
		require.NotNil(t, result)

		entries := readZipEntries(t, result)
		require.Len(t, entries, 2)
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.name
		}
		assert.Contains(t, names, "lantern.log")
		assert.Contains(t, names, "lantern-crash.log")
	})

	t.Run("missing log dir still includes extras", func(t *testing.T) {
		dir := t.TempDir()
		extra := filepath.Join(dir, "extra.txt")
		require.NoError(t, os.WriteFile(extra, []byte("data"), 0644))

		result, err := buildIssueArchive(log.NoOpLogger(), filepath.Join(dir, "nonexistent"), []string{extra}, 1024*1024)
		require.NoError(t, err)
		require.NotNil(t, result)

		entries := readZipEntries(t, result)
		require.Len(t, entries, 1)
		assert.Equal(t, "attachments/extra.txt", entries[0].name)
	})

	t.Run("archive respects maxSize", func(t *testing.T) {
		dir := t.TempDir()
		// Write incompressible data (2MB).
		logData := randomBytes(t, 2*1024*1024)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), logData, 0644))

		maxSize := int64(512 * 1024)
		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, maxSize)
		require.NoError(t, err)
		assert.LessOrEqual(t, int64(len(result)), maxSize)

		// Verify it contains the tail.
		entries := readZipEntries(t, result)
		require.Len(t, entries, 1)
		content := entries[0].content
		assert.Equal(t, string(logData[len(logData)-len(content):]), content)
	})

	t.Run("snapshot excludes data written after call", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "lantern.log")
		original := "before snapshot\n"
		require.NoError(t, os.WriteFile(logPath, []byte(original), 0644))

		// Snapshot the file.
		data, err := snapshotLogFile(logPath, 1024*1024)
		require.NoError(t, err)

		// Append after snapshot.
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = f.WriteString("after snapshot\n")
		require.NoError(t, err)
		f.Close()

		// Snapshot should only contain original content.
		assert.Equal(t, original, string(data))
	})
}

// --- test helpers ---

type zipEntry struct {
	name    string
	content string
}

func readZipEntries(t *testing.T, data []byte) []zipEntry {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)

	var entries []zipEntry
	for _, f := range r.File {
		rc, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(rc)
		require.NoError(t, err)
		rc.Close()
		entries = append(entries, zipEntry{name: f.Name, content: string(body)})
	}
	return entries
}

func writeGzipFile(t *testing.T, path string, content []byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(content)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0644))
}

func TestMostRecentCompressedBackup(t *testing.T) {
	t.Run("picks newest by lexical timestamp order", func(t *testing.T) {
		dir := t.TempDir()
		primary := filepath.Join(dir, "lantern.log")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz"), nil, 0644))
		newest := filepath.Join(dir, "lantern-2026-06-15T16-02-44.000.log.gz")
		require.NoError(t, os.WriteFile(newest, nil, 0644))

		got, ok := findMostRecentCompressedBackup(log.NoOpLogger(), primary)
		require.True(t, ok)
		assert.Equal(t, newest, got)
	})

	t.Run("false when no compressed backup", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log"), nil, 0644))

		_, ok := findMostRecentCompressedBackup(log.NoOpLogger(), filepath.Join(dir, "lantern.log"))
		assert.False(t, ok)
	})

	t.Run("ignores siblings the glob matches but lumberjack did not produce", func(t *testing.T) {
		dir := t.TempDir()
		primary := filepath.Join(dir, "lantern.log")
		backup := filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz")
		require.NoError(t, os.WriteFile(backup, nil, 0644))
		// A crash-log sibling the "lantern-*.log.gz" glob also matches; its later
		// timestamp would win a naive newest-wins comparison, but it is not a
		// rotation of lantern.log and must be rejected.
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-crash-2026-06-15T16-00-00.000.log.gz"), nil, 0644))

		got, ok := findMostRecentCompressedBackup(log.NoOpLogger(), primary)
		require.True(t, ok)
		assert.Equal(t, backup, got)
	})
}

func TestReadGzipTail(t *testing.T) {
	t.Run("round-trips content within cap", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "backup.log.gz")
		writeGzipFile(t, path, []byte("old line 1\nold line 2\n"))

		data, err := readGzipTail(path, 1024)
		require.NoError(t, err)
		assert.Equal(t, "old line 1\nold line 2\n", string(data))
	})

	t.Run("keeps the tail when over cap", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "backup.log.gz")
		writeGzipFile(t, path, []byte("01234\n6789\n"))

		data, err := readGzipTail(path, 7)
		require.NoError(t, err)
		assert.Equal(t, "6789\n", string(data), "the tail, without the line the cap cut")
	})

	t.Run("keeps the tail across multiple read chunks", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "backup.log.gz")
		content := append(bytes.Repeat([]byte("A"), 100*1024), []byte("\nTAILMARKER")...)
		writeGzipFile(t, path, content)

		data, err := readGzipTail(path, 14)
		require.NoError(t, err)
		assert.Equal(t, "TAILMARKER", string(data))
	})

	t.Run("error on non-gzip input", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "backup.log.gz")
		require.NoError(t, os.WriteFile(path, []byte("not gzip data"), 0644))

		_, err := readGzipTail(path, 1024)
		assert.Error(t, err)
	})
}

func TestBuildIssueArchiveIncludesCompressedBackup(t *testing.T) {
	primaryContent := func(t *testing.T, result []byte) string {
		t.Helper()
		for _, e := range readZipEntries(t, result) {
			if e.name == logArchiveName {
				return e.content
			}
		}
		t.Fatalf("no %s entry in archive", logArchiveName)
		return ""
	}

	t.Run("orders backup before current", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("current line\n"), 0644))
		writeGzipFile(t, filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz"), []byte("rotated line\n"))

		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, 1024*1024)
		require.NoError(t, err)
		assert.Equal(t, "rotated line\ncurrent line\n", primaryContent(t, result))
	})

	t.Run("inserts newline when backup lacks trailing newline", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("current line\n"), 0644))
		writeGzipFile(t, filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz"), []byte("rotated line"))

		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, 1024*1024)
		require.NoError(t, err)
		assert.Equal(t, "rotated line\ncurrent line\n", primaryContent(t, result))
	})

	t.Run("falls back to current on corrupt backup", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("current line\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz"), []byte("not gzip"), 0644))

		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, 1024*1024)
		require.NoError(t, err)
		assert.Equal(t, "current line\n", primaryContent(t, result))
	})

	t.Run("ignores empty backup", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), []byte("current line\n"), 0644))
		writeGzipFile(t, filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz"), nil)

		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, 1024*1024)
		require.NoError(t, err)
		assert.Equal(t, "current line\n", primaryContent(t, result))
	})

	t.Run("trims oldest backup bytes first when over budget", func(t *testing.T) {
		dir := t.TempDir()
		current := randomBytes(t, 200*1024)
		copy(current[len(current)-len("CURRENTTAILMARKER"):], "CURRENTTAILMARKER")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lantern.log"), current, 0644))

		backup := randomBytes(t, 400*1024)
		copy(backup, "BACKUPHEADMARKER")
		writeGzipFile(t, filepath.Join(dir, "lantern-2026-06-15T15-31-02.000.log.gz"), backup)

		// 200 KiB current + 400 KiB backup (incompressible) exceed the 384 KiB
		// budget, so the tail-trim must drop the prepended backup (oldest) and
		// keep the current log (newest).
		result, err := buildIssueArchive(log.NoOpLogger(), dir, nil, 384*1024)
		require.NoError(t, err)
		primary := primaryContent(t, result)
		assert.Contains(t, primary, "CURRENTTAILMARKER")
		assert.NotContains(t, primary, "BACKUPHEADMARKER")
	})
}

// randomBytes returns n incompressible bytes with no ':' or '=', so log redaction finds
// no URL or field in them and leaves them unchanged.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	for i, c := range b {
		if c == ':' || c == '=' {
			b[i] = c + 1
		}
	}
	return b
}
