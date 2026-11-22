package issue

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	lbA "github.com/getlantern/lantern-box/adapter"

	"github.com/getlantern/radiance/internal/redact"
)

const (
	// maxLogReadFactor bounds how much uncompressed log to read toward an archive:
	// maxArchiveSize * maxLogReadFactor bytes. Logs compress by at most roughly this
	// factor, so reading more than this can never be needed to reach the compressed
	// size budget.
	maxLogReadFactor int64 = 20
	// backupTimeFormat matches the timestamp format used in rotated backup
	// filenames: "<log-name>-<timestamp>.log.gz".
	backupTimeFormat = "2006-01-02T15-04-05.000"

	logExt    = ".log"
	backupExt = ".log.gz"
)

// buildIssueArchive creates a zip archive containing all .log files found in
// logDir plus additional attachment files. The primary log (lantern.log) is
// given truncation priority; secondary log files and attachments are included
// greedily if space permits. The total compressed archive size will not exceed
// maxSize bytes.
func buildIssueArchive(logger *slog.Logger, logDir string, additionalFiles []string, maxSize int64) ([]byte, error) {
	logFiles := globFiles(logger, logDir, "*.log")

	var primaryLogData []byte
	var secondaryLogs []extraFile

	for _, lf := range logFiles {
		data, err := snapshotLogFile(lf, maxSize)
		if err != nil {
			logger.Warn("unable to snapshot log file", "path", lf, "error", err)
			continue
		}
		if len(data) == 0 {
			continue
		}
		data = redactLog(data)
		if filepath.Base(lf) == logArchiveName {
			primaryLogData = data
		} else {
			secondaryLogs = append(secondaryLogs, extraFile{
				name: filepath.Base(lf),
				data: data,
			})
		}
	}

	attachments := readExtraFiles(logger, additionalFiles)

	primaryPath := filepath.Join(logDir, logArchiveName)
	primaryLogData = prependMostRecentBackup(logger, primaryPath, primaryLogData, maxSize)

	// Logs and attachments (config.json, servers.json, debug-box-options.json)
	// can name helper outbounds and the helpers' addresses, which clients
	// must not export.
	primaryLogData = redact.HelperBytes(primaryLogData)
	for i := range secondaryLogs {
		secondaryLogs[i].data = redact.HelperBytes(secondaryLogs[i].data)
	}
	for i := range attachments {
		attachments[i].data = redact.HelperBytes(attachments[i].data)
	}

	return fitArchive(primaryLogData, secondaryLogs, attachments, maxSize)
}

// sanitizeJSONAttachment re-encodes a JSON attachment, one value per line, with secret
// fields redacted, URL queries stripped, and helpers stubbed as by stubHelpers.
// Attachments without a .json extension, matched case-insensitively, are returned
// unchanged. It fails on a JSON attachment that does not parse.
func sanitizeJSONAttachment(name string, data []byte) ([]byte, error) {
	if !strings.EqualFold(filepath.Ext(name), ".json") {
		return data, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON document")
	}
	return json.MarshalIndent(stubHelpers(redactJSONValue(v)), "", "  ")
}

// stubHelpers replaces every object tagged with a helper tag, and every value keyed by
// one, with {"type": <its type>, "tag": "helper"}, and every helper tag string with
// "helper".
func stubHelpers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if tag, ok := t["tag"].(string); ok && isHelperTag(tag) {
			return helperStub(t)
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			if isHelperTag(k) {
				out["helper"] = helperStub(e)
				continue
			}
			out[k] = stubHelpers(e)
		}
		return out
	case []any:
		for i := range t {
			t[i] = stubHelpers(t[i])
		}
		return t
	case string:
		if isHelperTag(t) {
			return "helper"
		}
	}
	return v
}

func helperStub(v any) map[string]any {
	stub := map[string]any{"tag": "helper"}
	if m, ok := v.(map[string]any); ok {
		if typ, ok := m["type"].(string); ok {
			stub["type"] = typ
		}
	}
	return stub
}

// isHelperTag reports whether tag names a helper or reverse outbound, a group
// over them, the reverse portal, or selects one; all mark the device as having
// personal proxies.
func isHelperTag(tag string) bool {
	return lbA.IsHelperTag(tag) || lbA.IsReverseHelperTag(tag) || tag == redact.ReversePortalTag ||
		tag == redact.PersonalProxiesTag || tag == redact.PersonalProxyTag ||
		strings.HasPrefix(tag, redact.PersonalProxyTag+":")
}

// prependMostRecentBackup prepends the newest rotated gzip backup, if present,
// so a mid-session rotation does not lose earlier log history.
func prependMostRecentBackup(logger *slog.Logger, primaryLogPath string, current []byte, maxArchiveSize int64) []byte {
	backupPath, ok := findMostRecentCompressedBackup(logger, primaryLogPath)
	if !ok {
		return current
	}

	remaining := maxArchiveSize*maxLogReadFactor - int64(len(current))
	if remaining <= 0 {
		return current
	}

	backupData, err := readGzipTail(backupPath, remaining)
	if err != nil {
		logger.Warn("unable to read compressed log backup", "path", backupPath, "error", err)
		return current
	}
	if len(backupData) == 0 {
		return current
	}
	backupData = redactLog(backupData)
	if backupData[len(backupData)-1] != '\n' {
		backupData = append(backupData, '\n')
	}

	return append(backupData, current...)
}

func findMostRecentCompressedBackup(logger *slog.Logger, primaryLogPath string) (string, bool) {
	dir := filepath.Dir(primaryLogPath)
	base := filepath.Base(primaryLogPath)
	logName := strings.TrimSuffix(base, logExt)

	matches := globFiles(logger, dir, logName+"-*"+backupExt)
	if len(matches) == 0 {
		return "", false
	}

	var latestPath string
	var latestTimestamp time.Time
	for _, match := range matches {
		timestamp, ok := parseBackupTimestamp(match, logName)
		if ok && timestamp.After(latestTimestamp) {
			latestTimestamp = timestamp
			latestPath = match
		}
	}

	return latestPath, latestPath != ""
}

func parseBackupTimestamp(path, logName string) (time.Time, bool) {
	filename := filepath.Base(path)
	prefix := logName + "-"
	if !strings.HasPrefix(filename, prefix) || !strings.HasSuffix(filename, backupExt) {
		return time.Time{}, false
	}

	timestamp := filename[len(prefix) : len(filename)-len(backupExt)]
	ts, err := time.Parse(backupTimeFormat, timestamp)
	return ts, err == nil
}

// readGzipTail returns up to maxRead bytes from the end of the decompressed file.
// The tail is kept rather than the head because it is the history nearest in time
// to the current log; memory stays bounded to ~maxRead even when the backup
// decompresses to more.
func readGzipTail(path string, maxRead int64) ([]byte, error) {
	if maxRead <= 0 {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	var tail []byte
	cut := false
	chunk := make([]byte, 32*1024)
	for {
		n, readErr := gz.Read(chunk)
		if n > 0 {
			tail = append(tail, chunk[:n]...)
			if int64(len(tail)) > maxRead {
				tail = append(tail[:0], tail[int64(len(tail))-maxRead:]...)
				cut = true
			}
		}
		if readErr == io.EOF {
			if cut {
				tail = dropPartialFirstLine(tail)
			}
			return tail, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func globFiles(logger *slog.Logger, dir, pattern string) []string {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		logger.Warn("unable to glob files", "dir", dir, "pattern", pattern, "error", err)
		return nil
	}
	return matches
}

// snapshotLogFile opens the log file, records its current size, and reads the tail
// up to a reasonable cap.
func snapshotLogFile(logPath string, maxCompressed int64) ([]byte, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	if size == 0 {
		return nil, nil
	}

	maxRead := maxCompressed * maxLogReadFactor
	readSize := size
	if readSize > maxRead {
		readSize = maxRead
	}

	// Seek to read only the tail (most recent logs).
	if size > readSize {
		if _, err := f.Seek(size-readSize, io.SeekStart); err != nil {
			return nil, err
		}
	}

	data := make([]byte, readSize)
	n, err := io.ReadFull(f, data)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("reading log file: %w", err)
	}
	if size > readSize {
		return dropPartialFirstLine(data[:n]), nil
	}
	return data[:n], nil
}

// dropPartialFirstLine drops b's first line, which a read starting mid-file
// has cut: redaction works line by line, and the cut could separate an
// address from the helper outbound its line names.
func dropPartialFirstLine(b []byte) []byte {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return nil
	}
	return b[i+1:]
}

type extraFile struct {
	name string
	data []byte
}

func readExtraFiles(logger *slog.Logger, paths []string) []extraFile {
	var files []extraFile
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			logger.Warn("unable to read additional file", "path", p, "error", err)
			continue
		}
		if data, err = sanitizeJSONAttachment(p, data); err != nil {
			logger.Warn("omitting unparseable JSON attachment", "path", p, "error", err)
			continue
		}
		files = append(files, extraFile{
			name: filepath.Base(p),
			data: data,
		})
	}
	return files
}

// fitArchive builds a zip archive that fits within maxSize. The primary log
// (lantern.log) is given truncation priority, followed by secondary log files,
// then attachments.
func fitArchive(primaryLog []byte, secondaryLogs []extraFile, attachments []extraFile, maxSize int64) ([]byte, error) {
	allLogs := logsFromPrimary(primaryLog, secondaryLogs)

	if len(allLogs) == 0 && len(attachments) == 0 {
		return nil, nil
	}

	// Try everything.
	buf, err := writeArchive(allLogs, attachments)
	if err != nil {
		return nil, err
	}
	if int64(buf.Len()) <= maxSize {
		return buf.Bytes(), nil
	}

	// Try primary log only.
	primaryLogs := logsFromPrimary(primaryLog, nil)
	if len(primaryLog) > 0 {
		buf, err = writeArchive(primaryLogs, nil)
		if err != nil {
			return nil, err
		}
		if int64(buf.Len()) <= maxSize {
			// Full primary fits — greedily add secondary logs, then attachments.
			return addExtrasGreedily(primaryLogs, secondaryLogs, attachments, maxSize)
		}

		// Full primary doesn't fit — binary search for the maximum tail.
		tailSize := searchMaxLogTail(primaryLog, maxSize)
		tail := primaryLog[len(primaryLog)-tailSize:]
		trimmedPrimary := logsFromPrimary(tail, nil)
		return addExtrasGreedily(trimmedPrimary, secondaryLogs, attachments, maxSize)
	}

	// No primary log — greedily add secondary logs and attachments.
	return addExtrasGreedily(nil, secondaryLogs, attachments, maxSize)
}

// logsFromPrimary builds a combined log entry list with the primary log first.
func logsFromPrimary(primaryLog []byte, secondaryLogs []extraFile) []extraFile {
	var logs []extraFile
	if len(primaryLog) > 0 {
		logs = append(logs, extraFile{name: logArchiveName, data: primaryLog})
	}
	logs = append(logs, secondaryLogs...)
	return logs
}

const logArchiveName = "lantern.log"

func writeArchive(logs []extraFile, attachments []extraFile) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	for _, l := range logs {
		fw, err := w.Create(l.name)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(l.data); err != nil {
			return nil, err
		}
	}

	for _, f := range attachments {
		fw, err := w.Create("attachments/" + f.name)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(f.data); err != nil {
			return nil, err
		}
	}

	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}

// searchMaxLogTail binary-searches for the largest tail of logData (in 256KB chunks)
// that compresses into a zip archive not exceeding maxSize.
func searchMaxLogTail(logData []byte, maxSize int64) int {
	const chunkSize = 256 * 1024
	n := len(logData)
	lo, hi := 1, (n+chunkSize-1)/chunkSize
	best := 0

	for lo <= hi {
		mid := lo + (hi-lo)/2
		tailBytes := mid * chunkSize
		if tailBytes > n {
			tailBytes = n
		}

		logs := []extraFile{{name: logArchiveName, data: logData[n-tailBytes:]}}
		buf, err := writeArchive(logs, nil)
		if err != nil {
			hi = mid - 1
			continue
		}
		if int64(buf.Len()) <= maxSize {
			best = tailBytes
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return best
}

// addExtrasGreedily starts from the given base logs and greedily adds secondary
// log files then attachment files, keeping each only if the archive still fits
// within maxSize.
func addExtrasGreedily(baseLogs []extraFile, secondaryLogs []extraFile, attachments []extraFile, maxSize int64) ([]byte, error) {
	currentLogs := make([]extraFile, len(baseLogs))
	copy(currentLogs, baseLogs)
	var currentAttachments []extraFile

	buf, err := writeArchive(currentLogs, nil)
	if err != nil {
		return nil, err
	}
	lastGood := buf.Bytes()

	// Greedily add secondary log files.
	for _, sl := range secondaryLogs {
		trial := append(currentLogs[:len(currentLogs):len(currentLogs)], sl)
		buf, err := writeArchive(trial, currentAttachments)
		if err != nil {
			continue
		}
		if int64(buf.Len()) <= maxSize {
			currentLogs = trial
			lastGood = buf.Bytes()
		}
	}

	// Greedily add attachment files.
	for _, a := range attachments {
		trial := append(currentAttachments[:len(currentAttachments):len(currentAttachments)], a)
		buf, err := writeArchive(currentLogs, trial)
		if err != nil {
			continue
		}
		if int64(buf.Len()) <= maxSize {
			currentAttachments = trial
			lastGood = buf.Bytes()
		}
	}

	return lastGood, nil
}
