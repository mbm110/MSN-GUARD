// Package settings provides a simple interface for storing and retrieving user settings.
package settings

import (
	"context"
	jsonpkg "encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/fileperm"
)

type _key string

const (
	// Keys for various settings.
	// General settings keys.
	DataPathKey    _key = "data_path"    // string
	LogPathKey     _key = "log_path"     // string
	LogLevelKey    _key = "log_level"    // string
	CountryCodeKey _key = "country_code" // string
	LocaleKey      _key = "locale"       // string
	TimeZoneKey    _key = "time_zone"    // string, IANA name reported by the host app
	DeviceIDKey    _key = "device_id"    // string/int
	// PublicIPKey stores the device's last detected public IP, unmasked, because the API trusts
	// it as the client's exact address. Older versions stored a truncated value under
	// "public_ip", which is deliberately not read.
	PublicIPKey _key = "last_public_ip" // string

	// Application behavior related keys.
	TelemetryKey _key = "telemetry_enabled" // bool

	// User account related keys.
	EmailKey         _key = "email"          // string
	UserIDKey        _key = "user_id"        // string
	UserLevelKey     _key = "user_level"     // string
	TokenKey         _key = "token"          // string
	JwtTokenKey      _key = "jwt_token"      // string
	DevicesKey       _key = "devices"        // []Device
	UserDataKey      _key = "user_data"      // [account.UserData]
	OAuthLoginKey    _key = "oauth_login"    // bool
	OAuthProviderKey _key = "oauth_provider" // string (e.g. "google", "apple", "email")

	// VPN related keys.
	SmartRoutingKey      _key = "smart_routing"       // bool
	SplitTunnelKey       _key = "split_tunnel"        // bool
	SplitTunnelPolicyKey _key = "split_tunnel_policy" // string ("exclude"|"include")
	AdBlockKey           _key = "ad_block"            // bool
	// ProxylessKey lets smart routing reach sites directly, without a proxy,
	// when they aren't blocked. Unset means true. It applies only with
	// smart routing and the server's proxyless feature flag.
	ProxylessKey        _key = "proxyless"          // bool (unset = true)
	AutoConnectKey      _key = "auto_connect"       // bool
	PeerShareEnabledKey _key = "peer_share_enabled" // bool
	// PeerManualPortKey is the TCP port number the user has manually
	// forwarded on their router for the peer-proxy inbound (single-
	// port 1:1 NAT). Valid range is 1..65535; 0 means unset.
	PeerManualPortKey _key = "peer_manual_port" // int (0 = unset; 1..65535 = manual port)
	// PeerServePoolKey says whether the peer proxy also serves the general
	// pool ("help others too") rather than only its helper pairings. Unset
	// means true.
	PeerServePoolKey _key = "peer_serve_pool" // bool (unset = true)
	// UnboundedKey is the local opt-in (bool) for the Unbounded widget proxy.
	UnboundedKey      _key = "unbounded"       // bool
	SelectedServerKey _key = "selected_server" // [servers.Server] Server.Options is not stored

	PreferredLocationKey _key = "preferred_location" // [common.PreferredLocation]

	settingsFileName = "settings.json"
	// legacySettingsFileName is what v9.0.x called the same file (it was
	// renamed). On upgrade from v9.0.x, the user's
	// persisted user_id / token / user_level live at <dataDir>/local.json;
	// migrateLegacySettingsIfNeeded reads it from there so Pro state
	// survives the rename.
	legacySettingsFileName = "local.json"

	settingsInvalidFileName = "settings.invalid.json"

	// Development only keys
	ConfigFetchDisabledKey        _key = "config_fetch_disabled"     // bool
	FeatureOverridesKey           _key = "feature_overrides"         // string
	AdmissionRejectionDisabledKey _key = "admission_reject_disabled" // bool
	// SendLogsToSigNozKey enables uploading the redacted log to the telemetry
	// collector while telemetry runs. Unset means false.
	SendLogsToSigNozKey _key = "send_logs_to_signoz" // bool
)

var ErrNotExist = errors.New("key does not exist")

// errParseSettings marks a settings file that exists but isn't valid JSON. It
// distinguishes a recoverable invalid file (quarantine + start from defaults)
// from a genuine read failure, which stays fatal.
var errParseSettings = errors.New("settings file is not valid JSON")

func (k _key) String() string { return string(k) }

// settings holds the live state as an immutable snapshot: readers load k
// without locking, and writers build the next snapshot under mu and swap it
// in, so a load can never mutate a map a reader is traversing.
type settings struct {
	k           atomic.Pointer[koanf.Koanf]
	initialized bool
	filePath    string
	mu          sync.Mutex
	// pending holds writes that have not reached the file, reapplied on top
	// of it until one persists, so a later write cannot resurrect the state
	// they replaced. Guarded by mu.
	pending map[string]pendingWrite
}

// pendingWrite is one unpersisted write; deleted marks a tombstone.
type pendingWrite struct {
	value   any
	deleted bool
}

var k = &settings{}

func init() {
	k.k.Store(defaultSnapshot())
}

func defaultSnapshot() *koanf.Koanf {
	next := koanf.New(".")
	next.Set(UserLevelKey.String(), "free")
	return next
}

func snapshot() *koanf.Koanf { return k.k.Load() }

// clone deep-copies src through a marshal round-trip, giving values the same
// types they would have after being persisted and loaded.
func clone(src *koanf.Koanf) (*koanf.Koanf, error) {
	out, err := src.Marshal(json.Parser())
	if err != nil {
		return nil, fmt.Errorf("could not marshal settings: %w", err)
	}
	next := koanf.New(".")
	if err := next.Load(rawbytes.Provider(out), &settingsJSON{}); err != nil {
		return nil, fmt.Errorf("could not copy settings: %w", err)
	}
	return next, nil
}

// InitSettings initializes the config for user settings.
func InitSettings(fileDir string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.initialized {
		return nil
	}
	if err := os.MkdirAll(fileDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}
	k.filePath = filepath.Join(fileDir, settingsFileName)
	// Migration candidates reach outside fileDir — the pre-9.x YAML lives in
	// the user's real Lantern profile — so under test it would import the
	// developer's live account, pro token included, into the test's store.
	if !testing.Testing() && !env.GetBool(env.Testing) {
		migrateLegacySettingsIfNeeded(fileDir, k.filePath)
	}
	next, err := clone(snapshot())
	if err != nil {
		return err
	}
	switch err := loadInto(next, k.filePath); {
	case errors.Is(err, fs.ErrNotExist):
		slog.Warn("settings file not found", "path", k.filePath) // file may not have been created yet
		if err := save(next); err != nil {
			return err
		}
	case errors.Is(err, errParseSettings):
		// An invalid settings file must not be fatal: quarantine it, then start
		// from in-memory defaults and overwrite the bad file with them.
		slog.Error("Settings file is invalid; starting from defaults", "path", k.filePath, "error", err)
		quarantineInvalidSettings(k.filePath)
		if err := save(next); err != nil {
			return err
		}
	case err != nil:
		return fmt.Errorf("loading settings: %w", err)
	}
	k.k.Store(next)
	k.initialized = true
	return nil
}

// candidateSource is one possible location of persisted user state.
// contents is always canonical JSON — direct for v9.x, translated for
// pre-9.x YAML.
type candidateSource struct {
	path     string
	contents []byte
	exists   bool
	label    string
}

// migrateLegacySettingsIfNeeded preserves valid canonical settings and recovers
// missing or invalid settings from older client versions, preferring Pro accounts.
func migrateLegacySettingsIfNeeded(fileDir, canonicalPath string) {
	raw, err := os.ReadFile(canonicalPath)
	canonicalExists := err == nil
	switch {
	case err == nil:
		if validSettingsJSON(raw) {
			return
		}
	case !errors.Is(err, fs.ErrNotExist):
		slog.Warn("legacy settings migration: read failed", "path", canonicalPath, "error", err)
		return
	}
	candidates := []candidateSource{
		{path: filepath.Join(fileDir, legacySettingsFileName), label: "v9.0.x local.json"},
		{path: filepath.Join(fileDir, "data", settingsFileName), label: "v9.1.x data/settings.json"},
	}
	for i := range candidates {
		b, err := os.ReadFile(candidates[i].path)
		switch {
		case err == nil:
			if validSettingsJSON(b) {
				candidates[i].contents = b
				candidates[i].exists = true
			}
		case errors.Is(err, fs.ErrNotExist):
			// Expected — file just isn't there. Treat as not-present.
		default:
			slog.Warn("legacy settings migration: read failed",
				"path", candidates[i].path, "error", err)
		}
	}
	if yc := legacyYAMLCandidate(fileDir); yc.exists {
		candidates = append(candidates[:1], append([]candidateSource{yc}, candidates[1:]...)...)
	}
	// Windows v9.0.x cross-dir candidates (${PUBLIC}\Lantern\data) are the
	// same generation of state as the same-dir local.json, just stored
	// under a different filesystem root because lanternd's data dir moved
	// to ${ProgramData}\Lantern. On every other GOOS / when the
	// env is unset windowsCrossDirCandidatesFn returns nil and this is a
	// no-op.
	if winExtras := windowsCrossDirCandidatesFn(fileDir); len(winExtras) > 0 {
		candidates = append(candidates[:1], append(winExtras, candidates[1:]...)...)
	}

	// Pick: highest-priority file with user_level=="pro"; if none has pro,
	// highest-priority file that exists at all (with non-empty contents).
	pickIdx := -1
	for i, c := range candidates {
		if c.exists && userLevelInJSON(c.contents) == "pro" {
			pickIdx = i
			break
		}
	}
	if pickIdx == -1 {
		for i, c := range candidates {
			if c.exists && validSettingsJSON(c.contents) {
				pickIdx = i
				break
			}
		}
	}
	if pickIdx == -1 {
		// Nothing on disk yet — fresh install, normal path. No-op.
		return
	}
	if canonicalExists {
		quarantineInvalidSettings(canonicalPath)
	}
	writeMigrated(canonicalPath, candidates[pickIdx].contents, candidates[pickIdx].label)
}

func validSettingsJSON(contents []byte) bool {
	var values map[string]jsonpkg.RawMessage
	return jsonpkg.Unmarshal(contents, &values) == nil && values != nil
}

// writeMigrated overwrites the canonical settings file with the recovered
// contents and logs the outcome. Uses atomicfile.WriteFile (the same
// mechanism the normal save path uses) so a crash mid-write can't leave
// a half-written settings.json on disk. Errors are logged-and-swallowed:
// if the write fails the caller falls through to the fresh-install path,
// which is a worse UX but not a corruption risk.
func writeMigrated(canonicalPath string, contents []byte, source string) {
	if err := atomicfile.WriteFile(canonicalPath, contents, fileperm.File); err != nil {
		slog.Warn("legacy settings migration: write failed",
			"dst", canonicalPath, "source", source, "error", err)
		return
	}
	slog.Info("legacy settings migration: recovered persisted state",
		"dst", canonicalPath, "source", source, "bytes", len(contents))
}

// userLevelInJSON returns the value of the "user_level" key from a JSON
// settings blob, or "" if the key is missing / the blob is malformed.
// Lightweight extraction so the migration doesn't need to load the full
// koanf state machine before we've decided which file to read.
func userLevelInJSON(contents []byte) string {
	var s struct {
		UserLevel string `json:"user_level"`
	}
	if err := jsonpkg.Unmarshal(contents, &s); err != nil {
		return ""
	}
	return s.UserLevel
}

// loadInto merges the settings file at path into target. Koanf parses before
// merging, so a malformed file leaves target untouched.
func loadInto(target *koanf.Koanf, path string) error {
	contents, err := atomicfile.ReadFile(path)
	if err != nil {
		return fmt.Errorf("loading settings: %w", err)
	}
	if err := target.Load(rawbytes.Provider(contents), &settingsJSON{}); err != nil {
		return fmt.Errorf("parsing settings: %w", errors.Join(errParseSettings, err))
	}
	return nil
}

// quarantineInvalidSettings copies an invalid settings file aside to
// settings.invalid.json so a fresh default file can replace it in place while
// the original remains available for diagnostics.
func quarantineInvalidSettings(path string) {
	rawSettings, err := atomicfile.ReadFile(path)
	if err != nil {
		slog.Error("reading invalid settings for quarantine", "path", path, "error", err)
		return
	}
	invalidPath := filepath.Join(filepath.Dir(path), settingsInvalidFileName)
	if err := atomicfile.WriteFile(invalidPath, rawSettings, fileperm.File); err != nil {
		slog.Error("writing invalid settings copy", "path", invalidPath, "error", err)
		return
	}
	slog.Warn("quarantined invalid settings for diagnostics", "path", invalidPath)
}

func Get(key _key) any {
	return snapshot().Get(key.String())
}

// GetString returns the value of key, which must hold a scalar, as a string. A float64
// is truncated to an integer.
func GetString(key _key) string {
	value := Get(key)
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case float64:
		// Direct callers can still supply floating-point IDs.
		return strconv.FormatInt(int64(v), 10)
	case string:
		return v
	default:
		//logleak:ok GetString keys hold scalars
		return fmt.Sprintf("%v", v)
	}
}

func GetBool(key _key) bool {
	return snapshot().Bool(key.String())
}

// ProxylessEnabled reports the proxyless setting (ProxylessKey), which is on
// until the user turns it off.
func ProxylessEnabled() bool {
	return Get(ProxylessKey) == nil || GetBool(ProxylessKey)
}

// PeerServesPool reports the "help others too" setting (PeerServePoolKey):
// unset means on.
func PeerServesPool() bool {
	return Get(PeerServePoolKey) == nil || GetBool(PeerServePoolKey)
}

func GetInt(key _key) int {
	return snapshot().Int(key.String())
}

func GetInt64(key _key) int64 {
	return snapshot().Int64(key.String())
}

func GetFloat64(key _key) float64 {
	return snapshot().Float64(key.String())
}

func GetStringSlice(key _key) []string {
	return snapshot().Strings(key.String())
}

func GetDuration(key _key) time.Duration {
	return snapshot().Duration(key.String())
}

// GetStruct decodes the value at key into out by JSON field names, the form
// every value takes once it has passed through the settings file. A missing
// key is not an error and leaves out untouched.
func GetStruct(key _key, out any) error {
	raw := snapshot().Get(key.String())
	if raw == nil {
		return nil
	}
	// Not koanf's Unmarshal: it matches the koanf tag or the Go field name, so
	// a JSON name differing by more than case (user_level) is dropped.
	encoded, err := jsonpkg.Marshal(raw)
	if err != nil {
		return fmt.Errorf("could not encode value for %s: %w", key, err)
	}
	if err := jsonpkg.Unmarshal(encoded, out); err != nil {
		return fmt.Errorf("could not decode value for %s: %w", key, err)
	}
	return nil
}

func Exists(key _key) bool {
	return snapshot().Exists(key.String())
}

// mutate applies the writes returned by produce on top of the file's current
// contents, not this process's snapshot, so a write can't clobber keys another
// process changed; produce sees that same state and can decide against it. The
// next snapshot is published even when persisting fails, so the new value is
// visible in this process.
func mutate(produce func(next *koanf.Koanf) (map[string]pendingWrite, error)) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	unlock := lockSettingsFile(k.filePath)
	defer unlock()
	next, baseErr := writeBase()
	if baseErr != nil {
		// An unreadable file must not void the write locally — a logout's
		// tombstones in particular: decide and journal against the live
		// snapshot, and leave the file alone.
		var err error
		if next, err = clone(snapshot()); err != nil {
			return errors.Join(baseErr, err)
		}
		if err := applyWrites(next, k.pending); err != nil {
			return errors.Join(baseErr, err)
		}
	}
	updates, err := produce(next)
	if err != nil {
		return err
	}
	if err := applyWrites(next, updates); err != nil {
		return err
	}
	saveErr := baseErr
	if saveErr == nil {
		saveErr = save(next)
	}
	if saveErr != nil {
		if k.pending == nil {
			k.pending = make(map[string]pendingWrite)
		}
		for key, w := range updates {
			k.pending[key] = w
		}
	} else {
		k.pending = nil
	}
	k.k.Store(next)
	return saveErr
}

func writesProducer(updates map[string]pendingWrite) func(*koanf.Koanf) (map[string]pendingWrite, error) {
	return func(*koanf.Koanf) (map[string]pendingWrite, error) {
		return updates, nil
	}
}

func applyWrites(next *koanf.Koanf, updates map[string]pendingWrite) error {
	for key, w := range updates {
		if w.deleted {
			next.Delete(key)
			continue
		}
		if err := next.Set(key, w.value); err != nil {
			return fmt.Errorf("could not set key %s: %w", key, err)
		}
	}
	return nil
}

// writeBase returns the state a write starts from: the file's base state
// with this process's pending writes reapplied on top.
func writeBase() (*koanf.Koanf, error) {
	next, err := diskBase()
	if err != nil {
		return nil, err
	}
	if err := applyWrites(next, k.pending); err != nil {
		return nil, err
	}
	return next, nil
}

// diskBase returns the file's contents over the defaults. A missing or
// corrupt file falls back to the current snapshot, which turns a corrupt
// file back into valid state on the next write; any other read error is
// returned.
func diskBase() (*koanf.Koanf, error) {
	if k.filePath == "" {
		return clone(snapshot())
	}
	next := defaultSnapshot()
	switch err := loadInto(next, k.filePath); {
	case err == nil:
		return next, nil
	case errors.Is(err, fs.ErrNotExist):
		return clone(snapshot())
	case errors.Is(err, errParseSettings):
		slog.Warn("settings file invalid; overwriting with current settings", "path", k.filePath, "error", err)
		return clone(snapshot())
	default:
		return nil, err
	}
}

// lockSettingsFile takes the lock that serializes settings writers across
// processes, returning its release func. Failure to lock degrades to
// in-process serialization only, rather than failing the write.
func lockSettingsFile(path string) func() {
	if path == "" {
		return func() {}
	}
	fl := flock.New(path + ".lock")
	// A healthy holder keeps the lock for one read-modify-write; a holder
	// that waits longer is suspended (iOS freezes apps mid-write), and
	// startup paths write several keys against a ~7.5s iOS tunnel budget,
	// so waiting longer per write risks the whole process.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	locked, err := fl.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil || !locked {
		slog.Warn("settings file lock unavailable; writing without it", "path", path, "error", err)
		return func() {}
	}
	return func() {
		if err := fl.Unlock(); err != nil {
			slog.Warn("releasing settings file lock", "path", path, "error", err)
		}
	}
}

func Set(key _key, value any) error {
	return mutate(writesProducer(map[string]pendingWrite{key.String(): {value: value}}))
}

// SetIfAbsent persists value under key only when the key has no value yet,
// deciding against the file's state under the settings write lock.
func SetIfAbsent(key _key, value any) error {
	return mutate(func(next *koanf.Koanf) (map[string]pendingWrite, error) {
		if next.Exists(key.String()) {
			return nil, nil
		}
		return map[string]pendingWrite{key.String(): {value: value}}, nil
	})
}

// ReplaceString sets key to "to" only while its current value is "from",
// deciding against the file's state under the settings write lock.
func ReplaceString(key _key, from, to string) error {
	return mutate(func(next *koanf.Koanf) (map[string]pendingWrite, error) {
		if next.String(key.String()) != from {
			return nil, nil
		}
		return map[string]pendingWrite{key.String(): {value: to}}, nil
	})
}

func Clear(keys ..._key) error {
	updates := make(map[string]pendingWrite, len(keys))
	for _, key := range keys {
		updates[key.String()] = pendingWrite{deleted: true}
	}
	return mutate(writesProducer(updates))
}

type Settings map[_key]any

// LogValue renders s as a group with one attribute per setting, sorted by key, so a
// logger's per-key redaction applies to each setting.
func (s Settings) LogValue() slog.Value {
	attrs := make([]slog.Attr, 0, len(s))
	for _, key := range slices.Sorted(maps.Keys(s)) {
		attrs = append(attrs, slog.Any(string(key), s[key]))
	}
	return slog.GroupValue(attrs...)
}

func (s Settings) Diff(s2 Settings) Settings {
	diff := make(Settings)
	for k, v1 := range s {
		if v2, ok := s2[k]; !ok || v1 != v2 {
			diff[k] = v1
		}
	}
	return diff
}

func GetAll() Settings {
	s := make(Settings)
	for key, value := range snapshot().All() {
		s[_key(key)] = value
	}
	return s
}

func GetAllFor(keys ..._key) Settings {
	if len(keys) == 0 {
		return GetAll()
	}
	cur := snapshot()
	s := make(Settings)
	for _, key := range keys {
		s[key] = cur.Get(key.String())
	}
	return s
}

// Patch takes a map of settings to update and applies them all at once.
func Patch(updates Settings) error {
	writes := make(map[string]pendingWrite, len(updates))
	for key, value := range updates {
		writes[key.String()] = pendingWrite{value: value}
	}
	return mutate(writesProducer(writes))
}

func save(next *koanf.Koanf) error {
	out, err := next.Marshal(json.Parser())
	if err != nil {
		return fmt.Errorf("could not marshal koanf file: %w", err)
	}

	err = atomicfile.WriteFile(k.filePath, out, fileperm.File)
	if err != nil {
		return fmt.Errorf("could not write koanf file: %w", err)
	}
	return nil
}

// Reset clears the current settings in memory primarily for testing purposes.
func Reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.k.Store(koanf.New("."))
	k.pending = nil
	k.initialized = false
}

// Reload re-reads the settings file, adopting values written by another process.
//
// Mobile keeps the tunnel in a separate process that persists to the same file, so long-lived
// callers must reload before using cross-process metadata. The file supersedes memory rather than
// merging over it, so keys removed by another process do not linger; this process's unpersisted
// writes are reapplied on top. A missing file is not an error, and failed reloads leave the
// current settings untouched.
func Reload() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.initialized {
		return errors.New("settings not initialized")
	}
	next := defaultSnapshot()
	switch err := loadInto(next, k.filePath); {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("reloading settings: %w", err)
	}
	if err := applyWrites(next, k.pending); err != nil {
		return err
	}
	k.k.Store(next)
	return nil
}

func IsPro() bool {
	return strings.ToLower(GetString(UserLevelKey)) == "pro"
}

// Device is a machine registered to a user account (e.g. an Android phone or a Windows desktop).
type Device struct {
	ID   string
	Name string
}

func Devices() ([]Device, error) {
	devices := []Device{}
	err := GetStruct(DevicesKey, &devices)
	return devices, err
}
