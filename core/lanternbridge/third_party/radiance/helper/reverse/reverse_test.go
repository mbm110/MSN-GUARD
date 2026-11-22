package reverse

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShortIDs(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 32)
	now := time.Unix(1_800_000_000, 0)
	e := Epoch(now)
	ids := AcceptedShortIDs(k, now)
	require.Len(t, ids, 3)
	assert.Equal(t, ShortID(k, e-1), ids[0])
	assert.Equal(t, ShortID(k, e), ids[1])
	assert.Equal(t, ShortID(k, e+1), ids[2])
	assert.NotEqual(t, ShortID(k, e), ShortID(bytes.Repeat([]byte{2}, 32), e))
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte("lantern-helper-reverse-sid-v1"))
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(e))
	mac.Write(eb[:])
	var want [8]byte
	copy(want[:], mac.Sum(nil))
	assert.Equal(t, want, ShortID(k, e))
}

func TestEpoch(t *testing.T) {
	assert.Equal(t, int64(0), Epoch(time.Unix(86399, 0)))
	assert.Equal(t, int64(1), Epoch(time.Unix(86400, 0)))
	assert.Equal(t, int64(20833), Epoch(time.Unix(1_800_000_000, 0)))
}

func testRoute(now time.Time) Route {
	return Route{
		Addrs: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.7:40001"),
			netip.MustParseAddrPort("[2606:4700::1]:41000"),
		},
		PublicKey:      [32]byte{1},
		CertSPKISHA256: [32]byte{2},
		CoverDomain:    strings.Repeat("a", MaxDomainLen),
		IssuedAt:       now.Truncate(time.Second),
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	r := testRoute(now)
	blob, err := Seal(k, "p1", r)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(blob), MaxBlobLen)
	assert.Equal(t, byte(BlobVersion), blob[0])
	got, err := Open(k, "p1", blob, now)
	require.NoError(t, err)
	assert.Equal(t, r, got)
}

func TestSealOpenSingleIPv6(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	r := testRoute(now)
	r.Addrs = r.Addrs[1:]
	r.CoverDomain = "example.com"
	blob, err := Seal(k, "p1", r)
	require.NoError(t, err)
	got, err := Open(k, "p1", blob, now.Add(MaxBlobAge))
	require.NoError(t, err)
	assert.Equal(t, r, got)
}

func TestOpenRejects(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	blob, _ := Seal(k, "p1", testRoute(now))
	_, err := Open(k, "p2", blob, now)
	assert.ErrorIs(t, err, ErrBlob, "other pairing")
	_, err = Open(bytes.Repeat([]byte{4}, 32), "p1", blob, now)
	assert.ErrorIs(t, err, ErrBlob, "other key")
	bad := slices.Clone(blob)
	bad[0] = 2
	_, err = Open(k, "p1", bad, now)
	assert.ErrorIs(t, err, ErrBlob, "version")
	bad = slices.Clone(blob)
	bad[len(bad)-1] ^= 1
	_, err = Open(k, "p1", bad, now)
	assert.ErrorIs(t, err, ErrBlob, "tamper")
	_, err = Open(k, "p1", blob, now.Add(MaxBlobAge+time.Second))
	assert.ErrorIs(t, err, ErrStale)
	_, err = Open(k, "p1", blob, now.Add(-MaxBlobFuture-time.Second))
	assert.ErrorIs(t, err, ErrFuture)
	// An issue time centuries ahead saturates now.Sub at the minimum Duration.
	far, _ := Seal(k, "p1", testRoute(time.Unix(math.MaxInt64/2, 0)))
	_, err = Open(k, "p1", far, now)
	assert.ErrorIs(t, err, ErrFuture, "far future")
}

func TestOpenRejectsLength(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	for _, n := range []int{0, 1, headerLen + tagLen - 1, MaxBlobLen + 1} {
		blob := make([]byte, n)
		if n > 0 {
			blob[0] = BlobVersion
		}
		_, err := Open(k, "p1", blob, now)
		assert.ErrorIs(t, err, ErrBlob, "len %d", n)
	}
}

type ptBuilder struct{ b []byte }

func newPT(now time.Time, domain string) *ptBuilder {
	p := &ptBuilder{}
	p.b = binary.BigEndian.AppendUint64(p.b, uint64(now.Unix()))
	p.b = append(p.b, make([]byte, 64)...)
	p.b = append(p.b, byte(len(domain)))
	p.b = append(p.b, domain...)
	return p
}

func (p *ptBuilder) addrs(entries ...[]byte) []byte {
	p.b = append(p.b, byte(len(entries)))
	for _, e := range entries {
		p.b = append(p.b, e...)
	}
	return p.b
}

func entry(family byte, ip []byte, port uint16) []byte {
	e := append([]byte{family}, ip...)
	return binary.BigEndian.AppendUint16(e, port)
}

func TestOpenRejectsMalformedPlaintext(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	v4 := []byte{198, 51, 100, 7}
	v6 := netip.MustParseAddr("2606:4700::1").AsSlice()
	mapped := netip.MustParseAddr("::ffff:198.51.100.7").AsSlice()
	good := newPT(now, "example.com").addrs(entry(4, v4, 1), entry(6, v6, 2))

	blob, err := sealPlaintext(k, "p1", good)
	require.NoError(t, err)
	_, err = Open(k, "p1", blob, now)
	require.NoError(t, err, "control")

	cases := map[string][]byte{
		"trailing":       append(slices.Clone(good), 0),
		"truncated":      good[:len(good)-1],
		"dup family":     newPT(now, "example.com").addrs(entry(4, v4, 1), entry(4, v4, 2)),
		"port zero":      newPT(now, "example.com").addrs(entry(4, v4, 0)),
		"mapped v6":      newPT(now, "example.com").addrs(entry(6, mapped, 1)),
		"bad family":     newPT(now, "example.com").addrs(entry(5, v4, 1)),
		"no addrs":       newPT(now, "example.com").addrs(),
		"three addrs":    newPT(now, "example.com").addrs(entry(4, v4, 1), entry(6, v6, 2), entry(4, v4, 3)),
		"empty domain":   newPT(now, "").addrs(entry(4, v4, 1)),
		"long domain":    newPT(now, strings.Repeat("a", MaxDomainLen+1)).addrs(entry(4, v4, 1)),
		"short v6 entry": newPT(now, "example.com").addrs(entry(6, v4, 1)),
	}
	for name, pt := range cases {
		blob, err := sealPlaintext(k, "p1", pt)
		require.NoError(t, err, name)
		_, err = Open(k, "p1", blob, now)
		assert.ErrorIs(t, err, ErrBlob, name)
	}
}

func TestSealRejectsBadRoutes(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	r := testRoute(now)
	r.Addrs = append(r.Addrs, netip.MustParseAddrPort("203.0.113.9:1"))
	_, err := Seal(k, "p1", r)
	assert.Error(t, err, "two IPv4")
	r = testRoute(now)
	r.CoverDomain = strings.Repeat("a", MaxDomainLen+1)
	_, err = Seal(k, "p1", r)
	assert.Error(t, err)
	r = testRoute(now)
	r.Addrs = nil
	_, err = Seal(k, "p1", r)
	assert.Error(t, err)
	_, err = Seal(k[:31], "p1", testRoute(now))
	assert.Error(t, err)
}

func TestSealRejectsMore(t *testing.T) {
	k := bytes.Repeat([]byte{3}, 32)
	now := time.Unix(1_800_000_000, 0)
	mods := map[string]func(*Route){
		"two IPv6": func(r *Route) {
			r.Addrs = []netip.AddrPort{r.Addrs[1], netip.MustParseAddrPort("[2001:db8::1]:1")}
		},
		"port zero":    func(r *Route) { r.Addrs[0] = netip.MustParseAddrPort("198.51.100.7:0") },
		"mapped":       func(r *Route) { r.Addrs = []netip.AddrPort{netip.MustParseAddrPort("[::ffff:198.51.100.7]:1")} },
		"invalid addr": func(r *Route) { r.Addrs = []netip.AddrPort{{}} },
		"empty domain": func(r *Route) { r.CoverDomain = "" },
		"zero time":    func(r *Route) { r.IssuedAt = time.Time{} },
	}
	for name, mod := range mods {
		r := testRoute(now)
		mod(&r)
		_, err := Seal(k, "p1", r)
		assert.Error(t, err, name)
	}
}
