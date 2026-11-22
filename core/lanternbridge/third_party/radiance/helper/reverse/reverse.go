// Package reverse derives per-pairing short IDs and seals the inviter's route
// for its paired helper under K_pair, so the relay that carries the route
// learns none of its contents.
package reverse

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// BlobVersion is the blob format this package seals and opens; a peer on
	// another version rejects every blob with ErrBlob.
	BlobVersion = 1
	// MaxBlobLen keeps a register request carrying one blob per pairing inside
	// lantern-cloud's request body limit.
	MaxBlobLen = 256
	// MaxDomainLen is the longest cover domain a route can carry.
	MaxDomainLen = 63
	// MaxBlobAge is the oldest a blob can be and still open; older blobs fail
	// with ErrStale.
	MaxBlobAge = 10 * time.Minute
	// MaxBlobFuture is how far ahead of now a blob's issue time can be and
	// still open; further ahead fails with ErrFuture.
	MaxBlobFuture = 2 * time.Minute
	// EpochLength is the lifetime of a short ID; peers using different values
	// derive different short IDs.
	EpochLength = 24 * time.Hour
)

var (
	// ErrBlob means the blob is malformed, was sealed under another key or
	// pairing, or was tampered with. Retrying the same blob cannot succeed.
	ErrBlob = errors.New("reverse: bad blob")
	// ErrStale means the blob authenticated but was issued more than MaxBlobAge
	// ago; only a freshly sealed blob can succeed.
	ErrStale = errors.New("reverse: blob too old")
	// ErrFuture means the blob authenticated but was issued more than
	// MaxBlobFuture ahead of now, which points to clock skew between the apps.
	ErrFuture = errors.New("reverse: blob from the future")
)

const (
	sidLabel  = "lantern-helper-reverse-sid-v1"
	adLabel   = "lantern-helper-reverse-v1"
	headerLen = 1 + chacha20poly1305.NonceSizeX
	tagLen    = chacha20poly1305.Overhead
	maxAddrs  = 2
)

// Route is where a paired helper reaches the inviter's portal.
type Route struct {
	Addrs          []netip.AddrPort // at most one IPv4 and one IPv6
	PublicKey      [32]byte
	CertSPKISHA256 [32]byte
	CoverDomain    string
	// IssuedAt is sealed in whole Unix seconds, and Open returns it in the
	// local time zone.
	IssuedAt time.Time
}

// Epoch returns the short-ID epoch containing t.
func Epoch(t time.Time) int64 {
	return t.Unix() / int64(EpochLength/time.Second)
}

// ShortID returns the pairing's short ID for epoch.
func ShortID(kPair []byte, epoch int64) [8]byte {
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(sidLabel))
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(epoch))
	mac.Write(eb[:])
	var sid [8]byte
	copy(sid[:], mac.Sum(nil))
	return sid
}

// AcceptedShortIDs returns the short IDs for the epochs before, containing and
// after now, in that order, so peers with skewed clocks still agree.
func AcceptedShortIDs(kPair []byte, now time.Time) [][8]byte {
	e := Epoch(now)
	return [][8]byte{ShortID(kPair, e-1), ShortID(kPair, e), ShortID(kPair, e+1)}
}

// Seal encrypts r for the helper paired under kPair and pairingID.
func Seal(kPair []byte, pairingID string, r Route) ([]byte, error) {
	if err := validateRoute(r); err != nil {
		return nil, err
	}
	pt := binary.BigEndian.AppendUint64(nil, uint64(r.IssuedAt.Unix()))
	pt = append(pt, r.PublicKey[:]...)
	pt = append(pt, r.CertSPKISHA256[:]...)
	pt = append(pt, byte(len(r.CoverDomain)))
	pt = append(pt, r.CoverDomain...)
	pt = append(pt, byte(len(r.Addrs)))
	for _, ap := range r.Addrs {
		if ap.Addr().Is4() {
			pt = append(pt, 4)
		} else {
			pt = append(pt, 6)
		}
		pt = append(pt, ap.Addr().AsSlice()...)
		pt = binary.BigEndian.AppendUint16(pt, ap.Port())
	}
	return sealPlaintext(kPair, pairingID, pt)
}

func validateRoute(r Route) error {
	if len(r.Addrs) == 0 || len(r.Addrs) > maxAddrs {
		return fmt.Errorf("reverse: route needs 1 to %d addresses, has %d", maxAddrs, len(r.Addrs))
	}
	var seen4, seen6 bool
	for _, ap := range r.Addrs {
		a := ap.Addr()
		switch {
		case !ap.IsValid() || ap.Port() == 0:
			return errors.New("reverse: route address needs an IP and a nonzero port")
		case a.Is4In6() || a.Zone() != "":
			return errors.New("reverse: route IPv6 address must be unmapped and unzoned")
		case a.Is4() && seen4, a.Is6() && seen6:
			return errors.New("reverse: route has two addresses of one family")
		}
		seen4 = seen4 || a.Is4()
		seen6 = seen6 || a.Is6()
	}
	if len(r.CoverDomain) == 0 || len(r.CoverDomain) > MaxDomainLen {
		return fmt.Errorf("reverse: cover domain must be 1 to %d bytes", MaxDomainLen)
	}
	if r.IssuedAt.Unix() <= 0 {
		return errors.New("reverse: route needs an issue time")
	}
	return nil
}

func sealPlaintext(kPair []byte, pairingID string, pt []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kPair)
	if err != nil {
		return nil, fmt.Errorf("reverse: %w", err)
	}
	blob := make([]byte, headerLen, headerLen+len(pt)+tagLen)
	blob[0] = BlobVersion
	if _, err := rand.Read(blob[1:headerLen]); err != nil {
		return nil, fmt.Errorf("reverse: nonce: %w", err)
	}
	blob = aead.Seal(blob, blob[1:headerLen], pt, additionalData(pairingID))
	if len(blob) > MaxBlobLen {
		return nil, fmt.Errorf("reverse: sealed route is %d bytes, over %d", len(blob), MaxBlobLen)
	}
	return blob, nil
}

func additionalData(pairingID string) []byte {
	ad := make([]byte, 0, len(adLabel)+len(pairingID)+1)
	ad = append(ad, adLabel...)
	ad = append(ad, pairingID...)
	return append(ad, BlobVersion)
}

// Open decrypts and validates a blob sealed by Seal for the same kPair and
// pairingID. It returns an error wrapping ErrBlob, ErrStale or ErrFuture when
// the blob is rejected, and an error wrapping none of them when kPair is not
// 32 bytes.
func Open(kPair []byte, pairingID string, blob []byte, now time.Time) (Route, error) {
	aead, err := chacha20poly1305.NewX(kPair)
	if err != nil {
		return Route{}, fmt.Errorf("reverse: %w", err)
	}
	if len(blob) < headerLen+tagLen || len(blob) > MaxBlobLen {
		return Route{}, fmt.Errorf("%w: length %d", ErrBlob, len(blob))
	}
	if blob[0] != BlobVersion {
		return Route{}, fmt.Errorf("%w: version %d", ErrBlob, blob[0])
	}
	pt, err := aead.Open(nil, blob[1:headerLen], blob[headerLen:], additionalData(pairingID))
	if err != nil {
		return Route{}, fmt.Errorf("%w: authentication failed", ErrBlob)
	}
	r, err := decodeRoute(pt)
	if err != nil {
		return Route{}, fmt.Errorf("%w: %w", ErrBlob, err)
	}
	// Compare times rather than negate now.Sub: Sub saturates for an issue
	// time centuries ahead, and negating the minimum Duration stays negative.
	if r.IssuedAt.After(now.Add(MaxBlobFuture)) {
		return Route{}, fmt.Errorf("%w: issued %s ahead", ErrFuture, r.IssuedAt.Sub(now))
	} else if age := now.Sub(r.IssuedAt); age > MaxBlobAge {
		return Route{}, fmt.Errorf("%w: issued %s ago", ErrStale, age)
	}
	return r, nil
}

type reader struct{ b []byte }

func (rd *reader) take(n int) ([]byte, error) {
	if len(rd.b) < n {
		return nil, errors.New("truncated")
	}
	v := rd.b[:n]
	rd.b = rd.b[n:]
	return v, nil
}

func decodeRoute(pt []byte) (Route, error) {
	rd := &reader{b: pt}
	var r Route
	fixed, err := rd.take(8 + 32 + 32 + 1)
	if err != nil {
		return Route{}, err
	}
	issued := int64(binary.BigEndian.Uint64(fixed[:8]))
	if issued <= 0 {
		return Route{}, errors.New("issue time out of range")
	}
	r.IssuedAt = time.Unix(issued, 0)
	copy(r.PublicKey[:], fixed[8:40])
	copy(r.CertSPKISHA256[:], fixed[40:72])
	n := int(fixed[72])
	if n == 0 || n > MaxDomainLen {
		return Route{}, fmt.Errorf("cover domain length %d", n)
	}
	domain, err := rd.take(n)
	if err != nil {
		return Route{}, err
	}
	r.CoverDomain = string(domain)
	cb, err := rd.take(1)
	if err != nil {
		return Route{}, err
	}
	count := int(cb[0])
	if count == 0 || count > maxAddrs {
		return Route{}, fmt.Errorf("address count %d", count)
	}
	var seen [2]bool
	for range count {
		fb, err := rd.take(1)
		if err != nil {
			return Route{}, err
		}
		var ipLen, slot int
		switch fb[0] {
		case 4:
			ipLen, slot = 4, 0
		case 6:
			ipLen, slot = 16, 1
		default:
			return Route{}, fmt.Errorf("address family %d", fb[0])
		}
		if seen[slot] {
			return Route{}, errors.New("two addresses of one family")
		}
		seen[slot] = true
		ab, err := rd.take(ipLen + 2)
		if err != nil {
			return Route{}, err
		}
		addr, _ := netip.AddrFromSlice(ab[:ipLen])
		if addr.Is4In6() {
			return Route{}, errors.New("IPv4-mapped address in an IPv6 entry")
		}
		port := binary.BigEndian.Uint16(ab[ipLen:])
		if port == 0 {
			return Route{}, errors.New("port 0")
		}
		r.Addrs = append(r.Addrs, netip.AddrPortFrom(addr, port))
	}
	if len(rd.b) != 0 {
		return Route{}, fmt.Errorf("%d trailing bytes", len(rd.b))
	}
	return r, nil
}
