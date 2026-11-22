package servers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/getlantern/radiance/internal/tlsidentity"
	"github.com/sagernet/sing-box/option"
)

var errTLSIdentityRequired = errors.New("TLS authentication is required: remove insecure/allowInsecure for a publicly trusted certificate, or import JSON with a trusted certificate or certificate_public_key_sha256 pin")

// CheckTLSIdentity rejects TLS bypasses without a trusted certificate, public-key pin, or Reality.
func (s *Server) CheckTLSIdentity() error {
	var options any
	switch opts := s.Options.(type) {
	case option.Outbound:
		options = opts.Options
	case option.Endpoint:
		options = opts.Options
	}
	v := reflect.ValueOf(options)
	if !v.IsValid() || v.Kind() == reflect.Pointer && v.IsNil() {
		return nil
	}
	if v.Kind() == reflect.Struct {
		copy := reflect.New(v.Type())
		copy.Elem().Set(v)
		options = copy.Interface()
	}
	wrapper, ok := options.(option.OutboundTLSOptionsWrapper)
	if !ok {
		return nil
	}
	tls := wrapper.TakeOutboundTLSOptions()
	if tls == nil || !tls.Enabled || !tls.Insecure || len(tls.CertificatePublicKeySHA256) > 0 || (tls.Reality != nil && tls.Reality.Enabled) {
		return nil
	}
	if len(tls.Certificate) > 0 {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(strings.Join(tls.Certificate, "\n"))) {
			return errors.New("invalid TLS certificate: no PEM certificates found")
		}
		return nil
	}
	return errTLSIdentityRequired
}

func urlRequestsTLSBypass(u url.URL) (bool, error) {
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false, errors.New("invalid URL query parameters")
	}
	if u.Scheme == "vmess" {
		if data, err := base64.StdEncoding.DecodeString(u.Host); err == nil {
			var fields map[string]json.RawMessage
			if json.Unmarshal(data, &fields) == nil {
				for _, key := range []string{"insecure", "allowInsecure"} {
					if raw, ok := fields[key]; ok {
						var value string
						if json.Unmarshal(raw, &value) != nil {
							value = string(raw)
						}
						query.Add(key, value)
					}
				}
				if _, ok := fields["pinSHA256"]; ok {
					query.Set("pinSHA256", "")
				}
			}
		}
	}
	if query.Has("pinSHA256") {
		return false, errors.New("pinSHA256 URL imports are not supported; import JSON with a trusted certificate or certificate_public_key_sha256 public-key pin")
	}
	var insecure bool
	for _, key := range []string{"insecure", "allowInsecure"} {
		for _, value := range query[key] {
			enabled, err := strconv.ParseBool(value)
			if err != nil {
				return false, errors.New("invalid insecure/allowInsecure value: expected true or false")
			}
			insecure = insecure || enabled
		}
	}
	return insecure, nil
}

// WithTLSVerification returns a copy without TLS bypasses; public-key pins and Reality are preserved.
func (s *Server) WithTLSVerification() *Server {
	cp := s.Clone()
	switch opts := cp.Options.(type) {
	case option.Outbound:
		opts.Options = tlsidentity.Options(opts.Options)
		cp.Options = opts
	case option.Endpoint:
		opts.Options = tlsidentity.Options(opts.Options)
		cp.Options = opts
	}
	return cp
}
