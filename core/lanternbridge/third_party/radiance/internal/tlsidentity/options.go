// Package tlsidentity enforces certificate verification for standard TLS outbounds.
package tlsidentity

import (
	"reflect"

	"github.com/sagernet/sing-box/option"
)

// Options disables unauthenticated TLS bypasses without modifying the input.
func Options(options any) any {
	v := reflect.ValueOf(options)
	if !v.IsValid() {
		return options
	}
	isPointer := v.Kind() == reflect.Pointer
	if isPointer {
		if v.IsNil() {
			return options
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return options
	}
	copy := reflect.New(v.Type())
	copy.Elem().Set(v)
	wrapper, ok := copy.Interface().(option.OutboundTLSOptionsWrapper)
	if !ok {
		return options
	}
	tls := wrapper.TakeOutboundTLSOptions()
	if tls == nil || !tls.Insecure || len(tls.CertificatePublicKeySHA256) > 0 || (tls.Reality != nil && tls.Reality.Enabled) {
		return options
	}
	verifiedTLS := *tls
	verifiedTLS.Insecure = false
	wrapper.ReplaceOutboundTLSOptions(&verifiedTLS)
	if isPointer {
		return copy.Interface()
	}
	return copy.Elem().Interface()
}
