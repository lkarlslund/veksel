package pgpkey

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// MaxAutocryptKeyBytes bounds the key an Autocrypt header carries. The
// Autocrypt specification asks senders to keep headers small; a minimal key
// is a few kilobytes, so a larger one is not advertised.
const MaxAutocryptKeyBytes = 10 << 10

// AutocryptHeader returns the complete, folded Autocrypt Level 1 header
// field (without a trailing line break) advertising the minimal binary key
// for address. prefer-encrypt is nopreference. It fails when the key is
// larger than MaxAutocryptKeyBytes.
func AutocryptHeader(address string, binary []byte) (string, error) {
	if len(binary) > MaxAutocryptKeyBytes {
		return "", fmt.Errorf("key is %d bytes, over the %d byte Autocrypt limit", len(binary), MaxAutocryptKeyBytes)
	}
	encoded := base64.StdEncoding.EncodeToString(binary)
	var out strings.Builder
	out.WriteString("Autocrypt: addr=" + strings.ToLower(strings.TrimSpace(address)) + "; prefer-encrypt=nopreference; keydata=")
	// Whitespace inside keydata is ignored by receivers; fold well below
	// the 78 character recommendation.
	for len(encoded) > 0 {
		n := min(72, len(encoded))
		out.WriteString("\r\n " + encoded[:n])
		encoded = encoded[n:]
	}
	return out.String(), nil
}
