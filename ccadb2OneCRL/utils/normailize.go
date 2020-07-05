package utils

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/pkg/errors"
)

func Normalize(rdn *pkix.RDNSequence) {
	for _, set := range *rdn {
		sort.Slice(set, func(i, j int) bool {
			if len(set[i].Type) < len(set[j].Type) {
				return true
			}
			for index, value := range set[i].Type {
				if value < set[j].Type[index] {
					return true
				}
			}
			return false
		})
	}
}

// B64Decode attempts to decode the give string first as an
// RFC 4648 encoded string (with padding). If that fails, then
// RFC 4648 section 3.2 (without padding) is attempted. If
// RFC 4648 section 3.2 fails as well, then the original
// error message (with padding) is returned.
//
// All provided strings are first trimmed of whitespace
// before attempting decoding.
func B64Decode(b64 string) ([]byte, error) {
	// Some OneCRL entries have a trailing space.
	b64trimmed := strings.TrimSpace(b64)
	decoded, err := base64.StdEncoding.DecodeString(b64trimmed)
	if err == nil {
		return decoded, nil
	}
	// There are a handful entries that you will sometime find that
	// are raw encoded (with no padding). So give that a shot
	// as a fallback.
	decoded, err2 := base64.RawStdEncoding.DecodeString(b64trimmed)
	if err2 == nil {
		return decoded, nil
	}
	return nil, errors.Wrap(err, fmt.Sprintf("b64 decode error for '%s'", b64))
}

func B64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}
