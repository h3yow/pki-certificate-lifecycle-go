package pki

import (
	"unicode/utf8"
)

// maxIdentityLen bounds identity length.
const maxIdentityLen = 63

// validIdentity enforces a deterministic identity grammar without relying on
// regexp: one or more DNS-label-like segments separated by dots. Each
// segment is 1-63 characters from [a-z0-9-], beginning and ending with a
// letter or digit. Empty, upper-case and otherwise illegal identities are
// rejected rather than normalized or defaulted.
func validIdentity(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	segStart := true
	segLen := 0
	last := byte(0)
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '.':
			if segStart || segLen == 0 || isHyphen(last) {
				return false
			}
			segStart = true
			segLen = 0
		case isLowerAlnum(c):
			if segLen >= maxIdentityLen {
				return false
			}
			segLen++
			segStart = false
		case c == '-':
			if segStart {
				return false
			}
			if segLen >= maxIdentityLen {
				return false
			}
			segLen++
		default:
			return false
		}
		last = c
	}
	// Trailing dot, empty name or hyphen-ended segment are illegal.
	if segStart || segLen == 0 || isHyphen(last) {
		return false
	}
	return true
}

func isLowerAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func isHyphen(c byte) bool { return c == '-' }
