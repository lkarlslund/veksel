package model

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// IndexFold reports the byte range [start, end) of the first case-insensitive
// match of substr in s, or -1, -1. Unlike an index into strings.ToLower(s),
// the range always refers to s itself: lowering can change a rune's byte
// length, and invalid UTF-8 would be widened to U+FFFD, so an index into the
// lowered copy may point past the end of s or into the middle of a rune.
func IndexFold(s, substr string) (start, end int) {
	if substr == "" {
		return -1, -1
	}
	lower, offsets := lowerWithOffsets(s)
	lowerSubstr, _ := lowerWithOffsets(substr)
	index := strings.Index(lower, lowerSubstr)
	if index < 0 {
		return -1, -1
	}
	return offsets[index], offsets[index+len(lowerSubstr)]
}

// lowerWithOffsets lowercases s rune by rune, keeping invalid UTF-8 bytes
// unchanged, and returns for every byte of the result the offset in s of the
// rune it came from, followed by len(s).
func lowerWithOffsets(s string) (string, []int) {
	var lower strings.Builder
	lower.Grow(len(s))
	offsets := make([]int, 0, len(s)+1)
	for index := 0; index < len(s); {
		r, size := utf8.DecodeRuneInString(s[index:])
		if r == utf8.RuneError && size == 1 {
			lower.WriteByte(s[index])
			offsets = append(offsets, index)
		} else {
			written, _ := lower.WriteRune(unicode.ToLower(r))
			for range written {
				offsets = append(offsets, index)
			}
		}
		index += size
	}
	return lower.String(), append(offsets, len(s))
}
