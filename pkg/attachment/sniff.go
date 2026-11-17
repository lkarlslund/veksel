package attachment

import (
	"bytes"
	"encoding/binary"
)

// kind is a file type recognized from content rather than from its name.
type kind uint8

const (
	kindUnknown kind = iota
	kindPE
	kindELF
	kindMachO
	kindOLE2
	kindZIP
	kindPDF
)

func (k kind) String() string {
	switch k {
	case kindPE:
		return "a Windows executable"
	case kindELF:
		return "an ELF executable"
	case kindMachO:
		return "a Mach-O executable"
	case kindOLE2:
		return "an OLE2 document"
	case kindZIP:
		return "a ZIP archive"
	case kindPDF:
		return "a PDF"
	default:
		return "unknown"
	}
}

func (k kind) executable() bool { return k == kindPE || k == kindELF || k == kindMachO }

var (
	magicELF  = []byte("\x7fELF")
	magicOLE2 = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}
	magicZIP  = []byte("PK\x03\x04")
	magicPDF  = []byte("%PDF-")
	// vbaStorage is the OLE2 directory entry name of a VBA project, stored
	// as UTF-16LE.
	vbaStorage = []byte("_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00")
)

// sniff recognizes the file type of data from its leading bytes.
func sniff(data []byte) kind {
	switch {
	case bytes.HasPrefix(data, magicELF):
		return kindELF
	case bytes.HasPrefix(data, magicOLE2):
		return kindOLE2
	case bytes.HasPrefix(data, magicZIP):
		return kindZIP
	case bytes.HasPrefix(data, magicPDF):
		return kindPDF
	case isPE(data):
		return kindPE
	case isMachO(data):
		return kindMachO
	default:
		return kindUnknown
	}
}

// isPE recognizes a DOS MZ header whose PE offset, when within the data,
// points at the PE signature; two bytes alone are too weak a signature.
func isPE(data []byte) bool {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	offset := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if offset < 0 || offset > len(data)-4 {
		return offset > 0 && offset < 1<<20
	}
	return bytes.Equal(data[offset:offset+4], []byte("PE\x00\x00"))
}

// isMachO recognizes thin Mach-O images in either byte order and 64-bit
// variants; fat binaries share their magic with Java class files, so the
// architecture count disambiguates them.
func isMachO(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	switch binary.BigEndian.Uint32(data) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	case 0xcafebabe:
		return binary.BigEndian.Uint32(data[4:]) < 20
	}
	return false
}

// hasVBAStorage reports whether an OLE2 file contains a VBA project, the
// storage legacy Office macros live in.
func hasVBAStorage(data []byte) bool { return bytes.Contains(data, vbaStorage) }

// expectedKind reports whether found is a plausible content type for a file
// with extension. Extensions without a firm content signature accept any.
func expectedKind(extension string, found kind) bool {
	switch extension {
	case "pdf":
		return found == kindPDF
	case "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "zip", "odt", "ods", "odp":
		return found == kindZIP
	case "doc", "xls", "ppt", "dot", "xlt", "pps":
		return found == kindOLE2 || found == kindZIP
	default:
		return true
	}
}
