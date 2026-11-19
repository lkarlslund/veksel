package attachment

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"path"
	"strings"
	"unicode"

	"github.com/lkarlslund/veksel/pkg/model"
	"golang.org/x/net/html"
)

// Inspection bounds. They cap the work one message can cause regardless of
// how it is built.
const (
	maxParts             = 64
	maxDepth             = 8
	maxFindings          = 32
	maxTotalBytes        = 32 << 20  // decoded bytes across the message
	maxAttachmentBytes   = 8 << 20   // decoded bytes read per attachment
	maxEntryBytes        = 256 << 10 // decompressed bytes read per archive entry
	maxArchiveEntries    = 64        // archive entries inspected
	maxArchiveClaimed    = 1 << 30   // declared uncompressed bytes before an archive counts as a bomb
	maxCompressionRatio  = 1000      // declared ratio before a large entry counts as a bomb
	minBombEntryBytes    = 1 << 20
	maxHTMLBytes         = 256 << 10
	maxDetailBytes       = 120
	archiveInspectionMax = 1 // levels of archive nesting that are opened
)

// Analyze inspects the MIME parts of content, including nested
// message/rfc822 parts and ZIP archives one level deep.
func (p *Policy) Analyze(content []byte) Report {
	message, err := mail.ReadMessage(bytes.NewReader(content))
	if err != nil {
		return Report{}
	}
	w := &walker{policy: p, budget: maxTotalBytes, seen: make(map[Finding]struct{})}
	w.entity(textproto.MIMEHeader(message.Header), message.Body, 0)
	return w.report
}

type walker struct {
	policy *Policy
	report Report
	seen   map[Finding]struct{}
	parts  int
	budget int
}

func (w *walker) add(symbol, detail string, hard bool) {
	finding := Finding{Symbol: symbol, Detail: boundedDetail(detail), Hard: hard}
	if _, duplicate := w.seen[finding]; duplicate || len(w.report.Findings) >= maxFindings {
		return
	}
	w.seen[finding] = struct{}{}
	w.report.Findings = append(w.report.Findings, finding)
}

// read returns up to limit decoded bytes from reader, charged to the budget.
func (w *walker) read(reader io.Reader, limit int) []byte {
	limit = min(limit, w.budget)
	if limit <= 0 {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(reader, int64(limit)))
	w.budget -= len(data)
	return data
}

func (w *walker) entity(header textproto.MIMEHeader, body io.Reader, depth int) {
	if depth > maxDepth || w.parts >= maxParts || w.budget <= 0 {
		return
	}
	w.parts++
	mediaType, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		if params["boundary"] == "" {
			return
		}
		parts := multipart.NewReader(body, params["boundary"])
		for {
			part, err := parts.NextRawPart()
			if err != nil {
				return
			}
			w.entity(part.Header, part, depth+1)
			_ = part.Close()
		}
	case mediaType == "message/rfc822" || mediaType == "message/global":
		data := w.read(model.TransferDecoder(body, header.Get("Content-Transfer-Encoding")), maxAttachmentBytes)
		if nested, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
			w.entity(textproto.MIMEHeader(nested.Header), nested.Body, depth+1)
		}
	default:
		w.leaf(header, mediaType, body)
	}
}

// leaf inspects one non-container part when it presents as an attachment: a
// named part or an attachment disposition. Unnamed inline text is body.
func (w *walker) leaf(header textproto.MIMEHeader, mediaType string, body io.Reader) {
	disposition, dispositionParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	_, typeParams, _ := mime.ParseMediaType(header.Get("Content-Type"))
	name := dispositionParams["filename"]
	if name == "" {
		name = typeParams["name"]
	}
	if name == "" && disposition != "attachment" {
		return
	}
	name = model.DecodeHeaderValue(name)
	data := w.read(model.TransferDecoder(body, header.Get("Content-Transfer-Encoding")), maxAttachmentBytes)
	w.file(name, name, mediaType, data, 0)
}

// file inspects one file by name and content. label identifies it in
// findings; archiveDepth counts archives already opened above it.
func (w *walker) file(label, name, mediaType string, data []byte, archiveDepth int) {
	display := displayName(label)
	if spoofsName(name) {
		w.add(SymbolRTLO, display, false)
	}
	extensions := extensionsOf(name)
	last := ""
	if len(extensions) > 0 {
		last = extensions[len(extensions)-1]
	}
	_, blocked := w.policy.blocked[last]
	if blocked {
		w.add(SymbolDangerousExt, display, true)
		if len(extensions) > 1 && decoyExtensions[extensions[len(extensions)-2]] {
			w.add(SymbolDoubleExt, display, true)
		}
	}
	found := sniff(data)
	switch {
	case found.executable() && !blocked:
		w.add(SymbolTypeMismatch, display+" is "+found.String(), true)
	case !blocked && found != kindUnknown && !expectedKind(last, found):
		w.add(SymbolTypeMismatch, display+" is "+found.String(), false)
	}
	if macroExtensions[last] || (found == kindOLE2 && hasVBAStorage(data)) {
		w.add(SymbolMacro, display, false)
	}
	if found == kindZIP && archiveDepth < archiveInspectionMax {
		w.archive(label, data, blocked, archiveDepth)
	}
	if htmlExtensions[last] || (mediaType == "text/html" && last == "") {
		w.html(display, data)
	}
}

// archive lists a ZIP archive without expanding it: entry names, encryption
// and macro markers, and a bounded prefix of each entry for sniffing.
func (w *walker) archive(label string, data []byte, blocked bool, archiveDepth int) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	display := displayName(label)
	var claimed uint64
	container, encrypted := false, false
	entries := make([]*zip.File, 0, min(len(reader.File), maxArchiveEntries))
	for index, entry := range reader.File {
		if index >= maxArchiveEntries {
			break
		}
		claimed += entry.UncompressedSize64
		bomb := claimed > maxArchiveClaimed ||
			(entry.UncompressedSize64 > minBombEntryBytes && entry.CompressedSize64 > 0 && entry.UncompressedSize64/entry.CompressedSize64 > maxCompressionRatio)
		if bomb {
			w.add(SymbolArchiveBomb, display, false)
			return
		}
		lower := strings.ToLower(strings.ReplaceAll(entry.Name, `\`, "/"))
		switch {
		case strings.HasSuffix(lower, "vbaproject.bin"):
			w.add(SymbolMacro, display, false)
		case lower == "[content_types].xml" || lower == "meta-inf/manifest.mf" || lower == "mimetype":
			container = true
		}
		encrypted = encrypted || entry.Flags&1 != 0
		entries = append(entries, entry)
	}
	if encrypted {
		w.add(SymbolEncryptedArchive, display, false)
	}
	// Office, Java, and packaged-app archives legitimately hold scripts and
	// executables; only plain archives are listed.
	if container || blocked {
		return
	}
	for _, entry := range entries {
		if entry.FileInfo().IsDir() {
			continue
		}
		entryName := path.Base(strings.ReplaceAll(entry.Name, `\`, "/"))
		var prefix []byte
		if entry.Flags&1 == 0 {
			if opened, err := entry.Open(); err == nil {
				prefix = w.read(opened, maxEntryBytes)
				_ = opened.Close()
			}
		}
		w.file(label+":"+entryName, entryName, "", prefix, archiveDepth+1)
	}
}

// html flags HTML attachments carrying forms, password fields, or script,
// the shape of credential-phishing pages.
func (w *walker) html(display string, data []byte) {
	tokenizer := html.NewTokenizer(bytes.NewReader(data[:min(len(data), maxHTMLBytes)]))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttributes := tokenizer.TagName()
			switch string(name) {
			case "form":
				w.add(SymbolHTMLForm, display+" has a form", false)
			case "script":
				w.add(SymbolHTMLForm, display+" has script", false)
			case "input":
				for hasAttributes {
					var key, value []byte
					key, value, hasAttributes = tokenizer.TagAttr()
					if string(key) == "type" && strings.EqualFold(string(value), "password") {
						w.add(SymbolHTMLForm, display+" has a password field", false)
					}
				}
			}
		}
	}
}

// decoyExtensions are the document-like extensions a double extension uses
// to hide an executable one.
var decoyExtensions = map[string]bool{
	"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true, "txt": true,
	"rtf": true, "csv": true, "jpg": true, "jpeg": true, "png": true, "gif": true, "bmp": true, "zip": true,
	"htm": true, "html": true, "odt": true, "mp3": true, "mp4": true,
}

// macroExtensions are the macro-enabled Office formats.
var macroExtensions = map[string]bool{
	"docm": true, "dotm": true, "xlsm": true, "xltm": true, "xlam": true, "pptm": true, "potm": true, "ppam": true, "ppsm": true, "sldm": true,
}

var htmlExtensions = map[string]bool{"htm": true, "html": true, "xhtml": true, "shtml": true, "mht": true, "mhtml": true}

// extensionsOf returns the dot-separated suffixes of a file name, so
// "invoice.pdf.exe" yields pdf and exe. Control and bidirectional
// characters, and trailing spaces and dots that Windows ignores, are
// dropped first.
func extensionsOf(name string) []string {
	clean := strings.Map(func(character rune) rune {
		if spoofing(character) {
			return -1
		}
		return unicode.ToLower(character)
	}, name)
	segments := strings.Split(path.Base(strings.ReplaceAll(clean, `\`, "/")), ".")
	var extensions []string
	for _, segment := range segments[1:] {
		if segment = strings.TrimSpace(segment); segment != "" {
			extensions = append(extensions, segment)
		}
	}
	return extensions
}

// spoofing reports characters that reorder or hide parts of a displayed
// file name.
func spoofing(character rune) bool {
	switch {
	case character >= 0x202a && character <= 0x202e, character >= 0x2066 && character <= 0x2069:
		return true // bidirectional embedding, override, and isolate controls
	case character == 0x200b, character == 0x200c, character == 0x200d, character == 0x2060, character == 0xfeff:
		return true // zero-width characters
	}
	return unicode.IsControl(character)
}

func spoofsName(name string) bool { return strings.IndexFunc(name, spoofing) >= 0 }

// displayName makes a file name safe to show: spoofing characters appear as
// <U+XXXX> instead of acting on the surrounding text.
func displayName(name string) string {
	var builder strings.Builder
	for _, character := range name {
		if spoofing(character) {
			fmt.Fprintf(&builder, "<U+%04X>", character)
			continue
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

func boundedDetail(value string) string {
	value = strings.ToValidUTF8(value, "?")
	if len(value) <= maxDetailBytes {
		return value
	}
	end := maxDetailBytes
	for end > 0 && !isRuneStart(value[end]) {
		end--
	}
	return value[:end]
}

func isRuneStart(b byte) bool { return b&0xc0 != 0x80 }
