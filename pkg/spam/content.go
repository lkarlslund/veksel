package spam

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"golang.org/x/net/html"
)

const (
	maxContentBytes = 1 << 20
	maxContentParts = 64
	maxContentDepth = 8
	maxLinks        = 512
)

// content is the decoded, bounded text a message presents to a reader.
type content struct {
	text []string // decoded text/plain parts
	html []string // decoded text/html parts
	// htmlText and links are extracted from the HTML parts.
	htmlText []string
	links    []string
	// structure records MIME anomalies noticed while walking.
	structure mimeStructure
	// uris memoizes extractURIDomains, which several rules ask for.
	uris *uriDomains
}

// uriDomains is the longest URI domain list extracted from one content and
// the bound it was extracted under; shorter bounds take its prefix.
type uriDomains struct {
	max     int
	domains []string
}

// visibleText joins the plain text and the text of HTML parts.
func (c content) visibleText() string {
	return strings.Join(append(append([]string(nil), c.text...), c.htmlText...), "\n")
}

// parseContent decodes the text and HTML parts of raw, undoing
// quoted-printable and base64 transfer encodings. Parsing is bounded in
// bytes, parts, and nesting; an unparsable message is treated as text.
func parseContent(raw []byte) content {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		_, body := model.SplitHeaderBody(raw)
		return content{text: []string{string(limit(body))}, uris: &uriDomains{}}
	}
	walker := contentWalker{remaining: maxContentBytes}
	walker.walk(message.Body, message.Header.Get("Content-Type"), message.Header.Get("Content-Transfer-Encoding"), 0)
	for _, part := range walker.result.html {
		text, links := htmlTextAndLinks(part)
		walker.result.htmlText = append(walker.result.htmlText, text)
		walker.result.links = append(walker.result.links, links...)
	}
	walker.result.uris = &uriDomains{}
	return walker.result
}

func limit(data []byte) []byte {
	if len(data) > maxContentBytes {
		return data[:maxContentBytes]
	}
	return data
}

type contentWalker struct {
	result    content
	remaining int
	parts     int
}

func (w *contentWalker) walk(reader io.Reader, contentType, transferEncoding string, depth int) {
	if depth > maxContentDepth || w.parts >= maxContentParts || w.remaining <= 0 {
		return
	}
	w.parts++
	w.result.structure.noteEncoding(transferEncoding)
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		w.result.structure.nesting = max(w.result.structure.nesting, depth+1)
		if params["boundary"] == "" {
			w.result.structure.noBoundary = true
			return
		}
		parts := multipart.NewReader(reader, params["boundary"])
		for {
			part, err := parts.NextRawPart()
			if err != nil {
				w.result.structure.unterminated = w.result.structure.unterminated || err != io.EOF
				return
			}
			w.walk(part, part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"), depth+1)
			_ = part.Close()
		}
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		return
	}
	data, _ := io.ReadAll(io.LimitReader(model.TransferDecoder(reader, transferEncoding), int64(w.remaining)))
	w.remaining -= len(data)
	w.result.structure.noteText(mediaType, params["charset"], transferEncoding, data)
	if mediaType == "text/html" {
		w.result.html = append(w.result.html, string(data))
	} else {
		w.result.text = append(w.result.text, string(data))
	}
}

// linkAttributes are the HTML attributes whose values are followed or
// loaded by a mail client.
var linkAttributes = map[string]bool{"href": true, "src": true, "action": true, "background": true}

// htmlTextAndLinks returns the visible text of an HTML document and the
// values of its link attributes, with character references decoded.
func htmlTextAndLinks(document string) (string, []string) {
	tokenizer := html.NewTokenizer(strings.NewReader(document))
	var text strings.Builder
	var links []string
	skip := 0
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return text.String(), links
		case html.TextToken:
			if skip == 0 {
				text.Write(tokenizer.Text())
				text.WriteByte(' ')
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttributes := tokenizer.TagName()
			if string(name) == "script" || string(name) == "style" {
				skip++
			}
			for hasAttributes {
				var key, value []byte
				key, value, hasAttributes = tokenizer.TagAttr()
				if linkAttributes[strings.ToLower(string(key))] && len(links) < maxLinks {
					links = append(links, string(value))
				}
			}
		case html.EndTagToken:
			if name, _ := tokenizer.TagName(); (string(name) == "script" || string(name) == "style") && skip > 0 {
				skip--
			}
		}
	}
}
