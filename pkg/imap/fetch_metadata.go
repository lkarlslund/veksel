package imap

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"sort"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
)

func envelope(item model.Item) string {
	message, err := mail.ReadMessage(bytes.NewReader(item.Data))
	if err != nil {
		return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"
	}
	header := message.Header
	from := envelopeAddresses(header.Get("From"))
	sender := envelopeAddresses(header.Get("Sender"))
	if sender == "NIL" {
		sender = from
	}
	replyTo := envelopeAddresses(header.Get("Reply-To"))
	if replyTo == "NIL" {
		replyTo = from
	}
	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		imapNString(header.Get("Date")), decodedNString(header.Get("Subject")), from, sender, replyTo,
		envelopeAddresses(header.Get("To")), envelopeAddresses(header.Get("Cc")), envelopeAddresses(header.Get("Bcc")),
		imapNString(header.Get("In-Reply-To")), imapNString(header.Get("Message-Id")))
}

func envelopeAddresses(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	addresses, err := mail.ParseAddressList(value)
	if err != nil || len(addresses) == 0 {
		return "NIL"
	}
	formatted := make([]string, 0, len(addresses))
	for _, address := range addresses {
		at := strings.LastIndexByte(address.Address, '@')
		if at <= 0 || at == len(address.Address)-1 {
			continue
		}
		name := model.DecodeHeaderValue(address.Name)
		formatted = append(formatted, fmt.Sprintf("(%s NIL %s %s)", imapNString(name),
			imapNString(address.Address[:at]), imapNString(address.Address[at+1:])))
	}
	if len(formatted) == 0 {
		return "NIL"
	}
	return "(" + strings.Join(formatted, " ") + ")"
}

func decodedNString(value string) string {
	return imapNString(model.DecodeHeaderValue(value))
}

func imapNString(value string) string {
	if value == "" {
		return "NIL"
	}
	quoted, err := quoteIMAPString(value)
	if err != nil {
		return "NIL"
	}
	return quoted
}

func bodyStructure(item model.Item, extended bool) string {
	entity, err := readMIMEEntity(bytes.NewReader(item.Data))
	if err != nil {
		return `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)`
	}
	return formatBodyEntity(entity, extended, 0)
}

// maxMIMEDepth bounds how deeply nested multipart and message/rfc822 entities
// are opened. Every level re-reads its whole body, so an unbounded depth makes
// one crafted message cost time quadratic in its size. Deeper entities are
// presented as opaque leaves.
const maxMIMEDepth = service.MaxMIMEDepth

func formatBodyEntity(entity mimeEntity, extended bool, depth int) string {
	mediaType, parameters, err := mime.ParseMediaType(entity.header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
		parameters = nil
	}
	typeParts := strings.SplitN(strings.ToUpper(mediaType), "/", 2)
	major, subtype := "TEXT", "PLAIN"
	if len(typeParts) == 2 {
		major, subtype = typeParts[0], typeParts[1]
	}
	if major == "MULTIPART" && depth < maxMIMEDepth {
		children, childErr := mimeChildren(entity, parameters["boundary"])
		if childErr == nil && len(children) > 0 {
			parts := make([]string, len(children))
			for index, child := range children {
				parts[index] = formatBodyEntity(child, extended, depth+1)
			}
			result := "(" + strings.Join(parts, " ") + " " + imapNString(subtype)
			if extended {
				result += " " + bodyParameters(parameters, "boundary") + " " + bodyDisposition(entity.header.Get("Content-Disposition")) + " " + bodyLanguage(entity.header.Get("Content-Language")) + " " + imapNString(entity.header.Get("Content-Location"))
			}
			return result + ")"
		}
	}

	encoding := strings.ToUpper(strings.TrimSpace(entity.header.Get("Content-Transfer-Encoding")))
	if encoding == "" {
		encoding = "7BIT"
	}
	result := fmt.Sprintf("(%s %s %s %s %s %s %d", imapNString(major), imapNString(subtype),
		bodyParameters(parameters), imapNString(entity.header.Get("Content-Id")),
		decodedNString(entity.header.Get("Content-Description")), imapNString(encoding), len(entity.body))
	if major == "TEXT" {
		result += fmt.Sprintf(" %d", bytes.Count(normalizeCRLF(entity.body), []byte("\r\n")))
	}
	if extended {
		result += " NIL " + bodyDisposition(entity.header.Get("Content-Disposition")) + " " + bodyLanguage(entity.header.Get("Content-Language")) + " " + imapNString(entity.header.Get("Content-Location"))
	}
	return result + ")"
}

func mimeChildren(entity mimeEntity, boundary string) ([]mimeEntity, error) {
	if boundary == "" {
		return nil, errInvalidBinaryFetch
	}
	reader := multipart.NewReader(bytes.NewReader(entity.body), boundary)
	var children []mimeEntity
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return children, nil
		}
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(part)
		if err != nil {
			return nil, err
		}
		children = append(children, mimeEntity{header: mail.Header(part.Header), body: body})
	}
}

func bodyParameters(parameters map[string]string, excluded ...string) string {
	exclude := make(map[string]bool, len(excluded))
	for _, key := range excluded {
		exclude[strings.ToLower(key)] = true
	}
	keys := make([]string, 0, len(parameters))
	for key := range parameters {
		if !exclude[strings.ToLower(key)] {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return "NIL"
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		parts = append(parts, imapNString(strings.ToUpper(key)), imapNString(parameters[key]))
	}
	return "(" + strings.Join(parts, " ") + ")"
}

func bodyDisposition(value string) string {
	if strings.TrimSpace(value) == "" {
		return "NIL"
	}
	disposition, parameters, err := mime.ParseMediaType(value)
	if err != nil {
		return "NIL"
	}
	return "(" + imapNString(strings.ToUpper(disposition)) + " " + bodyParameters(parameters) + ")"
}

func bodyLanguage(value string) string {
	values := strings.Split(value, ",")
	var languages []string
	for _, language := range values {
		if language = strings.TrimSpace(language); language != "" {
			languages = append(languages, imapNString(language))
		}
	}
	if len(languages) == 0 {
		return "NIL"
	}
	if len(languages) == 1 {
		return languages[0]
	}
	return "(" + strings.Join(languages, " ") + ")"
}
