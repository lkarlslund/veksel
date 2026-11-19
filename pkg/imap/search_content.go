package imap

import (
	"bytes"
	"mime"
	"net/mail"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func canonicalSearchText(value string) string {
	return norm.NFC.String(strings.ToLower(value))
}

func decodedMessageHeaders(data []byte) mail.Header {
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	return message.Header
}

func decodedHeaderValue(value string) string {
	return model.DecodeHeaderValue(value)
}

func searchableHeaders(data []byte) string {
	header := decodedMessageHeaders(data)
	if header == nil {
		return string(extractHeaders(data))
	}
	var output strings.Builder
	for name, values := range header {
		output.WriteString(name)
		output.WriteByte(':')
		for _, value := range values {
			output.WriteByte(' ')
			output.WriteString(decodedHeaderValue(value))
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func searchableBody(data []byte) string {
	root, err := readMIMEEntity(bytes.NewReader(data))
	if err != nil {
		return string(extractBody(data))
	}
	var output strings.Builder
	var appendEntity func(mimeEntity, int)
	appendEntity = func(entity mimeEntity, depth int) {
		if depth > maxMIMEDepth {
			output.Write(entity.body)
			output.WriteByte('\n')
			return
		}
		mediaType, parameters, parseErr := mime.ParseMediaType(entity.header.Get("Content-Type"))
		if parseErr != nil || mediaType == "" {
			mediaType = "text/plain"
		}
		if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
			children, childErr := mimeChildren(entity, parameters["boundary"])
			if childErr != nil {
				output.Write(entity.body)
				return
			}
			for _, child := range children {
				appendEntity(child, depth+1)
			}
			return
		}
		decoded, decodeErr := decodeTransferEncoding(entity.body, entity.header.Get("Content-Transfer-Encoding"))
		if decodeErr != nil {
			decoded = entity.body
		}
		if strings.EqualFold(mediaType, "message/rfc822") || strings.EqualFold(mediaType, "message/global") {
			child, childErr := readMIMEEntity(bytes.NewReader(decoded))
			if childErr == nil {
				appendEntity(child, depth+1)
			} else {
				output.Write(decoded)
			}
			return
		}
		if strings.HasPrefix(strings.ToLower(mediaType), "text/") {
			if charset := parameters["charset"]; charset != "" && !strings.EqualFold(charset, "utf-8") && !strings.EqualFold(charset, "us-ascii") {
				if encoding, charsetErr := htmlindex.Get(charset); charsetErr == nil {
					if converted, _, convertErr := transform.Bytes(encoding.NewDecoder(), decoded); convertErr == nil {
						decoded = converted
					}
				}
			}
		}
		output.Write(decoded)
		output.WriteByte('\n')
	}
	appendEntity(root, 0)
	return output.String()
}
