package imap

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strconv"
	"strings"
)

var (
	errUnknownCTE         = errors.New("unknown content-transfer-encoding")
	errInvalidBinaryFetch = errors.New("invalid BINARY fetch item")
)

type binaryFetchRequest struct {
	section     string
	peek        bool
	sizeOnly    bool
	partial     bool
	partialFrom int64
	partialSize int64
}

func parseBinaryFetch(token string) (binaryFetchRequest, bool, error) {
	upper := strings.ToUpper(token)
	request := binaryFetchRequest{}
	var prefix string
	switch {
	case strings.HasPrefix(upper, "BINARY.SIZE["):
		prefix, request.sizeOnly = "BINARY.SIZE[", true
	case strings.HasPrefix(upper, "BINARY.PEEK["):
		prefix, request.peek = "BINARY.PEEK[", true
	case strings.HasPrefix(upper, "BINARY["):
		prefix = "BINARY["
	default:
		return request, false, nil
	}
	closeIndex := strings.IndexByte(token[len(prefix):], ']')
	if closeIndex < 0 {
		return request, true, errInvalidBinaryFetch
	}
	closeIndex += len(prefix)
	request.section = token[len(prefix):closeIndex]
	suffix := token[closeIndex+1:]
	if suffix == "" {
		return request, true, nil
	}
	if request.sizeOnly || len(suffix) < 5 || suffix[0] != '<' || suffix[len(suffix)-1] != '>' {
		return request, true, errInvalidBinaryFetch
	}
	parts := strings.Split(suffix[1:len(suffix)-1], ".")
	if len(parts) != 2 {
		return request, true, errInvalidBinaryFetch
	}
	var err error
	request.partialFrom, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil || request.partialFrom < 0 {
		return request, true, errInvalidBinaryFetch
	}
	request.partialSize, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || request.partialSize < 1 {
		return request, true, errInvalidBinaryFetch
	}
	request.partial = true
	return request, true, nil
}

func binarySection(message []byte, section string) ([]byte, error) {
	root, err := readMIMEEntity(bytes.NewReader(message))
	if err != nil {
		return nil, errInvalidBinaryFetch
	}
	entity := root
	if section != "" {
		pathParts := strings.Split(section, ".")
		path := make([]int, len(pathParts))
		for index, part := range pathParts {
			path[index], err = strconv.Atoi(part)
			if err != nil || path[index] < 1 {
				return nil, errInvalidBinaryFetch
			}
		}
		entity, err = entity.part(path)
		if err != nil {
			return nil, err
		}
	}
	mediaType, _, err := mime.ParseMediaType(entity.header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") || strings.EqualFold(mediaType, "message/rfc822") || strings.EqualFold(mediaType, "message/global") {
		// A composite entity has an identity transfer encoding (RFC 2045
		// 6.4), so decoding it leaves it as it is: the whole message for
		// BINARY[], the part's content otherwise.
		if section == "" {
			return message, nil
		}
		return entity.body, nil
	}
	decoded, err := decodeTransferEncoding(entity.body, entity.header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.ToLower(mediaType), "text/") {
		decoded = normalizeCRLF(decoded)
	}
	return decoded, nil
}

type mimeEntity struct {
	header mail.Header
	body   []byte
}

func readMIMEEntity(reader io.Reader) (mimeEntity, error) {
	message, err := mail.ReadMessage(reader)
	if err != nil {
		return mimeEntity{}, err
	}
	body, err := io.ReadAll(message.Body)
	return mimeEntity{header: message.Header, body: body}, err
}

func (entity mimeEntity) part(path []int) (mimeEntity, error) {
	if len(path) == 0 {
		return entity, nil
	}
	if len(path) > maxMIMEDepth {
		// Each level re-reads the remaining body; a client-chosen path
		// length must not multiply that work without bound.
		return mimeEntity{}, errInvalidBinaryFetch
	}
	mediaType, parameters, err := mime.ParseMediaType(entity.header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		if len(path) == 1 && path[0] == 1 {
			return entity, nil
		}
		return mimeEntity{}, errInvalidBinaryFetch
	}
	boundary := parameters["boundary"]
	if boundary == "" {
		return mimeEntity{}, errInvalidBinaryFetch
	}
	reader := multipart.NewReader(bytes.NewReader(entity.body), boundary)
	for index := 1; ; index++ {
		part, nextErr := reader.NextPart()
		if nextErr != nil {
			return mimeEntity{}, errInvalidBinaryFetch
		}
		body, readErr := io.ReadAll(part)
		if readErr != nil {
			return mimeEntity{}, readErr
		}
		if index == path[0] {
			child := mimeEntity{header: mail.Header(part.Header), body: body}
			return child.part(path[1:])
		}
	}
}

func decodeTransferEncoding(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		return append([]byte(nil), data...), nil
	case "base64":
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(bytes.NewReader(data)))
	default:
		return nil, fmt.Errorf("%w: %s", errUnknownCTE, encoding)
	}
}

func normalizeCRLF(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
}
