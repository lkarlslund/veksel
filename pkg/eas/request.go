package eas

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// requestLine is the command addressing of one ActiveSync request. Clients
// send it either as a plain query string (Cmd=Sync&User=...&DeviceId=...) or,
// like Windows Mail and Windows Phone, as one base64-encoded binary
// structure (MS-ASHTTP 2.2.1.1.1.1). Both forms normalize to this value.
type requestLine struct {
	Command      string
	User         string
	DeviceID     string
	DeviceType   string
	Version      string
	PolicyKey    string
	ItemID       string
	CollectionID string
	LongID       string
	Attachment   string
	Occurrence   string
	SaveInSent   bool
	SaveInSentOK bool
	MultiPart    bool
}

// base64CommandCodes are the MS-ASHTTP 2.2.1.1.1.1.2 command codes.
var base64CommandCodes = map[byte]string{
	0: "Sync", 1: "SendMail", 2: "SmartForward", 3: "SmartReply", 4: "GetAttachment",
	9: "FolderSync", 10: "FolderCreate", 11: "FolderDelete", 12: "FolderUpdate",
	13: "MoveItems", 14: "GetItemEstimate", 15: "MeetingResponse", 16: "Search",
	17: "Settings", 18: "Ping", 19: "ItemOperations", 20: "Provision",
	21: "ResolveRecipients", 22: "ValidateCert", 23: "Find",
}

func parseRequestLine(r *http.Request) (requestLine, error) {
	raw := r.URL.RawQuery
	query := r.URL.Query()
	var line requestLine
	if raw != "" && !query.Has("Cmd") {
		decoded, err := parseBase64RequestLine(raw)
		if err != nil {
			return requestLine{}, err
		}
		line = decoded
	} else {
		line = requestLine{
			Command:      strings.TrimSpace(query.Get("Cmd")),
			User:         query.Get("User"),
			DeviceID:     query.Get("DeviceId"),
			DeviceType:   query.Get("DeviceType"),
			ItemID:       query.Get("ItemId"),
			CollectionID: query.Get("CollectionId"),
			LongID:       query.Get("LongId"),
			Attachment:   query.Get("AttachmentName"),
			Occurrence:   query.Get("Occurrence"),
		}
		if value := query.Get("SaveInSent"); value != "" {
			line.SaveInSentOK = true
			line.SaveInSent = strings.EqualFold(value, "T")
		}
		line.Version = r.Header.Get("MS-ASProtocolVersion")
	}
	if line.PolicyKey == "" {
		line.PolicyKey = strings.TrimSpace(r.Header.Get("X-MS-PolicyKey"))
	}
	if line.Version == "" {
		line.Version = r.Header.Get("MS-ASProtocolVersion")
	}
	if line.Version == "" {
		line.Version = "14.1"
	}
	if strings.EqualFold(r.Header.Get("MS-ASAcceptMultiPart"), "T") {
		line.MultiPart = true
	}
	line.DeviceID = cleanDeviceID(line.DeviceID)
	return line, nil
}

func parseBase64RequestLine(raw string) (requestLine, error) {
	unescaped, err := url.QueryUnescape(raw)
	if err != nil {
		return requestLine{}, err
	}
	data, err := base64.StdEncoding.DecodeString(unescaped)
	if err != nil {
		if data, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(unescaped, "=")); err != nil {
			return requestLine{}, errors.New("invalid base64 request line")
		}
	}
	reader := byteCursor{data: data}
	version, ok1 := reader.byte()
	code, ok2 := reader.byte()
	_, ok3 := reader.bytes(2) // locale
	deviceID, ok4 := reader.counted()
	policy, ok5 := reader.counted()
	deviceType, ok6 := reader.counted()
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return requestLine{}, errors.New("truncated base64 request line")
	}
	command, known := base64CommandCodes[code]
	if !known {
		return requestLine{}, errors.New("unknown base64 command code")
	}
	line := requestLine{
		Command:    command,
		Version:    strconv.Itoa(int(version)/10) + "." + strconv.Itoa(int(version)%10),
		DeviceID:   base64DeviceID(deviceID),
		DeviceType: string(deviceType),
	}
	if len(policy) == 4 {
		line.PolicyKey = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(policy)), 10)
	}
	for reader.remaining() > 0 {
		tag, ok := reader.byte()
		value, ok2 := reader.counted()
		if !ok || !ok2 {
			return requestLine{}, errors.New("truncated base64 request parameter")
		}
		switch tag {
		case 0:
			line.Attachment = string(value)
		case 1:
			line.CollectionID = string(value)
		case 3:
			line.ItemID = string(value)
		case 4:
			line.LongID = string(value)
		case 6:
			line.Occurrence = string(value)
		case 7:
			if len(value) > 0 {
				line.SaveInSentOK = true
				line.SaveInSent = value[0]&0x01 != 0
				line.MultiPart = value[0]&0x02 != 0
			}
		case 8:
			line.User = string(value)
		}
	}
	return line, nil
}

// base64DeviceID keeps a printable alphanumeric identifier as sent and
// renders a binary one (Windows sends a GUID) as hexadecimal, matching the
// plain query form's alphabet.
func base64DeviceID(value []byte) string {
	for _, b := range value {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && (b < '0' || b > '9') {
			return hex.EncodeToString(value)
		}
	}
	return string(value)
}

type byteCursor struct {
	data []byte
	pos  int
}

func (c *byteCursor) remaining() int { return len(c.data) - c.pos }

func (c *byteCursor) byte() (byte, bool) {
	if c.pos >= len(c.data) {
		return 0, false
	}
	c.pos++
	return c.data[c.pos-1], true
}

func (c *byteCursor) bytes(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.data) {
		return nil, false
	}
	c.pos += n
	return c.data[c.pos-n : c.pos], true
}

func (c *byteCursor) counted() ([]byte, bool) {
	n, ok := c.byte()
	if !ok {
		return nil, false
	}
	return c.bytes(int(n))
}

func versionAtLeast(version string, major, minor int) bool {
	majorText, minorText, _ := strings.Cut(version, ".")
	gotMajor, err := strconv.Atoi(majorText)
	if err != nil {
		return false
	}
	gotMinor, _ := strconv.Atoi(minorText)
	return gotMajor > major || gotMajor == major && gotMinor >= minor
}
