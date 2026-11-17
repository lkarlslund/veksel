package smtp

import (
	"fmt"
	"strconv"
	"strings"
)

type dsnRecipientOptions struct {
	notify string
	orcpt  string
}

func splitSMTPPathParameters(value string) (string, []string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil, fmt.Errorf("address is required")
	}
	if value[0] == '<' {
		end := strings.IndexByte(value, '>')
		if end < 0 {
			return "", nil, fmt.Errorf("unterminated address path")
		}
		return value[:end+1], strings.Fields(value[end+1:]), nil
	}
	fields := strings.Fields(value)
	return fields[0], fields[1:], nil
}

func parseMailParameters(parameters []string, maxMessageSize int64) (returnMode, envelopeID string, requireTLS bool, err error) {
	seen := make(map[string]bool, len(parameters))
	for _, parameter := range parameters {
		name, value, hasValue := parameterParts(parameter)
		if seen[name] {
			return "", "", false, fmt.Errorf("duplicate MAIL parameter %s", name)
		}
		seen[name] = true
		switch name {
		case "BODY":
			upperValue := strings.ToUpper(value)
			if !hasValue || (upperValue != "7BIT" && upperValue != "8BITMIME") {
				return "", "", false, fmt.Errorf("unsupported BODY value")
			}
		case "SMTPUTF8":
			if hasValue {
				return "", "", false, fmt.Errorf("SMTPUTF8 does not take a value")
			}
		case "REQUIRETLS":
			if hasValue {
				return "", "", false, fmt.Errorf("REQUIRETLS does not take a value")
			}
			requireTLS = true
		case "SIZE":
			size, parseErr := strconv.ParseInt(value, 10, 64)
			if !hasValue || parseErr != nil || size < 0 {
				return "", "", false, fmt.Errorf("invalid SIZE value")
			}
			if maxMessageSize > 0 && size > maxMessageSize {
				return "", "", false, fmt.Errorf("declared message size exceeds limit")
			}
		case "RET":
			upperValue := strings.ToUpper(value)
			if !hasValue || (upperValue != "FULL" && upperValue != "HDRS") {
				return "", "", false, fmt.Errorf("RET must be FULL or HDRS")
			}
			returnMode = strings.ToLower(upperValue)
		case "ENVID":
			if !hasValue || len(value) > 100 || !validXText(value) {
				return "", "", false, fmt.Errorf("invalid ENVID")
			}
			envelopeID = value
		default:
			return "", "", false, fmt.Errorf("unsupported MAIL parameter %s", name)
		}
	}
	return returnMode, envelopeID, requireTLS, nil
}

func parseRecipientParameters(parameters []string) (dsnRecipientOptions, error) {
	var result dsnRecipientOptions
	seen := make(map[string]bool, len(parameters))
	for _, parameter := range parameters {
		name, value, hasValue := parameterParts(parameter)
		if seen[name] {
			return result, fmt.Errorf("duplicate RCPT parameter %s", name)
		}
		seen[name] = true
		switch name {
		case "NOTIFY":
			if !hasValue {
				return result, fmt.Errorf("NOTIFY requires a value")
			}
			values := strings.Split(strings.ToUpper(value), ",")
			if len(values) == 0 || len(values) > 3 {
				return result, fmt.Errorf("invalid NOTIFY value")
			}
			notifications := make(map[string]bool, len(values))
			for _, notification := range values {
				if notification != "NEVER" && notification != "SUCCESS" && notification != "FAILURE" && notification != "DELAY" {
					return result, fmt.Errorf("invalid NOTIFY value")
				}
				if notifications[notification] {
					return result, fmt.Errorf("duplicate NOTIFY value")
				}
				notifications[notification] = true
			}
			if notifications["NEVER"] && len(notifications) != 1 {
				return result, fmt.Errorf("NOTIFY NEVER cannot be combined")
			}
			result.notify = strings.ToLower(strings.Join(values, ","))
		case "ORCPT":
			addressType, original, ok := strings.Cut(value, ";")
			if !hasValue || !ok || !validAtom(addressType) || len(original) > 500 || !validXText(original) {
				return result, fmt.Errorf("invalid ORCPT")
			}
			result.orcpt = strings.ToLower(addressType) + ";" + original
		default:
			return result, fmt.Errorf("unsupported RCPT parameter %s", name)
		}
	}
	return result, nil
}

func parameterParts(parameter string) (name, value string, hasValue bool) {
	name, value, hasValue = strings.Cut(parameter, "=")
	return strings.ToUpper(name), value, hasValue
}

func validXText(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character == '+':
			if index+2 >= len(value) || !isHex(value[index+1]) || !isHex(value[index+2]) {
				return false
			}
			index += 2
		case character < '!' || character > '~' || character == '=':
			return false
		}
	}
	return true
}

func validAtom(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
			return false
		}
	}
	return true
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}
