// Package contactport provides storage-neutral, bounded contact import and
// export. It deliberately returns opaque vCard payloads: persistence and RBAC
// remain the responsibility of FolderSpace consumers.
package contactport

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/lkarlslund/veksel/pkg/model"
)

const (
	// MaxDocumentBytes is the largest accepted contact import document.
	MaxDocumentBytes = 10 << 20
	// MaxContactBytes bounds one opaque vCard payload.
	MaxContactBytes = 1 << 20
	// MaxContacts bounds one atomic import.
	MaxContacts = 10_000
	maxProblems = 100
)

// Format identifies a supported portable contact representation.
type Format string

const (
	FormatVCard Format = "vcard"
	FormatCSV   Format = "csv"
)

// Problem describes one input defect without echoing private contact data.
type Problem struct {
	Record  int    `json:"record,omitempty"`
	Message string `json:"message"`
}

// Document is a completely validated import projection. Contacts contain
// vCard payloads ready for FolderSpace creation. Callers must not persist a
// Document when Problems is non-empty.
type Document struct {
	Format   Format
	Contacts [][]byte
	Names    []string
	Problems []Problem
}

// Valid reports whether a document is non-empty and has no validation defects.
func (d Document) Valid() bool { return len(d.Contacts) > 0 && len(d.Problems) == 0 }

// DetectFormat resolves an explicit format or infers it from a filename.
func DetectFormat(explicit, filename string) (Format, error) {
	value := strings.ToLower(strings.TrimSpace(explicit))
	if value == "" || value == "auto" {
		switch strings.ToLower(filepath.Ext(filename)) {
		case ".vcf", ".vcard":
			return FormatVCard, nil
		case ".csv":
			return FormatCSV, nil
		default:
			return "", errors.New("contact file must use .vcf, .vcard, or .csv")
		}
	}
	switch Format(value) {
	case FormatVCard, FormatCSV:
		return Format(value), nil
	default:
		return "", errors.New("format must be auto, vcard, or csv")
	}
}

// Parse validates data and returns canonical vCard payloads. All input is
// examined before a caller can persist any contact.
func Parse(format Format, data []byte) Document {
	document := Document{Format: format, Contacts: make([][]byte, 0), Names: make([]string, 0), Problems: make([]Problem, 0)}
	if len(data) == 0 {
		document.addProblem(0, "contact file is empty")
		return document
	}
	if len(data) > MaxDocumentBytes {
		document.addProblem(0, fmt.Sprintf("contact file exceeds %d bytes", MaxDocumentBytes))
		return document
	}
	switch format {
	case FormatVCard:
		parseVCards(data, &document)
	case FormatCSV:
		parseCSV(data, &document)
	default:
		document.addProblem(0, "unsupported contact format")
	}
	if len(document.Contacts) == 0 && len(document.Problems) == 0 {
		document.addProblem(0, "contact file contains no contacts")
	}
	return document
}

func parseVCards(data []byte, document *Document) {
	normalized := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	scanner := bufio.NewScanner(strings.NewReader(normalized))
	scanner.Buffer(make([]byte, 64<<10), MaxContactBytes+1)
	var current strings.Builder
	inside, record := false, 0
	for scanner.Scan() {
		line := scanner.Text()
		envelope := strings.TrimSpace(line)
		switch {
		case strings.EqualFold(envelope, "BEGIN:VCARD"):
			if inside {
				document.addProblem(record+1, "nested BEGIN:VCARD")
				current.Reset()
			}
			inside = true
			current.WriteString(line)
			current.WriteByte('\n')
		case strings.EqualFold(envelope, "END:VCARD"):
			if !inside {
				document.addProblem(record+1, "END:VCARD appears before BEGIN:VCARD")
				continue
			}
			current.WriteString(line)
			current.WriteByte('\n')
			record++
			card := []byte(strings.ReplaceAll(current.String(), "\n", "\r\n"))
			if len(card) > MaxContactBytes {
				document.addProblem(record, fmt.Sprintf("vCard exceeds %d bytes", MaxContactBytes))
			} else if err := model.ValidateContactVCard(card); err != nil {
				document.addProblem(record, err.Error())
			} else {
				document.addContact(card)
			}
			inside = false
			current.Reset()
		default:
			if inside {
				current.WriteString(line)
				current.WriteByte('\n')
			} else if envelope != "" {
				document.addProblem(record+1, "content appears outside a vCard envelope")
			}
		}
		if len(document.Contacts) > MaxContacts {
			document.addProblem(0, fmt.Sprintf("contact file exceeds %d contacts", MaxContacts))
			return
		}
	}
	if err := scanner.Err(); err != nil {
		document.addProblem(record+1, "vCard line exceeds the supported size")
	}
	if inside {
		document.addProblem(record+1, "vCard is missing END:VCARD")
	}
}

var csvColumns = []string{
	"Full Name", "Prefix", "Given Name", "Middle Name", "Family Name", "Suffix", "Nickname",
	"Emails", "Phones", "Organization", "Department", "Title", "Role", "Birthday", "URL", "Categories", "Note",
	"Home Street", "Home City", "Home Region", "Home Postal Code", "Home Country",
	"Work Street", "Work City", "Work Region", "Work Postal Code", "Work Country", "Custom Fields",
}

func parseCSV(data []byte, document *Document) {
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = false
	header, err := reader.Read()
	if err != nil {
		document.addProblem(0, "CSV header is unreadable")
		return
	}
	columns := make(map[string]int, len(header))
	allowed := make(map[string]struct{}, len(csvColumns))
	for _, value := range csvColumns {
		allowed[normalizeColumn(value)] = struct{}{}
	}
	for index, value := range header {
		key := normalizeColumn(value)
		if key == "" {
			continue
		}
		if _, duplicate := columns[key]; duplicate {
			document.addProblem(0, fmt.Sprintf("CSV header %q is duplicated", strings.TrimSpace(value)))
			continue
		}
		if _, supported := allowed[key]; !supported {
			document.addProblem(0, fmt.Sprintf("CSV header %q is unsupported", strings.TrimSpace(value)))
			continue
		}
		columns[key] = index
	}
	if _, ok := columns[normalizeColumn("Full Name")]; !ok {
		if _, given := columns[normalizeColumn("Given Name")]; !given {
			if _, family := columns[normalizeColumn("Family Name")]; !family {
				document.addProblem(0, "CSV requires Full Name or Given Name/Family Name columns")
			}
		}
	}
	for row := 2; ; row++ {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			document.addProblem(row, "CSV row is malformed")
			break
		}
		if csvRowEmpty(record) {
			continue
		}
		contact, problem := contactFromCSV(record, columns)
		if problem != "" {
			document.addProblem(row, problem)
			continue
		}
		card := model.NewContactVCard(contact)
		if len(card) == 0 || len(card) > MaxContactBytes {
			document.addProblem(row, "CSV contact could not be represented as a bounded vCard")
			continue
		}
		document.addContact(card)
		if len(document.Contacts) > MaxContacts {
			document.addProblem(0, fmt.Sprintf("contact file exceeds %d contacts", MaxContacts))
			return
		}
	}
}

func contactFromCSV(row []string, columns map[string]int) (model.Contact, string) {
	rawValue := func(name string) string {
		index, ok := columns[normalizeColumn(name)]
		if !ok || index >= len(row) {
			return ""
		}
		return restoreCSVCell(row[index])
	}
	value := func(name string) string { return strings.TrimSpace(rawValue(name)) }
	contact := model.Contact{
		FN: value("Full Name"), Prefix: value("Prefix"), GivenName: value("Given Name"), MiddleName: value("Middle Name"), FamilyName: value("Family Name"), Suffix: value("Suffix"), Nickname: value("Nickname"),
		Emails: splitList(value("Emails")), Phones: splitList(value("Phones")), Org: value("Organization"), Department: value("Department"), Title: value("Title"), Role: value("Role"), Birthday: value("Birthday"), URL: value("URL"), Categories: splitList(value("Categories")), Note: rawValue("Note"),
	}
	if contact.FN == "" {
		contact.FN = strings.TrimSpace(strings.Join(nonEmpty(contact.Prefix, contact.GivenName, contact.MiddleName, contact.FamilyName, contact.Suffix), " "))
	}
	if contact.FN == "" {
		return model.Contact{}, "contact name is empty"
	}
	for _, kind := range []string{"Home", "Work"} {
		address := model.ContactAddress{Type: strings.ToLower(kind), Street: value(kind + " Street"), Locality: value(kind + " City"), Region: value(kind + " Region"), PostalCode: value(kind + " Postal Code"), Country: value(kind + " Country")}
		if address.Street != "" || address.Locality != "" || address.Region != "" || address.PostalCode != "" || address.Country != "" {
			contact.Addresses = append(contact.Addresses, address)
		}
	}
	if raw := value("Custom Fields"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &contact.CustomFields); err != nil {
			return model.Contact{}, "Custom Fields must be a JSON object of string values"
		}
		if contact.CustomFields == nil {
			return model.Contact{}, "Custom Fields must be a JSON object of string values"
		}
		for key, custom := range contact.CustomFields {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(custom) == "" {
				return model.Contact{}, "Custom Fields names and values must be non-empty"
			}
		}
	}
	return contact, ""
}

// Exporter writes contacts incrementally so workspace exports need not load an
// entire address book into memory.
type Exporter struct {
	format Format
	output io.Writer
	csv    *csv.Writer
}

// NewExporter starts a vCard or CSV stream and writes any required header.
func NewExporter(output io.Writer, format Format) (*Exporter, error) {
	exporter := &Exporter{format: format, output: output}
	switch format {
	case FormatVCard:
	case FormatCSV:
		exporter.csv = csv.NewWriter(output)
		if err := exporter.csv.Write(csvColumns); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported contact format")
	}
	return exporter, nil
}

// Write validates and appends one opaque vCard to the export.
func (e *Exporter) Write(data []byte) error {
	if len(data) == 0 || len(data) > MaxContactBytes {
		return errors.New("contact vCard has invalid size")
	}
	if err := model.ValidateContactVCard(data); err != nil {
		return fmt.Errorf("validate contact vCard: %w", err)
	}
	if e.format == FormatVCard {
		if _, err := e.output.Write(data); err != nil {
			return err
		}
		if !bytes.HasSuffix(data, []byte("\n")) {
			_, err := io.WriteString(e.output, "\r\n")
			return err
		}
		return nil
	}
	return e.csv.Write(contactCSVRow(model.ParseVCard(data)))
}

// Close flushes an export and reports buffered CSV errors.
func (e *Exporter) Close() error {
	if e.csv == nil {
		return nil
	}
	e.csv.Flush()
	return e.csv.Error()
}

func contactCSVRow(contact model.Contact) []string {
	addresses := make(map[string]model.ContactAddress)
	for _, address := range contact.Addresses {
		kind := strings.ToLower(strings.TrimSpace(address.Type))
		if kind == "home" || kind == "work" {
			if _, exists := addresses[kind]; !exists {
				addresses[kind] = address
			}
		}
	}
	custom := ""
	if len(contact.CustomFields) > 0 {
		encoded, _ := json.Marshal(contact.CustomFields)
		custom = string(encoded)
	}
	home, work := addresses["home"], addresses["work"]
	values := []string{
		contact.FN, contact.Prefix, contact.GivenName, contact.MiddleName, contact.FamilyName, contact.Suffix, contact.Nickname,
		strings.Join(contact.Emails, "\n"), strings.Join(contact.Phones, "\n"), contact.Org, contact.Department, contact.Title, contact.Role, contact.Birthday, contact.URL, strings.Join(contact.Categories, "\n"), contact.Note,
		home.Street, home.Locality, home.Region, home.PostalCode, home.Country,
		work.Street, work.Locality, work.Region, work.PostalCode, work.Country, custom,
	}
	for index := range values {
		values[index] = safeCSVCell(values[index])
	}
	return values
}

func (d *Document) addContact(card []byte) {
	if len(d.Contacts) >= MaxContacts {
		d.addProblem(0, fmt.Sprintf("contact file exceeds %d contacts", MaxContacts))
		return
	}
	d.Contacts = append(d.Contacts, card)
	d.Names = append(d.Names, model.ParseVCard(card).FN)
}

func (d *Document) addProblem(record int, message string) {
	if len(d.Problems) >= maxProblems {
		if len(d.Problems) == maxProblems {
			d.Problems = append(d.Problems, Problem{Message: "additional problems omitted"})
		}
		return
	}
	d.Problems = append(d.Problems, Problem{Record: record, Message: message})
}

func normalizeColumn(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return -1
	}, strings.TrimSpace(value))
}

func csvRowEmpty(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == ';' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func nonEmpty(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func safeCSVCell(value string) string {
	index := len(value) - len(strings.TrimLeft(value, " \t\r\n"))
	if index < len(value) && strings.ContainsRune("=+-@", rune(value[index])) {
		return value[:index] + "'" + value[index:]
	}
	return value
}

func restoreCSVCell(value string) string {
	index := len(value) - len(strings.TrimLeft(value, " \t\r\n"))
	if index+1 < len(value) && value[index] == '\'' && strings.ContainsRune("=+-@", rune(value[index+1])) {
		return value[:index] + value[index+1:]
	}
	return value
}

// CSVColumns returns the stable exported schema for documentation and tests.
func CSVColumns() []string {
	return append([]string(nil), csvColumns...)
}
