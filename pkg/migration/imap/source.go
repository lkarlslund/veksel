// Package imap provides an IMAP migration source.
package imap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/lkarlslund/veksel/pkg/migration"
	"github.com/lkarlslund/veksel/pkg/model"
)

type TLSMode string

const (
	TLSImplicit TLSMode = "tls"
	TLSStartTLS TLSMode = "starttls"
	TLSNone     TLSMode = "none"
)

type Config struct {
	Address   string
	Username  string
	Password  string
	TLSMode   TLSMode
	TLSConfig *tls.Config
	PageSize  uint32
	Timeout   time.Duration
}

type Source struct {
	client   *imapclient.Client
	identity string
	pageSize uint32
	folders  map[string]*imapv2.ListData
}

func Dial(cfg Config) (*Source, error) {
	if strings.TrimSpace(cfg.Address) == "" || strings.TrimSpace(cfg.Username) == "" {
		return nil, errors.New("IMAP address and username are required")
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	options := &imapclient.Options{TLSConfig: cfg.TLSConfig, Dialer: &net.Dialer{Timeout: cfg.Timeout}}
	var client *imapclient.Client
	var err error
	switch cfg.TLSMode {
	case TLSImplicit:
		client, err = imapclient.DialTLS(cfg.Address, options)
	case TLSStartTLS:
		client, err = imapclient.DialStartTLS(cfg.Address, options)
	case TLSNone:
		client, err = imapclient.DialInsecure(cfg.Address, options)
	default:
		return nil, fmt.Errorf("unsupported IMAP TLS mode %q", cfg.TLSMode)
	}
	if err != nil {
		return nil, fmt.Errorf("connect IMAP: %w", err)
	}
	if err := client.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("authenticate IMAP: %w", err)
	}
	return &Source{client: client, identity: "imap://" + cfg.Username + "@" + cfg.Address, pageSize: cfg.PageSize, folders: make(map[string]*imapv2.ListData)}, nil
}

func (s *Source) ID() string { return s.identity }

func (s *Source) Close() error {
	if s.client == nil {
		return nil
	}
	_ = s.client.Logout().Wait()
	return s.client.Close()
}

func (s *Source) Folders(_ context.Context) ([]migration.Folder, error) {
	listed, err := s.client.List("", "*", &imapv2.ListOptions{ReturnStatus: &imapv2.StatusOptions{NumMessages: true, UIDNext: true, UIDValidity: true}}).Collect()
	if err != nil {
		return nil, fmt.Errorf("list IMAP mailboxes: %w", err)
	}
	result := make([]migration.Folder, 0, len(listed))
	byName := make(map[string]string, len(listed))
	for _, mailbox := range listed {
		if hasAttr(mailbox.Attrs, imapv2.MailboxAttrNoSelect) || hasAttr(mailbox.Attrs, imapv2.MailboxAttrNonExistent) {
			continue
		}
		id := mailbox.Mailbox
		byName[mailbox.Mailbox] = id
		s.folders[id] = mailbox
	}
	for _, mailbox := range listed {
		if _, ok := s.folders[mailbox.Mailbox]; !ok {
			continue
		}
		parent := ""
		if mailbox.Delim != 0 {
			if index := strings.LastIndex(mailbox.Mailbox, string(mailbox.Delim)); index >= 0 {
				parent = byName[mailbox.Mailbox[:index]]
			}
		}
		name := mailbox.Mailbox
		if mailbox.Delim != 0 {
			if index := strings.LastIndex(name, string(mailbox.Delim)); index >= 0 {
				name = name[index+len(string(mailbox.Delim)):]
			}
		}
		estimate := int64(0)
		estimateKnown := false
		if mailbox.Status != nil && mailbox.Status.NumMessages != nil {
			estimate = int64(*mailbox.Status.NumMessages)
			estimateKnown = true
		}
		result = append(result, migration.Folder{ID: mailbox.Mailbox, ParentID: parent, Name: name, Type: model.FolderTypeMail, Special: specialUse(mailbox), Estimate: estimate, EstimateKnown: estimateKnown})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

type checkpoint struct {
	Version       int        `json:"version,omitempty"`
	UIDValidity   uint32     `json:"uid_validity"`
	HighestModSeq uint64     `json:"highest_mod_seq,omitempty"`
	KnownUIDs     []uidRange `json:"known_uids,omitempty"`
	// LastUID is retained solely to upgrade checkpoints written by the old
	// append-only implementation. New checkpoints use Scan.
	LastUID uint32          `json:"last_uid,omitempty"`
	Scan    *scanCheckpoint `json:"scan,omitempty"`
}

type scanCheckpoint struct {
	UIDValidity        uint32     `json:"uid_validity"`
	HighestModSeq      uint64     `json:"highest_mod_seq,omitempty"`
	LastUID            uint32     `json:"last_uid,omitempty"`
	UIDs               []uidRange `json:"uids,omitempty"`
	DeletedUIDValidity uint32     `json:"deleted_uid_validity,omitempty"`
	LastDeletedUID     uint32     `json:"last_deleted_uid,omitempty"`
	DeletedUIDs        []uidRange `json:"deleted_uids,omitempty"`
}

type uidRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

const imapCheckpointVersion = 2

func (s *Source) Items(_ context.Context, folder migration.Folder, token string) (migration.Page, error) {
	condstore := s.client.Caps().Has(imapv2.CapCondStore)
	selected, err := s.client.Select(folder.ID, &imapv2.SelectOptions{ReadOnly: true, CondStore: condstore}).Wait()
	if err != nil {
		return migration.Page{}, fmt.Errorf("select IMAP mailbox %q: %w", folder.ID, err)
	}
	state := checkpoint{Version: imapCheckpointVersion, UIDValidity: selected.UIDValidity}
	if token != "" {
		if err := json.Unmarshal([]byte(token), &state); err != nil {
			return migration.Page{}, fmt.Errorf("decode IMAP checkpoint: %w", err)
		}
		if state.Version == 0 {
			state.Version = imapCheckpointVersion
			if state.LastUID > 0 {
				state.KnownUIDs = []uidRange{{Start: 1, End: state.LastUID}}
			}
			state.LastUID = 0
		}
	}
	if state.Version != imapCheckpointVersion {
		return migration.Page{}, fmt.Errorf("unsupported IMAP checkpoint version %d", state.Version)
	}
	if state.Scan != nil && state.Scan.UIDValidity != selected.UIDValidity {
		return migration.Page{}, fmt.Errorf("IMAP UIDVALIDITY changed from %d to %d during an unfinished folder scan; clear this folder checkpoint before retrying", state.Scan.UIDValidity, selected.UIDValidity)
	}
	if state.Scan == nil {
		search, err := s.client.UIDSearch(&imapv2.SearchCriteria{}, nil).Wait()
		if err != nil {
			return migration.Page{}, fmt.Errorf("list UIDs in IMAP mailbox %q: %w", folder.ID, err)
		}
		current := uidNumbers(search.AllUIDs())
		var deletedUIDs []uidRange
		deletedValidity := state.UIDValidity
		if state.UIDValidity == selected.UIDValidity {
			deletedUIDs = compactUIDs(subtractUIDRanges(state.KnownUIDs, current))
		} else {
			deletedUIDs = append([]uidRange(nil), state.KnownUIDs...)
			state.HighestModSeq = 0
		}
		state.Scan = &scanCheckpoint{
			UIDValidity: selected.UIDValidity, HighestModSeq: selected.HighestModSeq,
			UIDs: compactUIDs(current), DeletedUIDValidity: deletedValidity, DeletedUIDs: deletedUIDs,
		}
	}
	pageUIDs := uidRangePage(state.Scan.UIDs, state.Scan.LastUID, int(s.pageSize))
	pageDeletedUIDs := uidRangePage(state.Scan.DeletedUIDs, state.Scan.LastDeletedUID, int(s.pageSize))
	deletedIDs := make([]string, len(pageDeletedUIDs))
	for i, uid := range pageDeletedUIDs {
		deletedIDs[i] = externalID(state.Scan.DeletedUIDValidity, uid)
	}
	if len(pageDeletedUIDs) > 0 {
		state.Scan.LastDeletedUID = pageDeletedUIDs[len(pageDeletedUIDs)-1]
	}
	if len(pageUIDs) == 0 {
		done := !uidRangesHaveAfter(state.Scan.DeletedUIDs, state.Scan.LastDeletedUID)
		if !done {
			encoded, err := json.Marshal(state)
			if err != nil {
				return migration.Page{}, err
			}
			return migration.Page{DeletedIDs: deletedIDs, Checkpoint: string(encoded)}, nil
		}
		state.UIDValidity = state.Scan.UIDValidity
		state.HighestModSeq = state.Scan.HighestModSeq
		state.KnownUIDs = state.Scan.UIDs
		state.Scan = nil
		encoded, err := json.Marshal(state)
		if err != nil {
			return migration.Page{}, err
		}
		return migration.Page{DeletedIDs: deletedIDs, Checkpoint: string(encoded), Done: true}, nil
	}
	set := imapv2.UIDSetNum(toIMAPUIDs(pageUIDs)...)
	if condstore && state.UIDValidity == state.Scan.UIDValidity && state.HighestModSeq > 0 {
		metadata, err := s.client.Fetch(set, &imapv2.FetchOptions{UID: true, ModSeq: true}).Collect()
		if err != nil {
			return migration.Page{}, fmt.Errorf("fetch IMAP mailbox %q metadata: %w", folder.ID, err)
		}
		changedUIDs := make([]uint32, 0, len(metadata))
		for _, message := range metadata {
			uid := uint32(message.UID)
			if message.ModSeq > state.HighestModSeq || !uidInRanges(state.KnownUIDs, uid) {
				changedUIDs = append(changedUIDs, uid)
			}
		}
		if len(changedUIDs) == 0 {
			state.Scan.LastUID = pageUIDs[len(pageUIDs)-1]
			done := !uidRangesHaveAfter(state.Scan.UIDs, state.Scan.LastUID) && !uidRangesHaveAfter(state.Scan.DeletedUIDs, state.Scan.LastDeletedUID)
			if done {
				state.UIDValidity = state.Scan.UIDValidity
				state.HighestModSeq = state.Scan.HighestModSeq
				state.KnownUIDs = state.Scan.UIDs
				state.Scan = nil
			}
			encoded, err := json.Marshal(state)
			if err != nil {
				return migration.Page{}, err
			}
			return migration.Page{DeletedIDs: deletedIDs, Checkpoint: string(encoded), Done: done}, nil
		}
		set = imapv2.UIDSetNum(toIMAPUIDs(changedUIDs)...)
	}
	section := &imapv2.FetchItemBodySection{}
	fetchOptions := &imapv2.FetchOptions{UID: true, Flags: true, InternalDate: true, RFC822Size: true, ModSeq: condstore, BodySection: []*imapv2.FetchItemBodySection{section}}
	command := s.client.Fetch(set, fetchOptions)
	messages, err := command.Collect()
	if err != nil {
		return migration.Page{}, fmt.Errorf("fetch IMAP mailbox %q: %w", folder.ID, err)
	}
	items := make([]migration.Item, 0, len(messages))
	for _, message := range messages {
		items = append(items, migrationItem(state.Scan.UIDValidity, message, section))
	}
	state.Scan.LastUID = pageUIDs[len(pageUIDs)-1]
	done := !uidRangesHaveAfter(state.Scan.UIDs, state.Scan.LastUID) && !uidRangesHaveAfter(state.Scan.DeletedUIDs, state.Scan.LastDeletedUID)
	if done {
		state.UIDValidity = state.Scan.UIDValidity
		state.HighestModSeq = state.Scan.HighestModSeq
		state.KnownUIDs = state.Scan.UIDs
		state.Scan = nil
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return migration.Page{}, err
	}
	return migration.Page{Items: items, DeletedIDs: deletedIDs, Checkpoint: string(encoded), Done: done}, nil
}

func migrationItem(uidValidity uint32, message *imapclient.FetchMessageBuffer, section *imapv2.FetchItemBodySection) migration.Item {
	data := append([]byte(nil), message.FindBodySection(section)...)
	flags := stringFlags(message.Flags)
	version := strconv.FormatUint(message.ModSeq, 10)
	if message.ModSeq == 0 {
		version = strconv.FormatInt(message.InternalDate.UnixNano(), 10) + ":" + strconv.FormatInt(message.RFC822Size, 10) + ":" + strings.Join(flags, ",")
	}
	return migration.Item{
		ID: externalID(uidValidity, uint32(message.UID)), Version: version, Data: data,
		Headers: model.ParseItemHeaders(data), Flags: flags, InternalDate: message.InternalDate,
	}
}

func externalID(uidValidity, uid uint32) string {
	return strconv.FormatUint(uint64(uidValidity), 10) + ":" + strconv.FormatUint(uint64(uid), 10)
}

func uidNumbers(values []imapv2.UID) []uint32 {
	result := make([]uint32, 0, len(values))
	for _, value := range values {
		if value != 0 {
			result = append(result, uint32(value))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func toIMAPUIDs(values []uint32) []imapv2.UID {
	result := make([]imapv2.UID, len(values))
	for i, value := range values {
		result[i] = imapv2.UID(value)
	}
	return result
}

func compactUIDs(values []uint32) []uidRange {
	if len(values) == 0 {
		return nil
	}
	values = append([]uint32(nil), values...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	ranges := make([]uidRange, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if len(ranges) == 0 {
			ranges = append(ranges, uidRange{Start: value, End: value})
			continue
		}
		last := &ranges[len(ranges)-1]
		if value <= last.End {
			continue
		}
		if last.End != ^uint32(0) && value == last.End+1 {
			last.End = value
			continue
		}
		ranges = append(ranges, uidRange{Start: value, End: value})
	}
	return ranges
}

func subtractUIDRanges(left []uidRange, right []uint32) []uint32 {
	result := make([]uint32, 0)
	j := 0
	for _, value := range left {
		if value.Start == 0 || value.End < value.Start {
			continue
		}
		for uid := value.Start; ; uid++ {
			for j < len(right) && right[j] < uid {
				j++
			}
			if j == len(right) || right[j] != uid {
				result = append(result, uid)
			}
			if uid == value.End {
				break
			}
		}
	}
	return result
}

func uidRangePage(ranges []uidRange, last uint32, limit int) []uint32 {
	if limit < 1 {
		return nil
	}
	result := make([]uint32, 0, limit)
	for _, value := range ranges {
		if value.Start == 0 || value.End < value.Start || value.End <= last {
			continue
		}
		start := value.Start
		if start <= last {
			if last == ^uint32(0) {
				continue
			}
			start = last + 1
		}
		for uid := start; ; uid++ {
			result = append(result, uid)
			if len(result) == limit || uid == value.End {
				break
			}
		}
		if len(result) == limit {
			break
		}
	}
	return result
}

func uidRangesHaveAfter(ranges []uidRange, last uint32) bool {
	for _, value := range ranges {
		if value.Start > 0 && value.End >= value.Start && value.End > last {
			return true
		}
	}
	return false
}

func uidInRanges(ranges []uidRange, uid uint32) bool {
	index := sort.Search(len(ranges), func(i int) bool { return ranges[i].End >= uid })
	return index < len(ranges) && ranges[index].Start <= uid
}

func stringFlags(flags []imapv2.Flag) []string {
	result := make([]string, len(flags))
	for i, flag := range flags {
		result[i] = string(flag)
	}
	return result
}

func hasAttr(attributes []imapv2.MailboxAttr, wanted imapv2.MailboxAttr) bool {
	for _, attribute := range attributes {
		if strings.EqualFold(string(attribute), string(wanted)) {
			return true
		}
	}
	return false
}

func specialUse(mailbox *imapv2.ListData) string {
	for _, attribute := range mailbox.Attrs {
		switch strings.ToLower(string(attribute)) {
		case "\\inbox":
			return model.SpecialUseInbox
		case "\\sent":
			return model.SpecialUseSent
		case "\\drafts":
			return model.SpecialUseDrafts
		case "\\trash":
			return model.SpecialUseTrash
		case "\\junk":
			return model.SpecialUseJunk
		case "\\archive":
			return model.SpecialUseArchive
		}
	}
	if strings.EqualFold(mailbox.Mailbox, "INBOX") {
		return model.SpecialUseInbox
	}
	return ""
}
