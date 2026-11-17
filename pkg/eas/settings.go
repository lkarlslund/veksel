package eas

import (
	"context"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

// Profile describes one account as ActiveSync presents it: in Settings
// UserInformation, as the default From address and in the GAL.
type Profile struct {
	ID          string
	DisplayName string
	// Addresses lists the account's email addresses, primary first.
	Addresses []string
	// TimeZone is the account's IANA zone, used for all-day events.
	TimeZone string
}

func (p Profile) primary() string {
	if len(p.Addresses) == 0 {
		return ""
	}
	return p.Addresses[0]
}

func (p Profile) owns(address string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	for _, candidate := range p.Addresses {
		if strings.EqualFold(candidate, address) {
			return true
		}
	}
	return false
}

// OutOfOffice is the account's automatic reply.
type OutOfOffice struct {
	Enabled bool
	Start   time.Time
	End     time.Time
	Message string
}

// Account is the account directory ActiveSync needs beyond FolderSpace.
type Account interface {
	Profile(ctx context.Context, userID string) (Profile, error)
	OutOfOffice(ctx context.Context, userID string) (OutOfOffice, error)
	SetOutOfOffice(ctx context.Context, userID string, oof OutOfOffice) error
	// Directory searches the global address list visible to userID.
	Directory(ctx context.Context, userID, query string, limit int) ([]Profile, error)
}

func (h *Handler) profile(command *commandContext) Profile {
	if command.profile != nil {
		return *command.profile
	}
	profile := Profile{ID: command.userID}
	if h.account != nil {
		if loaded, err := h.account.Profile(command.ctx, command.userID); err == nil {
			profile = loaded
		}
	}
	command.profile = &profile
	return profile
}

// userLocation is the zone all-day events are anchored in.
func (h *Handler) userLocation(command *commandContext) *time.Location {
	if name := h.profile(command).TimeZone; name != "" {
		if location, err := time.LoadLocation(name); err == nil {
			return location
		}
	}
	return time.Local
}

func (h *Handler) settings(command *commandContext) (*Node, error) {
	response := E(18, "Settings", T(18, "Status", "1"))
	request := command.request
	if request == nil {
		response.Children[0].Text = "2"
		return response, nil
	}
	for _, child := range request.Children {
		switch child.Tag {
		case "Oof":
			response.Children = append(response.Children, h.oofSettings(command, child))
		case "DeviceInformation":
			// The device inventory already captured the values.
			response.Children = append(response.Children, E(18, "DeviceInformation", T(18, "Status", "1")))
		case "DevicePassword":
			response.Children = append(response.Children, E(18, "DevicePassword", T(18, "Status", "1")))
		case "UserInformation":
			response.Children = append(response.Children, h.userInformation(command))
		case "RightsManagementInformation":
			response.Children = append(response.Children, E(18, "RightsManagementInformation", T(18, "Status", "1")))
		}
	}
	return response, nil
}

func (h *Handler) userInformation(command *commandContext) *Node {
	profile := h.profile(command)
	addresses := E(18, "EmailAddresses")
	for _, address := range profile.Addresses {
		addresses.Children = append(addresses.Children, T(18, "SmtpAddress", address))
	}
	if command.version(14, 1) {
		if primary := profile.primary(); primary != "" {
			addresses.Children = append(addresses.Children, T(18, "PrimarySmtpAddress", primary))
		}
		account := E(18, "Account")
		if profile.DisplayName != "" {
			account.Children = append(account.Children, T(18, "UserDisplayName", profile.DisplayName))
		}
		account.Children = append(account.Children, addresses)
		return E(18, "UserInformation", T(18, "Status", "1"), E(18, "Get", E(18, "Accounts", account)))
	}
	return E(18, "UserInformation", T(18, "Status", "1"), E(18, "Get", addresses))
}

// oofSettings answers Settings Oof Get and Set (MS-ASCMD 2.2.3.119). Veksel
// has one automatic reply, so the internal message is the authoritative
// one and is reported for every audience.
func (h *Handler) oofSettings(command *commandContext, request *Node) *Node {
	if h.account == nil {
		return E(18, "Oof", T(18, "Status", "2"))
	}
	if set := request.Child("Set"); set != nil {
		current, err := h.account.OutOfOffice(command.ctx, command.userID)
		if err != nil {
			return E(18, "Oof", T(18, "Status", "2"))
		}
		state := childText(set, "OofState")
		current.Enabled = state == "1" || state == "2"
		current.Start, current.End = time.Time{}, time.Time{}
		if state == "2" {
			if start, ok := parseEASTime(childText(set, "StartTime")); ok {
				current.Start = start
			}
			if end, ok := parseEASTime(childText(set, "EndTime")); ok {
				current.End = end
			}
		}
		var chosen *Node
		for _, message := range set.ChildrenNamed("OofMessage") {
			if message.Child("AppliesToInternal") != nil {
				chosen = message
				break
			}
			if chosen == nil {
				chosen = message
			}
		}
		if chosen != nil && chosen.Child("ReplyMessage") != nil {
			text := childText(chosen, "ReplyMessage")
			if strings.EqualFold(childText(chosen, "BodyType"), "HTML") {
				text = service.HTMLToText(text)
			}
			current.Message = text
		}
		if err := h.account.SetOutOfOffice(command.ctx, command.userID, current); err != nil {
			return E(18, "Oof", T(18, "Status", "2"))
		}
		return E(18, "Oof", T(18, "Status", "1"))
	}
	oof, err := h.account.OutOfOffice(command.ctx, command.userID)
	if err != nil {
		return E(18, "Oof", T(18, "Status", "2"))
	}
	state := "0"
	if oof.Enabled {
		state = "1"
		if !oof.Start.IsZero() || !oof.End.IsZero() {
			state = "2"
		}
	}
	bodyType := "TEXT"
	if requested := nodeText(request.Child("Get"), "BodyType"); strings.EqualFold(requested, "HTML") {
		bodyType = "HTML"
	}
	message := oof.Message
	if bodyType == "HTML" {
		message = textToHTML(message)
	}
	get := E(18, "Get", T(18, "OofState", state))
	if state == "2" {
		get.Children = append(get.Children, T(18, "StartTime", oof.Start.UTC().Format(easDateFormat)), T(18, "EndTime", oof.End.UTC().Format(easDateFormat)))
	}
	for _, audience := range []string{"AppliesToInternal", "AppliesToExternalKnown", "AppliesToExternalUnknown"} {
		entry := E(18, "OofMessage", E(18, audience), T(18, "Enabled", boolNumber(oof.Enabled)))
		if message != "" {
			entry.Children = append(entry.Children, T(18, "ReplyMessage", message))
		}
		entry.Children = append(entry.Children, T(18, "BodyType", bodyType))
		get.Children = append(get.Children, entry)
	}
	return E(18, "Oof", T(18, "Status", "1"), get)
}
