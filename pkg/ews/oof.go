package ews

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/service"
)

// OutOfOffice is the account's automatic reply (the vacation responder).
type OutOfOffice struct {
	Enabled bool
	Start   time.Time
	End     time.Time
	Subject string
	Message string
}

var errOOFUnavailable = errors.New("out-of-office settings are unavailable")

// oofResponse wraps the ResponseMessage of the availability-style OOF
// operations, which answer one mailbox without a ResponseMessages list.
func oofResponse(operation string, err error, body string) string {
	if err != nil {
		code, text := ewsError(err)
		return `<m:` + operation + `Response><m:ResponseMessage ResponseClass="Error"><m:MessageText>` + escape(text) + `</m:MessageText><m:ResponseCode>` + code + `</m:ResponseCode><m:DescriptiveLinkKey>0</m:DescriptiveLinkKey></m:ResponseMessage></m:` + operation + `Response>`
	}
	return `<m:` + operation + `Response><m:ResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode></m:ResponseMessage>` + body + `</m:` + operation + `Response>`
}

// oofMailbox checks that the request names the user's own mailbox; Veksel
// does not manage other users' automatic replies over EWS.
func (h *Handler) oofMailbox(ctx context.Context, access service.AccessContext, op *node) error {
	address := strings.TrimSpace(op.child("Mailbox").descendantText("Address"))
	profile := h.loadProfile(ctx, access.Actor.ID)
	if address != "" && len(profile.Addresses) > 0 && !profile.owns(address) {
		return service.ErrForbidden
	}
	return nil
}

// getUserOofSettings implements GetUserOofSettings over the vacation
// responder. Veksel keeps one message, sent to every sender, so both
// replies carry it and ExternalAudience is All.
func (h *Handler) getUserOofSettings(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	if err := h.oofMailbox(ctx, access, op); err != nil {
		return oofResponse("GetUserOofSettings", err, ""), nil
	}
	if h.outOfOffice == nil {
		return oofResponse("GetUserOofSettings", errOOFUnavailable, ""), nil
	}
	oof, err := h.outOfOffice(ctx, access.Actor.ID)
	if err != nil {
		return oofResponse("GetUserOofSettings", err, ""), nil
	}
	state := "Disabled"
	if oof.Enabled {
		state = "Enabled"
		if !oof.Start.IsZero() || !oof.End.IsZero() {
			state = "Scheduled"
		}
	}
	start, end := oof.Start, oof.End
	if start.IsZero() {
		start = time.Now().UTC().Truncate(time.Hour)
	}
	if end.IsZero() || !end.After(start) {
		end = start.Add(24 * time.Hour)
	}
	message := escape(oof.Message)
	body := `<t:OofSettings><t:OofState>` + state + `</t:OofState><t:ExternalAudience>All</t:ExternalAudience><t:Duration><t:StartTime>` + formatDateTime(start) + `</t:StartTime><t:EndTime>` + formatDateTime(end) + `</t:EndTime></t:Duration><t:InternalReply><t:Message>` + message + `</t:Message></t:InternalReply><t:ExternalReply><t:Message>` + message + `</t:Message></t:ExternalReply></t:OofSettings><m:AllowExternalOof>All</m:AllowExternalOof>`
	return oofResponse("GetUserOofSettings", nil, body), nil
}

// setUserOofSettings implements SetUserOofSettings: Disabled turns the
// responder off, Enabled on without dates, Scheduled on for Duration. The
// internal reply is kept, or the external one when the internal is empty.
func (h *Handler) setUserOofSettings(ctx context.Context, access service.AccessContext, op *node) (string, error) {
	if err := h.oofMailbox(ctx, access, op); err != nil {
		return oofResponse("SetUserOofSettings", err, ""), nil
	}
	if h.outOfOffice == nil || h.setOutOfOffice == nil {
		return oofResponse("SetUserOofSettings", errOOFUnavailable, ""), nil
	}
	settings := op.child("UserOofSettings")
	if settings == nil {
		return "", fmt.Errorf("%w: UserOofSettings is required", errEWSInvalidProperty)
	}
	current, err := h.outOfOffice(ctx, access.Actor.ID)
	if err != nil {
		return oofResponse("SetUserOofSettings", err, ""), nil
	}
	next := current
	switch strings.ToLower(strings.TrimSpace(settings.descendantText("OofState"))) {
	case "disabled":
		next.Enabled = false
	case "enabled":
		next.Enabled, next.Start, next.End = true, time.Time{}, time.Time{}
	case "scheduled":
		duration := settings.child("Duration")
		start, okStart := parseDateTime(duration.descendantText("StartTime"), localZone{location: time.UTC})
		end, okEnd := parseDateTime(duration.descendantText("EndTime"), localZone{location: time.UTC})
		if !okStart || !okEnd || !end.After(start) {
			return oofResponse("SetUserOofSettings", fmt.Errorf("%w: Scheduled requires a Duration whose EndTime follows StartTime", errEWSInvalidProperty), ""), nil
		}
		next.Enabled, next.Start, next.End = true, start, end
	default:
		return oofResponse("SetUserOofSettings", fmt.Errorf("%w: OofState must be Disabled, Enabled or Scheduled", errEWSInvalidProperty), ""), nil
	}
	internal := settings.child("InternalReply")
	external := settings.child("ExternalReply")
	if internal != nil || external != nil {
		message := oofMessage(internal)
		if message == "" {
			message = oofMessage(external)
		}
		next.Message = message
	}
	if err := h.setOutOfOffice(ctx, access.Actor.ID, next); err != nil {
		return oofResponse("SetUserOofSettings", err, ""), nil
	}
	return oofResponse("SetUserOofSettings", nil, ""), nil
}

// oofMessage reads a reply's Message, which clients send as HTML or text.
func oofMessage(reply *node) string {
	text := strings.TrimSpace(reply.descendantText("Message"))
	if strings.Contains(text, "<") && strings.Contains(text, ">") {
		text = strings.TrimSpace(service.HTMLToText(text))
	}
	return text
}
