package alertnotify

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lkarlslund/veksel/pkg/health"
	"github.com/lkarlslund/veksel/pkg/model"
)

// OutboundHoldMessage tells an account owner that their outbound mail is held
// as a suspected compromise. Its identity derives from the hold, so a
// re-admission after a crash is dropped as a duplicate.
func OutboundHoldMessage(account string, hold model.OutboundHold) Message {
	text := &strings.Builder{}
	fmt.Fprintf(text, "Outgoing mail from your account (%s) has been paused because it looks like someone else may be using it.\r\n\r\n", account)
	text.WriteString("Messages you send are kept on the server and are not delivered until an administrator has reviewed the account.\r\n\r\n")
	text.WriteString("If you did not send unusual amounts of mail recently, change your password and contact your administrator.\r\n")
	if len(hold.Signals) > 0 {
		fmt.Fprintf(text, "\r\nWhat was noticed: %s\r\n", strings.ReplaceAll(strings.Join(hold.Signals, ", "), "_", " "))
	}
	text.WriteString("\r\nThis message was sent automatically by Veksel.\r\n")
	return Message{
		ID: "outbound-hold-" + account + "-" + hold.Since.UTC().Format("20060102T150405"), Event: "outbound.hold",
		Subject: "Outgoing mail from your account is paused", Text: text.String(), Severity: health.SeverityCritical, At: hold.Since,
		Payload: map[string]any{"account_id": account, "score": strconv.FormatFloat(hold.Score, 'f', -1, 64), "signals": hold.Signals},
	}
}
