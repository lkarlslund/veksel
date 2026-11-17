package imap

import (
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/model"
)

// idleLine is one line read while a session is in IDLE.
type idleLine struct {
	line string
	err  error
}

// idleSafetySync is how often an IDLE session re-checks the selected
// mailbox on its own, covering changes that arrive without a notification.
var idleSafetySync = 30 * time.Second

// cmdIdle handles the IDLE command (RFC 2177).
//
// The client's DONE is read by a goroutine blocked on the connection rather
// than by polling with short read deadlines: a deadline that expires inside
// the COMPRESS=DEFLATE reader leaves the decompressor permanently failed,
// so a compressed session (Thunderbird's default) never saw DONE again.
func (s *Session) cmdIdle(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "IDLE does not accept arguments")
		return
	}
	if s.curState == stateIdle {
		return
	}

	previousState := s.curState
	s.curState = stateIdle

	// Register before the continuation so changes made elsewhere once the
	// client sees it are always delivered, then report what changed since
	// the last command, which covers everything woken so far.
	s.refreshWake()
	if touched, all := s.takeWake(); s.notify != nil && (all || len(touched) > 0) {
		s.reportNotifyFolders(touched, all)
	}
	s.syncView(true)
	s.sendContinuation("idling")

	// An idling client is waiting, not mid-command, so shutdown may close it.
	s.tracked.SetIdle(true)
	defer s.tracked.SetIdle(false)

	// IDLE timeout (30 minutes per RFC 2177 recommendation)
	const idleTimeout = 30 * time.Minute
	timeout := time.NewTimer(idleTimeout)
	defer timeout.Stop()
	safety := time.NewTicker(idleSafetySync)
	defer safety.Stop()

	if conn, ok := s.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout + time.Minute))
	}
	lines := make(chan idleLine, 1)
	go func() {
		// The DONE line is bounded like any command line.
		line, err := appendLineChunk(s.rw.Reader, nil)
		lines <- idleLine{line: string(line), err: err}
	}()

	// settle runs while a woken session waits for the rest of a burst.
	var settle <-chan time.Time
	completionText := "IDLE completed"
	sendCompletion := true
	for done := false; !done; {
		select {
		case read := <-lines:
			done = true
			switch {
			case read.err != nil:
				sendCompletion = false
			case strings.EqualFold(strings.TrimSpace(read.line), "DONE"):
				completionText = "IDLE completed"
			default:
				s.sendBAD(tag, "Expected DONE while IDLE")
				sendCompletion = false
			}
		case <-timeout.C:
			completionText = "IDLE terminated by server timeout"
			s.idleRead, done = lines, true
		case <-s.wakeSignal():
			if settle == nil {
				settle = time.After(wakeSettle)
			}
		case <-settle:
			settle = nil
			s.reportChanges()
		case <-safety.C:
			s.syncView(true)
		}
	}

	if previousState == stateSelected {
		s.curState = stateSelected
	} else {
		s.curState = stateAuthenticated
	}
	s.refreshWake()
	if sendCompletion {
		s.sendOK(tag, completionText)
	}
}

// pendingIdleLine returns the line an IDLE ended by the server was still
// reading. A DONE the client sent for it is dropped; anything else is the
// next command.
func (s *Session) pendingIdleLine() (string, bool, error) {
	if s.idleRead == nil {
		return "", false, nil
	}
	read := <-s.idleRead
	s.idleRead = nil
	if read.err != nil {
		return "", true, read.err
	}
	if strings.EqualFold(strings.TrimSpace(read.line), "DONE") {
		return "", false, nil
	}
	return strings.TrimRight(read.line, "\r\n"), true, nil
}

// expungeAll removes all items with \Deleted flag from the selected folder.
// EXPUNGE reports the removals through the view sync before its tagged
// completion; CLOSE deselects first and reports nothing (RFC 3501 6.4.2).
func (s *Session) expungeAll() {
	items, err := s.getSequenceItems()
	if err != nil {
		return
	}
	for seq := len(items); seq >= 1; seq-- {
		item := items[seq-1]
		if s.expungedPending(item.UID) || !hasFlagInsensitive(item, "\\Deleted") {
			continue
		}
		if err := s.cfg.FolderSpace.DeleteItem(*s.ctx, s.access(), item.ID); err != nil {
			continue
		}
		s.publish(s.selectedFolder)
	}
}

// hasFlagInsensitive checks if the item has the given flag, case-insensitively.
func hasFlagInsensitive(item model.Item, flag string) bool {
	flagUpper := strings.ToUpper(flag)
	for _, f := range item.Flags {
		if strings.ToUpper(f) == flagUpper {
			return true
		}
	}
	return false
}

// cmdExpunge handles the EXPUNGE command (RFC 3501).
func (s *Session) cmdExpunge(tag string, args []string) {
	if len(args) != 0 {
		s.sendBAD(tag, "EXPUNGE does not accept arguments")
		return
	}
	s.expungeAll()
	s.sendOK(tag, "EXPUNGE completed")
}
