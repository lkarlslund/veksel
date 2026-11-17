package events

import "testing"

func TestHubScopesEventsAndCancellation(t *testing.T) {
	hub := NewHub()
	alice, cancelAlice := hub.Subscribe("alice")
	bob, cancelBob := hub.Subscribe("bob")
	defer cancelBob()
	hub.Publish(Event{Type: "folder.changed", Recipients: []string{"alice", "alice"}})
	select {
	case event := <-alice:
		if event.Type != "folder.changed" || event.OccurredAt.IsZero() {
			t.Fatalf("event = %#v", event)
		}
	default:
		t.Fatal("Alice did not receive targeted event")
	}
	select {
	case event := <-bob:
		t.Fatalf("Bob received Alice event: %#v", event)
	default:
	}
	cancelAlice()
	if _, open := <-alice; open {
		t.Fatal("subscription remained open after cancellation")
	}
}
