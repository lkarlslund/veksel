package autodiscover

import (
	"strconv"
	"strings"
)

// extractPort extracts the port from an address like ":587" or "127.0.0.1:587".
// Returns 0 if the address is empty or the port cannot be parsed.
func extractPort(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0
	}
	// Find the last colon
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return 0
	}
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0
	}
	return port
}
