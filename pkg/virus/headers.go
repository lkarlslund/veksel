package virus

// AddVirusHeaders adds X-Virus-Scanned and X-Virus-Status headers to the
// headers map based on the scan result.
//
// When scanned (regardless of result):
//
//	X-Virus-Scanned: Veksel
//
// When clean:
//
//	X-Virus-Status: Clean
//
// When infected:
//
//	X-Virus-Status: Infected/VirusName
func AddVirusHeaders(headers map[string]string, virusName string, infected bool) {
	headers["X-Virus-Scanned"] = "Veksel"
	if infected && virusName != "" {
		headers["X-Virus-Status"] = "Infected/" + virusName
	} else {
		headers["X-Virus-Status"] = "Clean"
	}
}
