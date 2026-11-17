package smtp

import "testing"

func TestParseMailDSNParameters(t *testing.T) {
	returnMode, envelopeID, requireTLS, err := parseMailParameters([]string{"SIZE=512", "BODY=8BITMIME", "SMTPUTF8", "RET=HDRS", "ENVID=case+2Bid", "REQUIRETLS"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if returnMode != "hdrs" || envelopeID != "case+2Bid" || !requireTLS {
		t.Fatalf("return=%q envelope=%q requireTLS=%v", returnMode, envelopeID, requireTLS)
	}
	for _, test := range [][]string{
		{"RET=BODY"}, {"ENVID=bad value"}, {"ENVID=bad+Q0"}, {"SIZE=2048"}, {"SMTPUTF8=yes"}, {"REQUIRETLS=yes"}, {"UNKNOWN=x"}, {"RET=FULL", "RET=HDRS"},
	} {
		if _, _, _, err := parseMailParameters(test, 1024); err == nil {
			t.Fatalf("parameters %#v accepted", test)
		}
	}
}

func TestParseRecipientDSNParameters(t *testing.T) {
	options, err := parseRecipientParameters([]string{"NOTIFY=SUCCESS,FAILURE,DELAY", "ORCPT=rfc822;Original+40Example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if options.notify != "success,failure,delay" || options.orcpt != "rfc822;Original+40Example.test" {
		t.Fatalf("options=%#v", options)
	}
	for _, test := range [][]string{
		{"NOTIFY=NEVER,FAILURE"}, {"NOTIFY=FAILURE,FAILURE"}, {"NOTIFY=UNKNOWN"}, {"ORCPT=missing-type"}, {"ORCPT=rfc822;bad value"}, {"OTHER=x"},
	} {
		if _, err := parseRecipientParameters(test); err == nil {
			t.Fatalf("parameters %#v accepted", test)
		}
	}
}

func TestSplitSMTPPathParameters(t *testing.T) {
	path, parameters, err := splitSMTPPathParameters("<sender@example.test> RET=FULL ENVID=id")
	if err != nil || path != "<sender@example.test>" || len(parameters) != 2 {
		t.Fatalf("path=%q parameters=%#v error=%v", path, parameters, err)
	}
	if _, _, err := splitSMTPPathParameters("<broken@example.test"); err == nil {
		t.Fatal("unterminated path accepted")
	}
}
