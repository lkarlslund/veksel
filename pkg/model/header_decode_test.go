package model

import "testing"

func TestDecodeHeaderValueCharsets(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"windows-1252 Q", "=?Windows-1252?Q?Example_Ltd_=96_tilbud_p=E5_timer?=", "Example Ltd – tilbud på timer"},
		{"windows-1252 B", "=?windows-1252?B?UmU6IE5ldyBvcHBvcnR1bml0eSCXIGRlc2lnbg==?=", "Re: New opportunity — design"},
		{"adjacent words across a fold", "=?Windows-1252?Q?Re:_New_opportunity_=97_Active_Directory_Design_Authorit?=\r\n =?Windows-1252?Q?y_/_Senior_AD_Architect?=", "Re: New opportunity — Active Directory Design Authority / Senior AD Architect"},
		{"iso-8859-15", "=?iso-8859-15?Q?Pris_=A4_10?=", "Pris € 10"},
		{"utf-8", "=?UTF-8?Q?bl=C3=A5b=C3=A6r?=", "blåbær"},
		{"plain", "Plain subject", "Plain subject"},
		{"unknown charset kept raw", "=?x-unknown?Q?abc?=", "=?x-unknown?Q?abc?="},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DecodeHeaderValue(test.raw); got != test.want {
				t.Fatalf("DecodeHeaderValue(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}
