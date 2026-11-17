package service

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// htmlPolicy selects the rules for one sanitizer pass. The reader keeps
// remote images inert behind data-remote-src; outgoing composer HTML keeps
// cid: and http(s) image sources and never adds reader-only attributes.
type htmlPolicy struct {
	outgoing bool
}

// htmlSanitizer drops everything outside the allowlist; removed reports only
// active content (scripts, frames, forms, event handlers, script or
// resource-loading URLs and CSS) so the reader's "unsafe content" notice is
// not raised for the presentational markup every newsletter carries.
type htmlSanitizer struct {
	policy  htmlPolicy
	removed bool
	remote  bool
}

// safeEmailElements are kept with their (filtered) attributes; any other
// element is unwrapped and only its children survive.
var safeEmailElements = map[string]bool{
	"a": true, "b": true, "blockquote": true, "br": true, "caption": true, "code": true, "del": true, "div": true,
	"em": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "hr": true,
	"i": true, "img": true, "ins": true, "li": true, "ol": true, "p": true, "pre": true, "s": true, "small": true,
	"span": true, "strike": true, "strong": true, "sub": true, "sup": true, "table": true, "tbody": true,
	"td": true, "tfoot": true, "th": true, "thead": true, "tr": true, "u": true, "ul": true,
}

// droppedEmailElements are removed together with their content.
var droppedEmailElements = map[string]bool{
	"applet": true, "audio": true, "base": true, "button": true, "canvas": true, "embed": true, "form": true,
	"frame": true, "frameset": true, "head": true, "iframe": true, "input": true, "link": true, "math": true,
	"meta": true, "noscript": true, "object": true, "option": true, "script": true, "select": true, "style": true,
	"svg": true, "template": true, "textarea": true, "title": true, "video": true,
}

// activeEmailElements are the dropped elements that execute, embed, submit,
// or load content; dropping head, title, style, or meta is not worth a notice.
var activeEmailElements = map[string]bool{
	"applet": true, "audio": true, "base": true, "button": true, "canvas": true, "embed": true, "form": true,
	"frame": true, "frameset": true, "iframe": true, "input": true, "link": true, "math": true, "object": true,
	"script": true, "select": true, "svg": true, "template": true, "textarea": true, "video": true,
}

// safeCSSProperties are presentational declarations allowed in style
// attributes. Positioning, display, overflow, and anything that can load a
// resource are excluded so message content cannot overlay the application.
var safeCSSProperties = map[string]bool{
	"background-color": true, "border": true, "border-bottom": true, "border-collapse": true, "border-color": true,
	"border-left": true, "border-radius": true, "border-right": true, "border-spacing": true, "border-style": true,
	"border-top": true, "border-width": true, "color": true, "direction": true, "font-family": true, "font-size": true,
	"font-style": true, "font-variant": true, "font-weight": true, "height": true, "letter-spacing": true,
	"line-height": true, "list-style-type": true, "margin": true, "margin-bottom": true, "margin-left": true,
	"margin-right": true, "margin-top": true, "max-width": true, "min-width": true, "padding": true,
	"padding-bottom": true, "padding-left": true, "padding-right": true, "padding-top": true, "text-align": true,
	"text-decoration": true, "text-decoration-color": true, "text-decoration-line": true, "text-indent": true,
	"text-transform": true, "vertical-align": true, "white-space": true, "width": true,
}

var (
	safeCSSValue     = regexp.MustCompile(`^[a-zA-Z0-9 #.,%()'"+/\-]*$`)
	negativeCSSValue = regexp.MustCompile(`(^|[\s(,])-(\d|\.\d)`)
	cssDigits        = regexp.MustCompile(`^\d{1,4}$`)
	dataImageSource  = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\s]+$`)
)

// sanitizeEmailHTML prepares received HTML for the reader. It reports whether
// unsafe content was removed and whether remote images were blocked.
func sanitizeEmailHTML(input string) (string, bool, bool) {
	sanitizer := &htmlSanitizer{}
	output := sanitizer.run(input)
	return output, sanitizer.removed, sanitizer.remote
}

// SanitizeComposeHTML applies the outgoing allowlist to HTML submitted by the
// web composer or stored as a signature: no scripts, forms, event handlers,
// remote frames, or resource-loading CSS survive.
func SanitizeComposeHTML(input string) string {
	sanitizer := &htmlSanitizer{policy: htmlPolicy{outgoing: true}}
	return strings.TrimSpace(sanitizer.run(input))
}

func (s *htmlSanitizer) run(input string) string {
	contextNode := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := html.ParseFragment(strings.NewReader(input), contextNode)
	if err != nil {
		s.removed = true
		return html.EscapeString(input)
	}
	var output strings.Builder
	for _, node := range nodes {
		for _, safe := range s.node(node) {
			_ = html.Render(&output, safe)
		}
	}
	return output.String()
}

func (s *htmlSanitizer) node(node *html.Node) []*html.Node {
	switch node.Type {
	case html.TextNode:
		return []*html.Node{{Type: html.TextNode, Data: node.Data}}
	case html.ElementNode:
	default:
		return nil
	}
	name := strings.ToLower(node.Data)
	if droppedEmailElements[name] {
		s.removed = s.removed || activeEmailElements[name] || name == "meta" && hasAttribute(node, "http-equiv")
		return nil
	}
	children := make([]*html.Node, 0)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		children = append(children, s.node(child)...)
	}
	if name == "font" {
		return s.font(node, children)
	}
	if !safeEmailElements[name] {
		s.flagActiveAttributes(node)
		return children
	}
	clean := &html.Node{Type: html.ElementNode, Data: name}
	if name == "img" {
		if !s.image(node, clean) {
			return nil
		}
		return []*html.Node{clean}
	}
	for _, attribute := range node.Attr {
		key, value := strings.ToLower(attribute.Key), attribute.Val
		switch {
		case name == "a" && key == "href" && safeEmailLink(value):
			clean.Attr = append(clean.Attr, html.Attribute{Key: "href", Val: strings.TrimSpace(value)})
		case key == "title":
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: value})
		case (name == "td" || name == "th") && (key == "colspan" || key == "rowspan") && cssDigits.MatchString(value):
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: value})
		case name == "ol" && key == "start" && cssDigits.MatchString(value):
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: value})
		case name == "blockquote" && key == "type" && strings.EqualFold(value, "cite"):
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: "cite"})
		case key == "dir" && (value == "ltr" || value == "rtl" || value == "auto"):
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: value})
		case key == "style":
			s.style(clean, value)
		default:
			s.flagActiveAttribute(key, value)
		}
	}
	if name == "a" && !s.policy.outgoing {
		clean.Attr = append(clean.Attr, html.Attribute{Key: "rel", Val: "nofollow noopener noreferrer"})
	}
	for _, child := range children {
		clean.AppendChild(child)
	}
	return []*html.Node{clean}
}

// image keeps cid: references in both policies. Remote sources stay inert
// in the reader (data-remote-src) until the user shows them, and are kept as
// written in outgoing mail. Inline data: images are kept only by the reader;
// the composer turns them into Content-ID parts before submission.
func (s *htmlSanitizer) image(node, clean *html.Node) bool {
	source := ""
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, "src") {
			source = strings.TrimSpace(attribute.Val)
		}
	}
	lower := strings.ToLower(source)
	if strings.HasPrefix(lower, "//") {
		source, lower = "https:"+source, "https:"+lower
	}
	switch {
	case strings.HasPrefix(lower, "cid:") && len(source) > 4:
		clean.Attr = append(clean.Attr, html.Attribute{Key: "src", Val: source})
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		if _, err := url.Parse(source); err != nil {
			s.removed = true
			return false
		}
		if s.policy.outgoing {
			clean.Attr = append(clean.Attr, html.Attribute{Key: "src", Val: source})
		} else {
			s.remote = true
			clean.Attr = append(clean.Attr, html.Attribute{Key: "data-remote-src", Val: source})
		}
	case !s.policy.outgoing && dataImageSource.MatchString(source):
		clean.Attr = append(clean.Attr, html.Attribute{Key: "src", Val: source})
	default:
		s.removed = s.removed || source != ""
		return false
	}
	for _, attribute := range node.Attr {
		key, value := strings.ToLower(attribute.Key), attribute.Val
		switch {
		case key == "src":
		case key == "alt" || key == "title":
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: value})
		case (key == "width" || key == "height") && cssDigits.MatchString(value):
			clean.Attr = append(clean.Attr, html.Attribute{Key: key, Val: value})
		case key == "style":
			s.style(clean, value)
		default:
			s.flagActiveAttribute(key, value)
		}
	}
	return true
}

func hasAttribute(node *html.Node, key string) bool {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, key) {
			return true
		}
	}
	return false
}

func (s *htmlSanitizer) flagActiveAttributes(node *html.Node) {
	for _, attribute := range node.Attr {
		s.flagActiveAttribute(strings.ToLower(attribute.Key), attribute.Val)
	}
}

// flagActiveAttribute records a dropped attribute that would have run script
// or loaded content; layout attributes such as class, border, or bgcolor are
// dropped silently.
func (s *htmlSanitizer) flagActiveAttribute(key, value string) {
	switch {
	case strings.HasPrefix(key, "on"), key == "srcdoc", key == "formaction", key == "action":
		s.removed = true
	case key == "href" || key == "src" || key == "background" || key == "xlink:href":
		scheme, _, found := strings.Cut(strings.ToLower(strings.TrimSpace(value)), ":")
		s.removed = s.removed || found && (scheme == "javascript" || scheme == "vbscript" || scheme == "data")
	case key == "style":
		if _, active := sanitizeCSS(value); active {
			s.removed = true
		}
	}
}

// font converts legacy <font> markup into a styled span.
func (s *htmlSanitizer) font(node *html.Node, children []*html.Node) []*html.Node {
	sizes := map[string]string{"1": "x-small", "2": "small", "3": "medium", "4": "large", "5": "x-large", "6": "xx-large", "7": "xxx-large"}
	var declarations []string
	for _, attribute := range node.Attr {
		switch strings.ToLower(attribute.Key) {
		case "color":
			declarations = append(declarations, "color: "+attribute.Val)
		case "face":
			declarations = append(declarations, "font-family: "+attribute.Val)
		case "size":
			if size := sizes[strings.TrimSpace(attribute.Val)]; size != "" {
				declarations = append(declarations, "font-size: "+size)
			}
		case "style":
			declarations = append(declarations, attribute.Val)
		}
	}
	clean := &html.Node{Type: html.ElementNode, Data: "span", DataAtom: atom.Span}
	s.style(clean, strings.Join(declarations, ";"))
	if len(clean.Attr) == 0 {
		return children
	}
	for _, child := range children {
		clean.AppendChild(child)
	}
	return []*html.Node{clean}
}

func (s *htmlSanitizer) style(clean *html.Node, value string) {
	safe, active := sanitizeCSS(value)
	if active {
		s.removed = true
	}
	if safe != "" {
		clean.Attr = append(clean.Attr, html.Attribute{Key: "style", Val: safe})
	}
}

// sanitizeCSS keeps allowlisted declarations whose values cannot load
// resources, call functions other than colors, or shift content outside its
// box. It reports whether a dropped declaration was active: one that loads a
// resource or runs script, as opposed to a merely unsupported layout rule.
func sanitizeCSS(value string) (string, bool) {
	var kept []string
	active := false
	for _, declaration := range strings.Split(value, ";") {
		if strings.TrimSpace(declaration) == "" {
			continue
		}
		property, raw, ok := strings.Cut(declaration, ":")
		property = strings.ToLower(strings.TrimSpace(property))
		raw = strings.TrimSpace(raw)
		lower := strings.ToLower(raw)
		if !ok || !safeCSSProperties[property] || raw == "" || len(raw) > 200 || !safeCSSValue.MatchString(raw) ||
			negativeCSSValue.MatchString(raw) || cssCallsUnsafeFunction(lower) {
			active = active || cssLoadsOrRuns(strings.ToLower(declaration))
			continue
		}
		kept = append(kept, property+": "+raw)
	}
	return strings.Join(kept, "; "), active
}

func cssLoadsOrRuns(declaration string) bool {
	for _, marker := range []string{"url(", "image-set(", "expression(", "javascript:", "@import", "behavior", "-moz-binding"} {
		if strings.Contains(declaration, marker) {
			return true
		}
	}
	return false
}

func cssCallsUnsafeFunction(value string) bool {
	rest := value
	for {
		open := strings.IndexByte(rest, '(')
		if open < 0 {
			return false
		}
		start := open
		for start > 0 && (rest[start-1] >= 'a' && rest[start-1] <= 'z' || rest[start-1] == '-') {
			start--
		}
		switch rest[start:open] {
		case "rgb", "rgba", "hsl", "hsla":
		default:
			return true
		}
		rest = rest[open+1:]
	}
}

func safeEmailLink(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "mailto":
		return true
	default:
		return false
	}
}
