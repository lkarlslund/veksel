package service

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var (
	textWhitespace   = regexp.MustCompile(`[ \t\r\n\f]+`)
	textBlankLines   = regexp.MustCompile(`\n{3,}`)
	textBlockElement = map[string]bool{
		"address": true, "article": true, "caption": true, "div": true, "dl": true, "dt": true, "dd": true, "figure": true,
		"footer": true, "header": true, "ol": true, "section": true, "table": true, "tr": true, "ul": true,
	}
	textParagraphElement = map[string]bool{"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "p": true, "pre": true}
)

// HTMLToText renders composer HTML as the text/plain alternative: paragraphs
// and line breaks are kept, lists get markers, quotes get "> " prefixes, and
// links keep their target after the label.
func HTMLToText(input string) string {
	contextNode := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := html.ParseFragment(strings.NewReader(input), contextNode)
	if err != nil {
		return strings.TrimSpace(input)
	}
	var builder strings.Builder
	for _, node := range nodes {
		builder.WriteString(textOf(node, false))
	}
	return tidyText(builder.String())
}

// textOf renders one node. Preformatted whitespace is carried as NBSP and
// U+2028 so tidyText can collapse markup whitespace without touching it.
func textOf(node *html.Node, pre bool) string {
	switch node.Type {
	case html.TextNode:
		if pre {
			return strings.NewReplacer(" ", " ", "\n", " ").Replace(node.Data)
		}
		return textWhitespace.ReplaceAllString(node.Data, " ")
	case html.ElementNode:
	default:
		return ""
	}
	name := strings.ToLower(node.Data)
	if droppedEmailElements[name] {
		return ""
	}
	children := func(pre bool) string {
		var builder strings.Builder
		index := 0
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if child.Type == html.ElementNode && strings.EqualFold(child.Data, "li") {
				index++
				marker := "- "
				if name == "ol" {
					marker = strconv.Itoa(index) + ". "
				}
				builder.WriteString(marker + strings.TrimSpace(tidyText(textOf(child, pre))) + "\n")
				continue
			}
			builder.WriteString(textOf(child, pre))
		}
		return builder.String()
	}
	switch {
	case name == "br":
		return "\n"
	case name == "hr":
		return "\n----\n"
	case name == "img":
		if alt := strings.TrimSpace(attribute(node, "alt")); alt != "" {
			return "[" + alt + "]"
		}
		return ""
	case name == "a":
		label, href := children(pre), strings.TrimSpace(attribute(node, "href"))
		target := strings.TrimPrefix(href, "mailto:")
		if href == "" || strings.Contains(label, target) {
			return label
		}
		return label + " <" + href + ">"
	case name == "blockquote":
		lines := strings.Split(tidyText(children(pre)), "\n")
		for index, line := range lines {
			if line == "" {
				lines[index] = ">"
			} else {
				lines[index] = "> " + line
			}
		}
		return "\n\n" + strings.Join(lines, "\n") + "\n\n"
	case name == "td" || name == "th":
		return children(pre) + " "
	case textParagraphElement[name]:
		return "\n\n" + children(pre || name == "pre") + "\n\n"
	case textBlockElement[name]:
		return "\n" + children(pre) + "\n"
	default:
		return children(pre)
	}
}

func tidyText(value string) string {
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		lines[index] = strings.Trim(line, " \t\r")
	}
	value = textBlankLines.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
	return strings.Trim(strings.NewReplacer(" ", " ", " ", "\n").Replace(strings.Trim(value, " \t\r\n")), "\n")
}

func attribute(node *html.Node, key string) string {
	for _, candidate := range node.Attr {
		if strings.EqualFold(candidate.Key, key) {
			return candidate.Val
		}
	}
	return ""
}
