package panel

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
)

// Permit only the exact trusted inline scripts shipped with the standalone
// consoles. The old script-src 'self' silently blocked their buttons; using
// 'unsafe-inline' would unnecessarily weaken protection against injection.
var inlineScripts = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
var adminInlineScriptHashes = scriptHashes(sentinelHTML, killswitchHTML)

func scriptHashes(pages ...string) string {
	var sources []string
	for _, page := range pages {
		for _, match := range inlineScripts.FindAllStringSubmatch(page, -1) {
			sum := sha256.Sum256([]byte(match[1]))
			sources = append(sources, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
		}
	}
	if len(sources) == 0 {
		return ""
	}
	return " " + strings.Join(sources, " ")
}
