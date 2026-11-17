// Package doccheck verifies inexpensive relationships between current-state
// documentation and code-owned product contracts.
package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/lkarlslund/veksel/pkg/account"
	"github.com/lkarlslund/veksel/pkg/releasebuild"
)

var (
	markdownLink = regexp.MustCompile(`\[[^]]+\]\(([^)]+)\)`)
	codePath     = regexp.MustCompile("`((?:pkg|cmd)/[A-Za-z0-9_./-]+)`")
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve documentation test location")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestLicenseMetadataAgrees(t *testing.T) {
	root := repositoryRoot(t)
	license := read(t, filepath.Join(root, "LICENSE"))
	if !strings.HasPrefix(license, "MIT License\n") {
		t.Fatal("LICENSE is not the MIT license declared by the project")
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestTrackedDocumentationLinksResolve(t *testing.T) {
	root := repositoryRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, "README.md"))
	for _, file := range files {
		contents := read(t, file)
		for _, match := range markdownLink.FindAllStringSubmatch(contents, -1) {
			target := strings.Trim(match[1], "<>")
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
				continue
			}
			target = strings.SplitN(target, "#", 2)[0]
			if target == "" {
				continue
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(file), filepath.FromSlash(target))); err != nil {
				t.Errorf("%s: unresolved link %q", filepath.Base(file), match[1])
			}
		}
	}
}

func TestCurrentArchitectureReferencesExistingPackages(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{"README.md", "docs/index.md", "docs/architecture.md", "docs/protocol-handlers.md", "docs/storage.md", "docs/configuration.md", "docs/design-model.md", "docs/authorization.md", "docs/releases.md", "docs/features.md"} {
		contents := read(t, filepath.Join(root, filepath.FromSlash(name)))
		for _, match := range codePath.FindAllStringSubmatch(contents, -1) {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(match[1]))); err != nil {
				t.Errorf("%s: code path %q does not exist", name, match[1])
			}
		}
	}
}

func TestReleaseAndStorageSummariesFollowCodeOwnedCatalogs(t *testing.T) {
	root := repositoryRoot(t)
	releases := read(t, filepath.Join(root, "docs", "releases.md"))
	releasesLower := strings.ToLower(releases)
	for _, target := range releasebuild.Targets() {
		if !strings.Contains(releasesLower, target.GOOS) || !strings.Contains(releasesLower, target.GOARCH) {
			t.Errorf("release documentation omits %s/%s", target.GOOS, target.GOARCH)
		}
	}
	for _, variant := range releasebuild.Variants() {
		if !strings.Contains(releases, "`"+variant.Name+"`") {
			t.Errorf("release documentation omits variant %q", variant.Name)
		}
	}
	index := read(t, filepath.Join(root, "docs", "index.md"))
	for _, engine := range account.ProductionEngines {
		if !strings.Contains(strings.ToLower(index), string(engine)) {
			t.Errorf("documentation index omits production account engine %q", engine)
		}
	}
}

func TestImplementedPOP3IsNotPresentedAsPlanned(t *testing.T) {
	features := read(t, filepath.Join(repositoryRoot(t), "docs", "features.md"))
	parts := strings.SplitN(features, "## POP3 Handler", 2)
	if len(parts) != 2 {
		t.Fatal("feature roadmap omits the POP3 section")
	}
	section := strings.SplitN(parts[1], "\n## ", 2)[0]
	if strings.Contains(section, "🔜") || !strings.Contains(section, "| ✅ |") {
		t.Fatal("implemented POP3 capabilities are still presented as planned")
	}
}
