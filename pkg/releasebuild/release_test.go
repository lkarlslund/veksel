package releasebuild

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestReleaseMatrixIsCompleteAndUnique(t *testing.T) {
	matrix := ReleaseMatrix()
	if err := ValidateMatrix(matrix, true); err != nil {
		t.Fatal(err)
	}
	if got, want := len(matrix.Include), len(Targets())*len(Variants()); got != want || got != 48 {
		t.Fatalf("release matrix entries = %d, want %d", got, want)
	}
	for _, target := range Targets() {
		for _, variant := range Variants() {
			if !slices.Contains(matrix.Include, MatrixEntry{GOOS: target.GOOS, GOARCH: target.GOARCH, Variant: variant.Name}) {
				t.Fatalf("release matrix omits %s/%s %s", target.GOOS, target.GOARCH, variant.Name)
			}
		}
	}
}

func TestCIMatrixCoversEveryOSAndFeatureVariant(t *testing.T) {
	matrix := CIMatrix()
	if err := ValidateMatrix(matrix, false); err != nil {
		t.Fatal(err)
	}
	operatingSystems := make(map[string]bool)
	variantNames := make(map[string]bool)
	for _, entry := range matrix.Include {
		operatingSystems[entry.GOOS] = true
		variantNames[entry.Variant] = true
	}
	for _, target := range Targets() {
		if !operatingSystems[target.GOOS] {
			t.Errorf("CI matrix does not cover %s", target.GOOS)
		}
	}
	for _, variant := range Variants() {
		if !variantNames[variant.Name] {
			t.Errorf("CI matrix does not cover %s", variant.Name)
		}
	}
}

func TestNextTagAllocatesAndReusesWorkflowRun(t *testing.T) {
	refs := []TagRef{
		{Name: "v1.0.0", Subject: "not a periodic release"},
		{Name: "r0002", Subject: "Veksel r0002; veksel-run-id=41"},
		{Name: "r0099", Subject: "Veksel r0099; veksel-run-id=42"},
		{Name: "rbroken", Subject: "ignored"},
	}
	tag, reused, err := NextTag(refs, "43")
	if err != nil || tag != "r0100" || reused {
		t.Fatalf("NextTag new = %q, %v, %v", tag, reused, err)
	}
	tag, reused, err = NextTag(refs, "42")
	if err != nil || tag != "r0099" || !reused {
		t.Fatalf("NextTag rerun = %q, %v, %v", tag, reused, err)
	}
	tag, reused, err = NextTag([]TagRef{{Name: "r0001", Subject: "Veksel r0001; veksel-run-id=420; veksel-go=1.26.6"}}, "42")
	if err != nil || tag != "r0002" || reused {
		t.Fatalf("NextTag prefix collision = %q, %v, %v", tag, reused, err)
	}
}

func TestTagSubjectRoundTrip(t *testing.T) {
	subject, err := TagSubject("r0042", "12345", "go1.26.6")
	if err != nil {
		t.Fatal(err)
	}
	goVersion, err := TagGoVersion(subject, "12345")
	if err != nil || goVersion != "1.26.6" {
		t.Fatalf("TagGoVersion = %q, %v", goVersion, err)
	}
	if _, err := TagGoVersion(subject, "999"); err == nil {
		t.Fatal("TagGoVersion accepted a different workflow run")
	}
}

func TestNextTagRejectsInvalidRunID(t *testing.T) {
	for _, runID := range []string{"", "a\nb", "a\tb"} {
		if _, _, err := NextTag(nil, runID); err == nil {
			t.Errorf("NextTag accepted run ID %q", runID)
		}
	}
}

func TestArtifactNamesExposePlatformAndFeatures(t *testing.T) {
	tests := []struct {
		goos, arch, variant, want string
	}{
		{"linux", "amd64", "full", "veksel_r0007_linux_amd64_full.tar.gz"},
		{"windows", "arm64", "noexchange", "veksel_r0007_windows_arm64_noexchange.zip"},
	}
	for _, test := range tests {
		got, err := ArtifactName("r0007", test.goos, test.arch, test.variant)
		if err != nil || got != test.want {
			t.Errorf("ArtifactName(%s/%s %s) = %q, %v; want %q", test.goos, test.arch, test.variant, got, err, test.want)
		}
	}
	for _, invalid := range []struct{ tag, goos, arch, variant string }{
		{"v1", "linux", "amd64", "full"},
		{"r0001", "plan9", "amd64", "full"},
		{"r0001", "linux", "amd64", "unknown"},
	} {
		if _, err := ArtifactName(invalid.tag, invalid.goos, invalid.arch, invalid.variant); err == nil {
			t.Errorf("ArtifactName accepted %+v", invalid)
		}
	}
}

func TestWriteArchiveIsDeterministicAndPreservesExecutable(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "source")
	if err := os.WriteFile(binary, []byte("binary-data"), 0o755); err != nil {
		t.Fatal(err)
	}
	modified := time.Date(2026, 8, 18, 12, 34, 56, 0, time.UTC)
	info := []byte("{\"tag\":\"r0001\"}\n")
	for _, extension := range []string{".tar.gz", ".zip"} {
		first := filepath.Join(root, "first"+extension)
		second := filepath.Join(root, "second"+extension)
		if err := writeArchive(first, "veksel", binary, info, modified); err != nil {
			t.Fatal(err)
		}
		if err := writeArchive(second, "veksel", binary, info, modified); err != nil {
			t.Fatal(err)
		}
		firstHash, _, _ := fileDigest(first)
		secondHash, _, _ := fileDigest(second)
		if firstHash != secondHash {
			t.Errorf("%s archive is not deterministic", extension)
		}
		mode, embeddedInfo := archiveContents(t, first)
		if mode&0o111 == 0 {
			t.Errorf("%s binary mode = %v, want executable", extension, mode)
		}
		if string(embeddedInfo) != string(info) {
			t.Errorf("%s build info = %q, want %q", extension, embeddedInfo, info)
		}
	}
}

func archiveContents(t *testing.T, path string) (os.FileMode, []byte) {
	t.Helper()
	if strings.HasSuffix(path, ".zip") {
		reader, err := zip.OpenReader(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reader.Close() }()
		var mode os.FileMode
		var info []byte
		for _, file := range reader.File {
			input, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(input)
			_ = input.Close()
			if err != nil {
				t.Fatal(err)
			}
			switch file.Name {
			case "veksel":
				mode = file.Mode()
			case buildInfoName:
				info = data
			}
		}
		return mode, info
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	gzipReader, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	var mode os.FileMode
	var info []byte
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		switch header.Name {
		case "veksel":
			mode = os.FileMode(header.Mode)
		case buildInfoName:
			info = data
		}
	}
	return mode, info
}

func TestAssembleVerifiesCompleteRelease(t *testing.T) {
	input := t.TempDir()
	output := filepath.Join(t.TempDir(), "assets")
	manifestWant := writeFakeParts(t, input)
	manifest, err := Assemble(input, output)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 48 || manifest.Tag != manifestWant.Tag {
		t.Fatalf("manifest = %#v", manifest)
	}
	if err := ValidateChecksums(output); err != nil {
		t.Fatal(err)
	}
	names, err := ExpectedAssetNames(manifest.Tag)
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	gotNames := make([]string, 0, len(files))
	for _, file := range files {
		gotNames = append(gotNames, file.Name())
	}
	if !slices.Equal(gotNames, names) {
		t.Fatalf("asset names = %v, want %v", gotNames, names)
	}
	actual := filepath.Join(t.TempDir(), "download")
	if err := os.Mkdir(actual, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if err := copyFile(filepath.Join(output, file.Name()), filepath.Join(actual, file.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyAssets(output, actual); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, names[0]), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAssets(output, actual); err == nil {
		t.Fatal("VerifyAssets accepted tampered content")
	}
}

func TestAssembleRejectsMissingAndTamperedParts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"missing", func(t *testing.T, input string) {
			files, _ := filepath.Glob(filepath.Join(input, "*.fragment.json"))
			if err := os.Remove(files[0]); err != nil {
				t.Fatal(err)
			}
		}},
		{"tampered", func(t *testing.T, input string) {
			files, _ := filepath.Glob(filepath.Join(input, "*.tar.gz"))
			if err := os.WriteFile(files[0], []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := t.TempDir()
			writeFakeParts(t, input)
			test.mutate(t, input)
			if _, err := Assemble(input, filepath.Join(t.TempDir(), "assets")); err == nil {
				t.Fatal("Assemble accepted invalid parts")
			}
		})
	}
}

func writeFakeParts(t *testing.T, directory string) Manifest {
	t.Helper()
	manifest := Manifest{SchemaVersion: ManifestSchema, Tag: "r0042", Commit: strings.Repeat("a", 40), BuiltAt: "2026-08-18T12:34:56Z", GoVersion: "go1.26.0", WorkflowRunID: "12345"}
	binaryPath := filepath.Join(directory, ".test-binary")
	if err := os.WriteFile(binaryPath, []byte("test release binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	binaryDigest, _, err := fileDigest(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	modified := time.Date(2026, 8, 18, 12, 34, 56, 0, time.UTC)
	for _, entry := range ReleaseMatrix().Include {
		name, err := ArtifactName(manifest.Tag, entry.GOOS, entry.GOARCH, entry.Variant)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		variant, _ := VariantByName(entry.Variant)
		info := BuildInfo{SchemaVersion: manifest.SchemaVersion, Tag: manifest.Tag, Commit: manifest.Commit, BuiltAt: manifest.BuiltAt, GoVersion: manifest.GoVersion, WorkflowRunID: manifest.WorkflowRunID, GOOS: entry.GOOS, GOARCH: entry.GOARCH, Variant: entry.Variant, BuildTags: variant.BuildTags, Features: variant.Features, BinarySHA256: binaryDigest}
		infoData, err := marshalJSON(info)
		if err != nil {
			t.Fatal(err)
		}
		archivedBinary := "veksel"
		if entry.GOOS == "windows" {
			archivedBinary = "veksel.exe"
		}
		if err := writeArchive(path, archivedBinary, binaryPath, infoData, modified); err != nil {
			t.Fatal(err)
		}
		digest, size, err := fileDigest(path)
		if err != nil {
			t.Fatal(err)
		}
		artifact := Artifact{Name: name, GOOS: entry.GOOS, GOARCH: entry.GOARCH, Variant: entry.Variant, BuildTags: variant.BuildTags, Features: variant.Features, SHA256: digest, BinarySHA256: binaryDigest, Size: size}
		fragment := Fragment{SchemaVersion: manifest.SchemaVersion, Tag: manifest.Tag, Commit: manifest.Commit, BuiltAt: manifest.BuiltAt, GoVersion: manifest.GoVersion, WorkflowRunID: manifest.WorkflowRunID, Artifact: artifact}
		encoded, err := json.Marshal(fragment)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".fragment.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	return manifest
}
