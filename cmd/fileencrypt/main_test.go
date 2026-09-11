package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/feifangit/file-encryption/internal/crypttool"
)

func TestExtensionSetDefaultsAndReplacement(t *testing.T) {
	defaults, err := extensionSet(crypttool.Encrypt, cliOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaults[".jpg"]; !ok {
		t.Fatal("default image extensions were not selected")
	}

	replaced, err := extensionSet(crypttool.Encrypt, cliOptions{
		only:    []string{".md,.wav"},
		include: []string{".PNG"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".md", ".wav", ".png"} {
		if _, ok := replaced[ext]; !ok {
			t.Fatalf("%s missing from %#v", ext, replaced)
		}
	}
	if _, ok := replaced[".jpg"]; ok {
		t.Fatal("replacement unexpectedly retained a default extension")
	}
}

func TestExtensionPolicyPriority(t *testing.T) {
	config := crypttool.ExtensionConfig{
		Extensions: []string{".md", ".png"},
		Exclude:    []string{"Public", "资料/共享.md"},
	}

	fromConfig, err := resolveExtensionPolicy(
		crypttool.Encrypt,
		cliOptions{include: []string{".wav"}},
		config,
		"/vault/.ageconfig",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".md", ".png", ".wav"} {
		if _, ok := fromConfig.extensions[ext]; !ok {
			t.Fatalf("%s missing from config policy %#v", ext, fromConfig.extensions)
		}
	}
	if _, ok := fromConfig.extensions[".jpg"]; ok {
		t.Fatal("built-in default leaked into config policy")
	}
	if strings.Join(fromConfig.exclude, ",") != "Public,资料/共享.md" {
		t.Fatalf("config exclusions missing: %#v", fromConfig.exclude)
	}

	fromFlag, err := resolveExtensionPolicy(
		crypttool.Encrypt,
		cliOptions{only: []string{".pdf"}},
		config,
		"/vault/.ageconfig",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromFlag.extensions) != 1 {
		t.Fatalf("--ext did not replace config: %#v", fromFlag.extensions)
	}
	if _, ok := fromFlag.extensions[".pdf"]; !ok {
		t.Fatal("--ext selection missing")
	}
	if strings.Join(fromFlag.exclude, ",") != "Public,资料/共享.md" {
		t.Fatalf("--ext unexpectedly removed config exclusions: %#v", fromFlag.exclude)
	}
}

func TestPreviewCommandUsesConfigAndDoesNotModifyFiles(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"note.md":                     "note",
		"Public/skip.md":              "skip",
		"manual.pdf":                  "pdf",
		"image.png.age":               "encrypted-placeholder",
		crypttool.ExtensionConfigName: `{"extensions":[".md"],"exclude":["Public"]}`,
	}
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var output bytes.Buffer
	if code := run([]string{"preview", root}, &output); code != 0 {
		t.Fatalf("preview exit=%d\n%s", code, output.String())
	}
	for _, want := range []string{
		"PREVIEW",
		".ageconfig",
		"Excluded paths: Public",
		"FILE TYPE STATISTICS",
		"Would encrypt: 1 file(s)",
		"Would skip: 2 scanned regular file(s)",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("redirected preview output contains ANSI escapes:\n%s", output.String())
	}
	for name, content := range files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != content {
			t.Fatalf("preview modified %s: content=%q err=%v", name, got, err)
		}
	}
}

func TestPreviewExplicitExtCannotBypassInvalidConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, crypttool.ExtensionConfigName), []byte(`{"extensions":["all"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "note.md"), []byte("note"), 0o600); err != nil {
		t.Fatal(err)
	}

	var withoutOverride bytes.Buffer
	if code := run([]string{"preview", root}, &withoutOverride); code != 2 {
		t.Fatalf("invalid config exit=%d, want 2\n%s", code, withoutOverride.String())
	}

	var withOverride bytes.Buffer
	if code := run([]string{"preview", "--ext", ".md", root}, &withOverride); code != 2 {
		t.Fatalf("override exit=%d, want 2\n%s", code, withOverride.String())
	}
	if !strings.Contains(withOverride.String(), "extensions cannot contain all or *") {
		t.Fatalf("unexpected override output:\n%s", withOverride.String())
	}
}

func TestAllExtensionSelection(t *testing.T) {
	all, err := extensionSet(crypttool.Decrypt, cliOptions{only: []string{"all"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := all["*"]; !ok {
		t.Fatalf("all selection missing wildcard: %#v", all)
	}
	if _, err := extensionSet(crypttool.Encrypt, cliOptions{only: []string{"all"}}); err == nil {
		t.Fatal("encrypt should reject an unrestricted all-files selection")
	}
}

func TestReplacementInputIsCommaSeparated(t *testing.T) {
	set, err := replacementExtensionSet(".md, .wav", crypttool.Encrypt)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("unexpected replacement: %#v", set)
	}
}
