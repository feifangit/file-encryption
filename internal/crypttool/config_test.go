package crypttool

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadExtensionConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ExtensionConfigName)
	if err := os.WriteFile(path, []byte(`{"extensions":["MD",".png",".MD","wav"],"exclude":[" Public/ ","资料\\共享","Public"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	config, gotPath, found, err := LoadExtensionConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if !found || gotPath != path {
		t.Fatalf("found=%v path=%q, want true %q", found, gotPath, path)
	}
	want := []string{".md", ".png", ".wav"}
	if !reflect.DeepEqual(config.Extensions, want) {
		t.Fatalf("extensions=%#v, want %#v", config.Extensions, want)
	}
	wantExclude := []string{"Public", "资料/共享"}
	if !reflect.DeepEqual(config.Exclude, wantExclude) {
		t.Fatalf("exclude=%#v, want %#v", config.Exclude, wantExclude)
	}
}

func TestLoadExtensionConfigMissing(t *testing.T) {
	root := t.TempDir()
	_, path, found, err := LoadExtensionConfig(root)
	if err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if path != filepath.Join(root, ExtensionConfigName) {
		t.Fatalf("path=%q", path)
	}
}

func TestLoadExtensionConfigUsesDefaultsWhenExtensionsAreOmitted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ExtensionConfigName)
	if err := os.WriteFile(path, []byte(`{"exclude":["Public","资料/共享.md"]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	config, _, found, err := LoadExtensionConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("config was not found")
	}
	wantExtensions, err := ValidateExtensionList(DefaultExtensions)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.Extensions, wantExtensions) {
		t.Fatalf("extensions=%#v, want defaults %#v", config.Extensions, wantExtensions)
	}
	if want := []string{"Public", "资料/共享.md"}; !reflect.DeepEqual(config.Exclude, want) {
		t.Fatalf("exclude=%#v, want %#v", config.Exclude, want)
	}
}

func TestLoadExtensionConfigRejectsUnsafeValues(t *testing.T) {
	for _, content := range []string{
		`{"extensions":[]}`,
		`{"extensions":["all"]}`,
		`{"extensions":[".age"]}`,
		`{"extensions":[".tar.gz"]}`,
		`{"extensions":["../md"]}`,
		`{"extensions":[".md"],"password":"secret"}`,
		`{"extensions":[".md"],"exclude":[""]}`,
		`{"extensions":[".md"],"exclude":["../secret"]}`,
		`{"extensions":[".md"],"exclude":["/absolute"]}`,
		`{"extensions":[".md"],"exclude":["C:\\absolute"]}`,
		`{"extensions":[".md"],"exclude":["notes/*.md"]}`,
		`{"extensions":[".md"]} trailing`,
	} {
		t.Run(content, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, ExtensionConfigName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := LoadExtensionConfig(root); err == nil {
				t.Fatalf("accepted invalid config %s", content)
			}
		})
	}
}

func TestLoadExtensionConfigRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real-config")
	if err := os.WriteFile(target, []byte(`{"extensions":[".md"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ExtensionConfigName)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadExtensionConfig(root); err == nil {
		t.Fatal("symlink config was accepted")
	}
}
