package crypttool

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

const testPassword = "correct horse battery staple"

func testConfig(root string) Config {
	return Config{Root: root, Workers: 2, WorkFactor: DefaultWorkFactor}
}

func TestUnicodeNestedRoundTripAndMetadata(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "资料", "旅行 🗺️.md")
	mustWrite(t, path, []byte("# 你好\n\nUnicode content ✨\n"))
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}

	encryptPlan := mustPlan(t, root, Encrypt)
	result, err := Execute(context.Background(), encryptPlan, testConfig(root), testPassword, "")
	if err != nil || result.Completed != 1 {
		t.Fatalf("encrypt: result=%+v err=%v", result, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("plaintext still exists: %v", err)
	}
	encPath := path + ".age"
	info, err := os.Stat(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 || !info.ModTime().Equal(mtime) {
		t.Fatalf("encrypted metadata mismatch: mode=%o mtime=%v", info.Mode().Perm(), info.ModTime())
	}

	decryptPlan := mustPlan(t, root, Decrypt)
	result, err = Execute(context.Background(), decryptPlan, testConfig(root), testPassword, "")
	if err != nil || result.Completed != 1 {
		t.Fatalf("decrypt: result=%+v err=%v", result, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# 你好\n\nUnicode content ✨\n" {
		t.Fatalf("content mismatch: %q", got)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0o640 || !info.ModTime().Equal(mtime) {
		t.Fatalf("restored metadata mismatch: mode=%o mtime=%v", info.Mode().Perm(), info.ModTime())
	}
}

func TestObsidianFilteringAndSymlink(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "note.md"), []byte("secret"))
	mustWrite(t, filepath.Join(root, "image.PNG"), []byte("png"))
	mustWrite(t, filepath.Join(root, "document.pdf"), []byte("pdf"))
	mustWrite(t, filepath.Join(root, ".obsidian", "plugin.md"), []byte("config"))
	if err := os.Symlink(filepath.Join(root, "note.md"), filepath.Join(root, "linked.md")); err != nil {
		t.Fatal(err)
	}

	plan := mustPlan(t, root, Encrypt)
	if len(plan.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %+v", plan.Tasks)
	}
	_, err := Execute(context.Background(), plan, testConfig(root), testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	assertExists(t, filepath.Join(root, "note.md.age"))
	assertExists(t, filepath.Join(root, "image.PNG.age"))
	assertExists(t, filepath.Join(root, "document.pdf"))
	assertExists(t, filepath.Join(root, ".obsidian", "plugin.md"))
	if target, err := os.Readlink(filepath.Join(root, "linked.md")); err != nil || !strings.HasSuffix(target, "note.md") {
		t.Fatalf("symlink changed: target=%q err=%v", target, err)
	}
}

func TestRepeatedEncryptOnlyProcessesNewFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "first.md"), []byte("first"))
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
	plan = mustPlan(t, root, Encrypt)
	if len(plan.Tasks) != 0 {
		t.Fatalf("second encryption should be no-op: %+v", plan.Tasks)
	}
	mustWrite(t, filepath.Join(root, "第二篇.md"), []byte("second"))
	plan = mustPlan(t, root, Encrypt)
	if len(plan.Tasks) != 1 || !strings.HasSuffix(plan.Tasks[0].Source, "第二篇.md") {
		t.Fatalf("expected only new file: %+v", plan.Tasks)
	}
	if err := ValidateExistingPassword(plan, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
}

func TestSameContentProducesDifferentCiphertext(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.md"), []byte("same"))
	mustWrite(t, filepath.Join(root, "b.md"), []byte("same"))
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(root, "a.md.age"))
	b, _ := os.ReadFile(filepath.Join(root, "b.md.age"))
	if bytes.Equal(a, b) {
		t.Fatal("ciphertexts should differ")
	}
}

func TestWrongPasswordDoesNotModifyFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "note.md"), []byte("secret"))
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
	encPath := filepath.Join(root, "note.md.age")
	before, _ := os.ReadFile(encPath)
	plan = mustPlan(t, root, Decrypt)
	_, err := Execute(context.Background(), plan, testConfig(root), "wrong password", "")
	if err == nil {
		t.Fatal("expected wrong-password error")
	}
	after, _ := os.ReadFile(encPath)
	if !bytes.Equal(before, after) {
		t.Fatal("encrypted source changed after wrong password")
	}
	if _, err := os.Stat(filepath.Join(root, "note.md")); !os.IsNotExist(err) {
		t.Fatal("plaintext should not have been created")
	}
}

func TestChangePasswordAndResumeMixedState(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.md", "b.md", "c.md"} {
		mustWrite(t, filepath.Join(root, name), []byte("content-"+name))
	}
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}

	newPassword := "a completely different password"
	changePlan := mustPlan(t, root, ChangePassword)
	firstOnly := changePlan
	firstOnly.Tasks = append([]Task(nil), changePlan.Tasks[:1]...)
	if _, err := Execute(context.Background(), firstOnly, testConfig(root), testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	result, err := Execute(context.Background(), changePlan, testConfig(root), testPassword, newPassword)
	if err != nil {
		t.Fatal(err)
	}
	if result.NoOp != 1 {
		t.Fatalf("expected one already-new file, got %+v", result)
	}

	decryptPlan := mustPlan(t, root, Decrypt)
	if _, err := Execute(context.Background(), decryptPlan, testConfig(root), newPassword, ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.md", "b.md", "c.md"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != "content-"+name {
			t.Fatalf("%s: content=%q err=%v", name, got, err)
		}
	}
}

func TestRecoveryWhenPlainAndEncryptedBothExist(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.md")
	mustWrite(t, path, []byte("recover me"))
	plan := mustPlan(t, root, Encrypt)
	task := plan.Tasks[0]
	if err := encryptCopyWithoutRemoving(task, testPassword); err != nil {
		t.Fatal(err)
	}
	plan = mustPlan(t, root, Encrypt)
	if len(plan.Tasks) != 1 || !plan.Tasks[0].Recovery {
		t.Fatalf("expected recovery task, got %+v", plan.Tasks)
	}
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("duplicate plaintext was not cleaned")
	}
	assertExists(t, path+".age")
}

func TestCorruptCiphertextIsKept(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.md")
	mustWrite(t, path, []byte("secret content"))
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
	encPath := path + ".age"
	data, _ := os.ReadFile(encPath)
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(encPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	plan = mustPlan(t, root, Decrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err == nil {
		t.Fatal("expected authentication error")
	}
	assertExists(t, encPath)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("plaintext should not be published")
	}
}

func TestStandardAgeCompatibility(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "compatible.md")
	mustWrite(t, path, []byte("standard age payload"))
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path + ".age")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	id, _ := age.NewScryptIdentity(testPassword)
	id.SetMaxWorkFactor(MaxWorkFactor)
	r, err := age.Decrypt(f, id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "standard age payload" {
		t.Fatalf("payload=%q err=%v", got, err)
	}
}

func TestInstalledAgeCLICompatibility(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the pseudo-terminal wrapper in this integration test is macOS-specific")
	}
	agePath, err := exec.LookPath("age")
	if err != nil {
		t.Skip("age command is not installed")
	}
	root := t.TempDir()
	path := filepath.Join(root, "官方-age-兼容.md")
	mustWrite(t, path, []byte("decryptable by the age CLI"))
	plan := mustPlan(t, root, Encrypt)
	if _, err := Execute(context.Background(), plan, testConfig(root), testPassword, ""); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(root, "age-cli-output.md")
	cmd := exec.Command("script", "-q", "/dev/null", agePath, "--decrypt", "-o", outputPath, path+".age")
	cmd.Stdin = strings.NewReader(testPassword + "\n")
	terminalOutput, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official age could not decrypt output: %v\n%s", err, terminalOutput)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read official age output: %v\n%s", err, terminalOutput)
	}
	if string(got) != "decryptable by the age CLI" {
		t.Fatalf("official age returned %q", got)
	}
}

func TestAllDefaultExtensions(t *testing.T) {
	root := t.TempDir()
	for _, ext := range DefaultExtensions {
		mustWrite(t, filepath.Join(root, "file"+ext), []byte(ext))
	}
	plan := mustPlan(t, root, Encrypt)
	if len(plan.Tasks) != len(DefaultExtensions) {
		t.Fatalf("got %d tasks, want %d", len(plan.Tasks), len(DefaultExtensions))
	}
}

func TestDecryptPlanReportsUnselectedAgeFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "note.md.age"), []byte("placeholder"))
	mustWrite(t, filepath.Join(root, "audio.wav.age"), []byte("placeholder"))
	mustWrite(t, filepath.Join(root, "archive.age"), []byte("placeholder"))

	plan := mustPlan(t, root, Decrypt)
	if len(plan.Tasks) != 1 || len(plan.UnselectedAge) != 2 || len(plan.ExistingAge) != 3 {
		t.Fatalf("unexpected default selection: tasks=%d unselected=%d existing=%d", len(plan.Tasks), len(plan.UnselectedAge), len(plan.ExistingAge))
	}

	allPlan, err := BuildPlan(root, Decrypt, map[string]struct{}{"*": {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(allPlan.Tasks) != 3 || len(allPlan.UnselectedAge) != 0 {
		t.Fatalf("unexpected all selection: tasks=%d unselected=%d", len(allPlan.Tasks), len(allPlan.UnselectedAge))
	}
}

func TestNormalizeExtensionListDoesNotAddDefaults(t *testing.T) {
	set := NormalizeExtensionList([]string{"md", ".WAV", " .md "})
	if len(set) != 2 {
		t.Fatalf("unexpected set: %#v", set)
	}
	if _, ok := set[".md"]; !ok {
		t.Fatal(".md missing")
	}
	if _, ok := set[".wav"]; !ok {
		t.Fatal(".wav missing")
	}
	if _, ok := set[".jpg"]; ok {
		t.Fatal("exact extension list unexpectedly included a default")
	}
}

func TestEncryptPlanIncludesPreviewStatistics(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "notes", "one.md"), []byte("one"))
	mustWrite(t, filepath.Join(root, "notes", "two.md"), []byte("two"))
	mustWrite(t, filepath.Join(root, "manual.pdf"), []byte("pdf"))
	mustWrite(t, filepath.Join(root, "already.png.age"), []byte("age"))
	mustWrite(t, filepath.Join(root, ExtensionConfigName), []byte(`{"extensions":[".md"]}`))

	plan, err := BuildPlan(root, Encrypt, NormalizeExtensionList([]string{".md"}))
	if err != nil {
		t.Fatal(err)
	}
	if plan.ScannedFiles != 4 || len(plan.Tasks) != 2 {
		t.Fatalf("scanned=%d tasks=%d", plan.ScannedFiles, len(plan.Tasks))
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Reason != "encryption policy configuration" {
		t.Fatalf("skipped=%#v", plan.Skipped)
	}

	stats := make(map[string]FileTypeStat)
	for _, stat := range plan.FileTypes {
		stats[stat.Extension] = stat
	}
	if stats[".md"].Files != 2 || stats[".md"].PlannedFiles != 2 {
		t.Fatalf("markdown stats=%+v", stats[".md"])
	}
	if stats[".pdf"].Files != 1 || stats[".pdf"].PlannedFiles != 0 {
		t.Fatalf("PDF stats=%+v", stats[".pdf"])
	}
	if stats[".age"].Files != 1 || stats[".age"].PlannedFiles != 0 {
		t.Fatalf("age stats=%+v", stats[".age"])
	}
}

func TestBuildPlanExcludesConfiguredFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "keep.md"), []byte("keep"))
	mustWrite(t, filepath.Join(root, "Public", "skip.md"), []byte("skip"))
	mustWrite(t, filepath.Join(root, "资料", "共享.md"), []byte("skip"))
	mustWrite(t, filepath.Join(root, "资料", "共享.md.age"), []byte("skip encrypted"))
	mustWrite(t, filepath.Join(root, "资料", "保留.md"), []byte("keep"))

	plan, err := BuildPlan(
		root,
		Encrypt,
		NormalizeExtensionList([]string{".md"}),
		[]string{"Public", "资料/共享.md"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tasks) != 2 {
		t.Fatalf("tasks=%#v, want two included files", plan.Tasks)
	}
	for _, task := range plan.Tasks {
		path := filepath.ToSlash(task.Source)
		if strings.Contains(path, "/Public/") || strings.HasSuffix(path, "/资料/共享.md") {
			t.Fatalf("excluded path was planned: %s", task.Source)
		}
	}
	count := 0
	for _, item := range plan.Skipped {
		if item.Reason == "excluded by .ageconfig" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("excluded skip count=%d, skipped=%#v", count, plan.Skipped)
	}

	decryptPlan, err := BuildPlan(
		root,
		Decrypt,
		NormalizeExtensionList([]string{".md"}),
		[]string{"Public", "资料/共享.md"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(decryptPlan.Tasks) != 0 || len(decryptPlan.ExistingAge) != 0 {
		t.Fatalf("excluded ciphertext entered decrypt plan: %+v", decryptPlan)
	}
}

func BenchmarkStatedWorkload(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping 590 MiB workload in short mode")
	}
	for i := 0; i < b.N; i++ {
		root := b.TempDir()
		for n := 0; n < 900; n++ {
			mustSizedFile(b, filepath.Join(root, fmt.Sprintf("small-%04d.md", n)), 100*1024)
		}
		for n := 0; n < 100; n++ {
			mustSizedFile(b, filepath.Join(root, fmt.Sprintf("large-%04d.png", n)), 5*1024*1024)
		}
		plan, err := BuildPlan(root, Encrypt, NormalizeExtensions(nil))
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(plan.Bytes)
		if _, err := Execute(context.Background(), plan, Config{Root: root, Workers: DefaultWorkers(), WorkFactor: DefaultWorkFactor}, testPassword, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func mustPlan(t *testing.T, root string, op Operation) Plan {
	t.Helper()
	plan, err := BuildPlan(root, op, NormalizeExtensions(nil))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustWrite(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSizedFile(t testing.TB, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func encryptCopyWithoutRemoving(task Task, password string) error {
	data, err := os.ReadFile(task.Source)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	r, _ := age.NewScryptRecipient(password)
	r.SetWorkFactor(DefaultWorkFactor)
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.WriteFile(task.Target, out.Bytes(), 0o600)
}

func TestPlanOrderIsDeterministic(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"z.md", "a.md", "中.md"} {
		mustWrite(t, filepath.Join(root, name), []byte(name))
	}
	plan := mustPlan(t, root, Encrypt)
	paths := make([]string, len(plan.Tasks))
	for i, task := range plan.Tasks {
		paths[i] = task.Source
	}
	if !sort.StringsAreSorted(paths) {
		t.Fatalf("tasks not sorted: %v", paths)
	}
}

func TestMainPlatformIsSupported(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("tool intentionally supports macOS and Linux")
	}
}
