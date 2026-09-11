package crypttool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"

	"filippo.io/age"
)

const (
	DefaultWorkFactor = 14
	MaxWorkFactor     = 14
	tempPrefix        = ".fileencrypt-tmp-"
)

var ageMagic = []byte("age-encryption.org/v1\n")

var DefaultExtensions = []string{
	".md", ".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp",
}

type Operation string

const (
	Encrypt        Operation = "encrypt"
	Decrypt        Operation = "decrypt"
	ChangePassword Operation = "change-password"
)

type Task struct {
	Source   string
	Target   string
	Size     int64
	Recovery bool
}

type SkippedItem struct {
	Path   string
	Reason string
}

type FileTypeStat struct {
	Extension    string
	Files        int
	Bytes        int64
	PlannedFiles int
	PlannedBytes int64
}

type Plan struct {
	Root            string
	Operation       Operation
	Tasks           []Task
	ExistingAge     []string
	UnselectedAge   []string
	Skipped         []SkippedItem
	Conflicts       []string
	Bytes           int64
	EligibleAgeFile int
	ScannedFiles    int
	ScannedBytes    int64
	FileTypes       []FileTypeStat
}

type Progress struct {
	Completed int
	Total     int
	Action    string
	Path      string
}

type Result struct {
	Completed int
	Total     int
	NoOp      int
}

type Config struct {
	Root       string
	Workers    int
	WorkFactor int
	Progress   func(Progress)
}

func NormalizeExtensions(extra []string) map[string]struct{} {
	values := append(append([]string{}, DefaultExtensions...), extra...)
	return NormalizeExtensionList(values)
}

func NormalizeExtensionList(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, ext := range values {
		ext = strings.TrimSpace(strings.ToLower(ext))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		out[ext] = struct{}{}
	}
	return out
}

func DefaultWorkers() int {
	n := runtime.NumCPU()
	if n > 4 {
		return 4
	}
	if n < 1 {
		return 1
	}
	return n
}

func BuildPlan(root string, operation Operation, extensions map[string]struct{}, excludedPaths ...[]string) (Plan, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Plan{}, fmt.Errorf("resolve root: %w", err)
	}
	rootInfo, err := os.Stat(absRoot)
	if err != nil {
		return Plan{}, fmt.Errorf("stat root: %w", err)
	}
	if !rootInfo.IsDir() {
		return Plan{}, fmt.Errorf("%s is not a directory", absRoot)
	}

	excludes := []string(nil)
	if len(excludedPaths) > 0 {
		excludes = excludedPaths[0]
	}
	plan := Plan{Root: absRoot, Operation: operation}
	regular := make(map[string]fs.FileInfo)
	err = filepath.WalkDir(absRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != absRoot && entry.IsDir() && entry.Name() == ".obsidian" {
			plan.Skipped = append(plan.Skipped, SkippedItem{Path: path, Reason: "Obsidian configuration directory"})
			return filepath.SkipDir
		}
		if path != absRoot && entry.Name() == ExtensionConfigName {
			plan.Skipped = append(plan.Skipped, SkippedItem{Path: path, Reason: "encryption policy configuration"})
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path != absRoot {
			relativePath, err := filepath.Rel(absRoot, path)
			if err != nil {
				return fmt.Errorf("resolve relative path for %s: %w", path, err)
			}
			if isExcludedPolicyPath(filepath.ToSlash(relativePath), excludes) {
				plan.Skipped = append(plan.Skipped, SkippedItem{Path: path, Reason: "excluded by .ageconfig"})
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			plan.Skipped = append(plan.Skipped, SkippedItem{Path: path, Reason: "tool temporary file"})
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			plan.Skipped = append(plan.Skipped, SkippedItem{Path: path, Reason: "symbolic link"})
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			plan.Skipped = append(plan.Skipped, SkippedItem{Path: path, Reason: "special file"})
			return nil
		}
		regular[path] = info
		return nil
	})
	if err != nil {
		return Plan{}, fmt.Errorf("scan directory: %w", err)
	}

	paths := make([]string, 0, len(regular))
	for path := range regular {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		info := regular[path]
		plan.ScannedFiles++
		plan.ScannedBytes += info.Size()
		isEncrypted := strings.EqualFold(filepath.Ext(path), ".age")
		base := strings.TrimSuffix(path, filepath.Ext(path))
		eligibleAge := isEncrypted && eligible(base, extensions)

		if isEncrypted {
			plan.ExistingAge = append(plan.ExistingAge, path)
		}
		if eligibleAge {
			plan.EligibleAgeFile++
		} else if isEncrypted {
			plan.UnselectedAge = append(plan.UnselectedAge, path)
		}

		switch operation {
		case Encrypt:
			if isEncrypted || !eligible(path, extensions) {
				continue
			}
			magic, err := hasAgeMagic(path)
			if err != nil {
				return Plan{}, err
			}
			if magic {
				plan.Conflicts = append(plan.Conflicts, path+": contains age data but lacks .age suffix")
				continue
			}
			target := path + ".age"
			targetInfo, exists := regular[target]
			if !exists {
				if _, err := os.Lstat(target); err == nil {
					plan.Conflicts = append(plan.Conflicts, target+": target exists and is not a regular file")
					continue
				} else if !errors.Is(err, os.ErrNotExist) {
					return Plan{}, fmt.Errorf("inspect target %s: %w", target, err)
				}
			}
			plan.Tasks = append(plan.Tasks, Task{Source: path, Target: target, Size: info.Size(), Recovery: targetInfo != nil})
			plan.Bytes += info.Size()

		case Decrypt:
			if !eligibleAge {
				continue
			}
			target := base
			targetInfo, exists := regular[target]
			if !exists {
				if _, err := os.Lstat(target); err == nil {
					plan.Conflicts = append(plan.Conflicts, target+": target exists and is not a regular file")
					continue
				} else if !errors.Is(err, os.ErrNotExist) {
					return Plan{}, fmt.Errorf("inspect target %s: %w", target, err)
				}
			}
			plan.Tasks = append(plan.Tasks, Task{Source: path, Target: target, Size: info.Size(), Recovery: targetInfo != nil})
			plan.Bytes += info.Size()

		case ChangePassword:
			if !eligibleAge {
				continue
			}
			plan.Tasks = append(plan.Tasks, Task{Source: path, Target: path, Size: info.Size()})
			plan.Bytes += info.Size()

		default:
			return Plan{}, fmt.Errorf("unsupported operation %q", operation)
		}
	}

	sort.Slice(plan.Tasks, func(i, j int) bool { return plan.Tasks[i].Source < plan.Tasks[j].Source })
	plan.FileTypes = buildFileTypeStats(paths, regular, plan.Tasks)
	return plan, nil
}

func isExcludedPath(path string, excludedPaths []string) bool {
	for _, excluded := range excludedPaths {
		if path == excluded || strings.HasPrefix(path, excluded+"/") {
			return true
		}
	}
	return false
}

func isExcludedPolicyPath(path string, excludedPaths []string) bool {
	if isExcludedPath(path, excludedPaths) {
		return true
	}
	if strings.EqualFold(filepath.Ext(path), ".age") {
		return isExcludedPath(strings.TrimSuffix(path, filepath.Ext(path)), excludedPaths)
	}
	return false
}

func buildFileTypeStats(paths []string, regular map[string]fs.FileInfo, tasks []Task) []FileTypeStat {
	planned := make(map[string]struct{}, len(tasks))
	for _, task := range tasks {
		planned[task.Source] = struct{}{}
	}

	stats := make(map[string]*FileTypeStat)
	for _, path := range paths {
		extension := strings.ToLower(filepath.Ext(path))
		if extension == "" {
			extension = "(no extension)"
		}
		stat := stats[extension]
		if stat == nil {
			stat = &FileTypeStat{Extension: extension}
			stats[extension] = stat
		}
		info := regular[path]
		stat.Files++
		stat.Bytes += info.Size()
		if _, ok := planned[path]; ok {
			stat.PlannedFiles++
			stat.PlannedBytes += info.Size()
		}
	}

	extensions := make([]string, 0, len(stats))
	for extension := range stats {
		extensions = append(extensions, extension)
	}
	sort.Strings(extensions)
	out := make([]FileTypeStat, 0, len(extensions))
	for _, extension := range extensions {
		out = append(out, *stats[extension])
	}
	return out
}

func ValidateExistingPassword(plan Plan, password string) error {
	var path string
	switch plan.Operation {
	case Encrypt:
		if len(plan.ExistingAge) > 0 {
			path = plan.ExistingAge[0]
		}
	case Decrypt:
		if len(plan.Tasks) > 0 {
			path = plan.Tasks[0].Source
		}
	}
	if path == "" {
		return nil
	}
	return validatePassword(path, password)
}

func Execute(ctx context.Context, plan Plan, cfg Config, password, newPassword string) (Result, error) {
	if len(plan.Conflicts) != 0 {
		return Result{}, fmt.Errorf("plan has %d conflict(s)", len(plan.Conflicts))
	}
	if cfg.Workers < 1 || cfg.Workers > 32 {
		return Result{}, fmt.Errorf("workers must be between 1 and 32")
	}
	if cfg.WorkFactor == 0 {
		cfg.WorkFactor = DefaultWorkFactor
	}
	if cfg.WorkFactor != DefaultWorkFactor {
		return Result{}, fmt.Errorf("unsupported work factor %d", cfg.WorkFactor)
	}

	lock, err := acquireDirectoryLock(plan.Root)
	if err != nil {
		return Result{}, err
	}
	defer lock.Close()

	if len(plan.Tasks) == 0 {
		return Result{Total: 0}, nil
	}

	if plan.Operation != ChangePassword && password == "" {
		return Result{}, errors.New("password cannot be empty")
	}
	if plan.Operation == ChangePassword && (password == "" || newPassword == "") {
		return Result{}, errors.New("old and new passwords cannot be empty")
	}

	var work func(Task) (string, error)
	switch plan.Operation {
	case Encrypt:
		work = func(task Task) (string, error) {
			if task.Recovery {
				return "recovered", reconcileEncryptedPair(task, password)
			}
			return "encrypted", encryptOne(task, password, cfg.WorkFactor)
		}
	case Decrypt:
		work = func(task Task) (string, error) {
			if task.Recovery {
				return "recovered", reconcileDecryptedPair(task, password)
			}
			return "decrypted", decryptOne(task, password)
		}
	case ChangePassword:
		work = func(task Task) (string, error) {
			return changePasswordOne(task, password, newPassword, cfg.WorkFactor)
		}
	default:
		return Result{}, fmt.Errorf("unsupported operation %q", plan.Operation)
	}

	return runTasks(ctx, plan.Tasks, cfg.Workers, cfg.Progress, work)
}

func runTasks(ctx context.Context, tasks []Task, workers int, progress func(Progress), work func(Task) (string, error)) (Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan Task)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	var progressMu sync.Mutex
	completed := 0
	noOp := 0

	worker := func() {
		defer wg.Done()
		for task := range jobs {
			if ctx.Err() != nil {
				return
			}
			action, err := work(task)
			if err != nil {
				errOnce.Do(func() {
					firstErr = fmt.Errorf("%s: %w", task.Source, err)
					cancel()
				})
				return
			}
			progressMu.Lock()
			completed++
			if action == "already-new" {
				noOp++
			}
			if progress != nil {
				progress(Progress{Completed: completed, Total: len(tasks), Action: action, Path: task.Source})
			}
			progressMu.Unlock()
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	feedDone := make(chan struct{})
	go func() {
		defer close(jobs)
		defer close(feedDone)
		for _, task := range tasks {
			select {
			case jobs <- task:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	<-feedDone
	return Result{Completed: completed, Total: len(tasks), NoOp: noOp}, firstErr
}

func encryptOne(task Task, password string, workFactor int) error {
	before, src, err := openStableSource(task.Source)
	if err != nil {
		return err
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(task.Target), tempPrefix)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("create password recipient: %w", err)
	}
	recipient.SetWorkFactor(workFactor)
	enc, err := age.Encrypt(tmp, recipient)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("start encryption: %w", err)
	}
	if _, err := io.Copy(enc, src); err != nil {
		enc.Close()
		tmp.Close()
		return fmt.Errorf("encrypt content: %w", err)
	}
	if err := enc.Close(); err != nil {
		tmp.Close()
		return fmt.Errorf("finish encryption: %w", err)
	}
	if err := finalizeTemp(tmp, tmpName, before); err != nil {
		return err
	}
	if err := ensureUnchanged(task.Source, before); err != nil {
		return err
	}
	return publishThenRemove(tmpName, task.Target, task.Source)
}

func decryptOne(task Task, password string) error {
	before, src, err := openStableSource(task.Source)
	if err != nil {
		return err
	}
	defer src.Close()

	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return fmt.Errorf("create password identity: %w", err)
	}
	identity.SetMaxWorkFactor(MaxWorkFactor)
	dec, err := age.Decrypt(src, identity)
	if err != nil {
		return fmt.Errorf("decrypt header (wrong password or invalid file): %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(task.Target), tempPrefix)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, dec); err != nil {
		tmp.Close()
		return fmt.Errorf("decrypt and authenticate content: %w", err)
	}
	if err := finalizeTemp(tmp, tmpName, before); err != nil {
		return err
	}
	if err := ensureUnchanged(task.Source, before); err != nil {
		return err
	}
	return publishThenRemove(tmpName, task.Target, task.Source)
}

func changePasswordOne(task Task, oldPassword, newPassword string, workFactor int) (string, error) {
	before, src, err := openStableSource(task.Source)
	if err != nil {
		return "", err
	}

	oldIdentity, err := age.NewScryptIdentity(oldPassword)
	if err != nil {
		src.Close()
		return "", err
	}
	oldIdentity.SetMaxWorkFactor(MaxWorkFactor)
	dec, oldErr := age.Decrypt(src, oldIdentity)
	if oldErr != nil {
		src.Close()
		if err := validatePassword(task.Source, newPassword); err == nil {
			return "already-new", nil
		}
		return "", fmt.Errorf("file matches neither old nor new password")
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(task.Source), tempPrefix)
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	recipient, err := age.NewScryptRecipient(newPassword)
	if err != nil {
		tmp.Close()
		return "", err
	}
	recipient.SetWorkFactor(workFactor)
	enc, err := age.Encrypt(tmp, recipient)
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("start encryption with new password: %w", err)
	}
	if _, err := io.Copy(enc, dec); err != nil {
		enc.Close()
		tmp.Close()
		return "", fmt.Errorf("decrypt old content: %w", err)
	}
	if err := enc.Close(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("finish encryption with new password: %w", err)
	}
	if err := finalizeTemp(tmp, tmpName, before); err != nil {
		return "", err
	}
	if err := ensureUnchanged(task.Source, before); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, task.Source); err != nil {
		return "", fmt.Errorf("replace encrypted file: %w", err)
	}
	if err := syncDirectory(filepath.Dir(task.Source)); err != nil {
		return "", err
	}
	return "password-changed", nil
}

func reconcileEncryptedPair(task Task, password string) error {
	equal, err := plainEqualsEncrypted(task.Source, task.Target, password)
	if err != nil {
		return err
	}
	if !equal {
		return errors.New("plaintext and existing encrypted target contain different data")
	}
	info, err := os.Stat(task.Source)
	if err != nil {
		return err
	}
	if err := applyMetadata(task.Target, info); err != nil {
		return err
	}
	if err := os.Remove(task.Source); err != nil {
		return fmt.Errorf("remove duplicate plaintext: %w", err)
	}
	return syncDirectory(filepath.Dir(task.Source))
}

func reconcileDecryptedPair(task Task, password string) error {
	equal, err := plainEqualsEncrypted(task.Target, task.Source, password)
	if err != nil {
		return err
	}
	if !equal {
		return errors.New("encrypted file and existing plaintext target contain different data")
	}
	info, err := os.Stat(task.Source)
	if err != nil {
		return err
	}
	if err := applyMetadata(task.Target, info); err != nil {
		return err
	}
	if err := os.Remove(task.Source); err != nil {
		return fmt.Errorf("remove duplicate encrypted file: %w", err)
	}
	return syncDirectory(filepath.Dir(task.Source))
}

func plainEqualsEncrypted(plainPath, encryptedPath, password string) (bool, error) {
	plain, err := os.Open(plainPath)
	if err != nil {
		return false, err
	}
	defer plain.Close()
	enc, err := os.Open(encryptedPath)
	if err != nil {
		return false, err
	}
	defer enc.Close()
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return false, err
	}
	identity.SetMaxWorkFactor(MaxWorkFactor)
	dec, err := age.Decrypt(enc, identity)
	if err != nil {
		return false, fmt.Errorf("decrypt existing age file: %w", err)
	}
	aHash, aSize, err := hashReader(plain)
	if err != nil {
		return false, err
	}
	bHash, bSize, err := hashReader(dec)
	if err != nil {
		return false, fmt.Errorf("authenticate existing age file: %w", err)
	}
	return aSize == bSize && bytes.Equal(aHash[:], bHash[:]), nil
}

func hashReader(r io.Reader) ([sha256.Size]byte, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, n, err
}

func validatePassword(path, password string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return err
	}
	identity.SetMaxWorkFactor(MaxWorkFactor)
	dec, err := age.Decrypt(f, identity)
	if err != nil {
		return fmt.Errorf("wrong password or invalid age file: %w", err)
	}
	var one [1]byte
	_, err = dec.Read(one[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read decrypted content: %w", err)
	}
	return nil
}

func hasAgeMagic(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	buf := make([]byte, len(ageMagic))
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false, err
	}
	return n == len(ageMagic) && bytes.Equal(buf, ageMagic), nil
}

func eligible(path string, extensions map[string]struct{}) bool {
	if _, all := extensions["*"]; all {
		return true
	}
	_, ok := extensions[strings.ToLower(filepath.Ext(path))]
	return ok
}

func openStableSource(path string) (fs.FileInfo, *os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("source is no longer a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	openedInfo, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !os.SameFile(info, openedInfo) {
		f.Close()
		return nil, nil, errors.New("source changed while opening")
	}
	return openedInfo, f, nil
}

func ensureUnchanged(path string, before fs.FileInfo) error {
	after, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("recheck source: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("source changed during processing")
	}
	return nil
}

func finalizeTemp(tmp *os.File, path string, sourceInfo fs.FileInfo) error {
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	return applyMetadata(path, sourceInfo)
}

func applyMetadata(path string, info fs.FileInfo) error {
	if err := os.Chmod(path, info.Mode().Perm()); err != nil {
		return fmt.Errorf("preserve permissions: %w", err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		return fmt.Errorf("preserve modification time: %w", err)
	}
	return nil
}

func publishThenRemove(tmpName, target, source string) error {
	if err := os.Link(tmpName, target); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("target appeared during processing: %s", target)
		}
		return fmt.Errorf("publish target: %w", err)
	}
	if err := os.Remove(tmpName); err != nil {
		return fmt.Errorf("remove temporary link: %w", err)
	}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return fmt.Errorf("remove source after publishing target: %w", err)
	}
	return syncDirectory(filepath.Dir(target))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

type directoryLock struct {
	dir *os.File
}

func acquireDirectoryLock(root string) (*directoryLock, error) {
	dir, err := os.Open(root)
	if err != nil {
		return nil, fmt.Errorf("open root for locking: %w", err)
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		dir.Close()
		return nil, fmt.Errorf("another fileencrypt operation is using %s: %w", root, err)
	}
	return &directoryLock{dir: dir}, nil
}

func (l *directoryLock) Close() error {
	if l == nil || l.dir == nil {
		return nil
	}
	_ = syscall.Flock(int(l.dir.Fd()), syscall.LOCK_UN)
	return l.dir.Close()
}

func FormatBytes(n int64) string {
	const unit = int64(1024)
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := unit, 0
	for value := n / unit; value >= unit && exp < 5; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
