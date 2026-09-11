package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/feifangit/file-encryption/internal/crypttool"
	"golang.org/x/term"
)

const version = "0.3.1"

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
)

type cliOptions struct {
	yes     bool
	workers int
	include []string
	only    []string
}

type resolvedPolicy struct {
	extensions map[string]struct{}
	exclude    []string
	source     string
}

type extensionFlag []string

func (f *extensionFlag) String() string { return strings.Join(*f, ",") }

func (f *extensionFlag) Set(value string) error {
	for _, ext := range strings.Split(value, ",") {
		ext = strings.TrimSpace(ext)
		if ext != "" {
			*f = append(*f, ext)
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintf(stderr, "fileencrypt %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return 0
	}

	var operation crypttool.Operation
	preview := false
	switch args[0] {
	case "encrypt":
		operation = crypttool.Encrypt
	case "preview":
		operation = crypttool.Encrypt
		preview = true
	case "decrypt":
		operation = crypttool.Decrypt
	case "change-password":
		operation = crypttool.ChangePassword
	case "help", "-h", "--help":
		usage(stderr)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}

	options, root, err := parseFlags(args[0], operation, args[1:], stderr)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	config, configPath, configFound, configErr := crypttool.LoadExtensionConfig(root)
	if configErr != nil {
		printError(stderr, configErr)
		return 2
	}
	policy, err := resolveExtensionPolicy(operation, options, config, configPath, configFound)
	if err != nil {
		printError(stderr, err)
		return 2
	}
	if !options.yes && operation == crypttool.Encrypt && !preview {
		policy.extensions, policy.source, err = promptEncryptExtensions(stderr, policy.extensions, policy.exclude, policy.source)
		if err != nil {
			printError(stderr, err)
			return 1
		}
	}
	plan, err := crypttool.BuildPlan(root, operation, policy.extensions, policy.exclude)
	if err != nil {
		printError(stderr, err)
		return 1
	}
	if preview {
		printPreview(stderr, plan, policy.extensions, policy.exclude, policy.source)
		if len(plan.Conflicts) > 0 {
			return 1
		}
		return 0
	}
	if !options.yes && (operation == crypttool.Decrypt || operation == crypttool.ChangePassword) && len(plan.UnselectedAge) > 0 {
		policy.extensions, policy.source, err = promptAgeExtensions(stderr, policy.extensions, policy.exclude, plan.UnselectedAge, policy.source)
		if err != nil {
			printError(stderr, err)
			return 1
		}
		plan, err = crypttool.BuildPlan(root, operation, policy.extensions, policy.exclude)
		if err != nil {
			printError(stderr, err)
			return 1
		}
	}
	printPlan(stderr, plan, policy.extensions, policy.exclude, policy.source)
	if len(plan.Conflicts) > 0 {
		for _, conflict := range plan.Conflicts {
			fmt.Fprintf(stderr, "  %s %s\n", colorize(stderr, ansiRed, "conflict:"), conflict)
		}
		return 1
	}
	if len(plan.Tasks) == 0 {
		fmt.Fprintln(stderr, "Nothing to do.")
		return 0
	}
	if !options.yes {
		printSection(stderr, "CONFIRMATION")
		ok, err := confirmTTY(fmt.Sprintf("Proceed with %s? [y/N]: ", operation))
		if err != nil {
			printError(stderr, err)
			return 1
		}
		if !ok {
			fmt.Fprintln(stderr, "Cancelled.")
			return 0
		}
	}

	printSection(stderr, "PASSWORD")
	var password, newPassword string
	switch operation {
	case crypttool.Encrypt:
		if len(plan.ExistingAge) == 0 {
			password, err = readNewPassword("Create password: ", "Confirm password: ")
		} else {
			password, err = readPassword("Password: ")
			if err == nil {
				err = crypttool.ValidateExistingPassword(plan, password)
			}
		}
	case crypttool.Decrypt:
		password, err = readPassword("Password: ")
		if err == nil {
			err = crypttool.ValidateExistingPassword(plan, password)
		}
	case crypttool.ChangePassword:
		password, err = readPassword("Old password: ")
		if err == nil {
			newPassword, err = readNewPassword("New password: ", "Confirm new password: ")
		}
		if err == nil && password == newPassword {
			err = errors.New("new password must differ from old password")
		}
	}
	if err != nil {
		printError(stderr, err)
		return 1
	}

	printSection(stderr, "PROGRESS")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := crypttool.Execute(ctx, plan, crypttool.Config{
		Root:       plan.Root,
		Workers:    options.workers,
		WorkFactor: crypttool.DefaultWorkFactor,
		Progress: func(p crypttool.Progress) {
			fmt.Fprintf(stderr, "[%d/%d] %s %s\n", p.Completed, p.Total, p.Action, relative(plan.Root, p.Path))
		},
	}, password, newPassword)
	if err != nil {
		printError(stderr, fmt.Errorf("after %d/%d file(s): %w", result.Completed, result.Total, err))
		return 1
	}
	fmt.Fprintf(stderr, "%s %d file(s)", colorize(stderr, ansiGreen, "Done:"), result.Completed)
	if result.NoOp > 0 {
		fmt.Fprintf(stderr, ", %d already used the new password", result.NoOp)
	}
	fmt.Fprintln(stderr)
	return 0
}

func parseFlags(command string, operation crypttool.Operation, args []string, stderr io.Writer) (cliOptions, string, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var includes extensionFlag
	var only extensionFlag
	options := cliOptions{}
	options.workers = crypttool.DefaultWorkers()
	if command != "preview" {
		fs.BoolVar(&options.yes, "yes", false, "skip the destructive-operation confirmation")
		fs.IntVar(&options.workers, "workers", options.workers, "number of concurrent workers (1-32)")
	}
	fs.Var(&includes, "include", "additional extension(s), repeatable or comma-separated")
	extHelp := "replace the configured or default extension list"
	if operation != crypttool.Encrypt {
		extHelp += "; use 'all' for every non-excluded .age file"
	}
	fs.Var(&only, "ext", extHelp)
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, "", err
	}
	if fs.NArg() != 1 {
		return cliOptions{}, "", errors.New("exactly one target directory is required")
	}
	if options.workers < 1 || options.workers > 32 {
		return cliOptions{}, "", errors.New("workers must be between 1 and 32")
	}
	options.include = includes
	options.only = only
	return options, fs.Arg(0), nil
}

func printPlan(w io.Writer, plan crypttool.Plan, extensions map[string]struct{}, excludedPaths []string, policySource string) {
	printSection(w, "PLAN")
	fmt.Fprintf(w, "%s: %s\n", strings.Title(string(plan.Operation)), plan.Root) //nolint:staticcheck
	fmt.Fprintf(w, "Policy source: %s\n", policySource)
	fmt.Fprintf(w, "Selected original file types: %s\n", formatExtensions(extensions))
	printExcludedPaths(w, excludedPaths)
	fmt.Fprintf(w, "Pending: %d file(s), %s\n", len(plan.Tasks), crypttool.FormatBytes(plan.Bytes))
	fmt.Fprintf(w, "Existing .age files: %d (%d selected, %d outside selection)\n", len(plan.ExistingAge), plan.EligibleAgeFile, len(plan.UnselectedAge))
	if len(plan.UnselectedAge) > 0 {
		fmt.Fprintf(w, "Outside selection: %s\n", formatAgeExtensions(plan.UnselectedAge))
	}
	if len(plan.Skipped) > 0 {
		fmt.Fprintf(w, "Excluded from scan: %d item(s)\n", len(plan.Skipped))
	}
	printWarning(w, "Close applications that are editing this directory before continuing.")
}

func printPreview(w io.Writer, plan crypttool.Plan, extensions map[string]struct{}, excludedPaths []string, policySource string) {
	printSection(w, "PREVIEW")
	fmt.Fprintf(w, "Directory: %s\n", plan.Root)
	fmt.Fprintf(w, "Policy source: %s\n", policySource)
	fmt.Fprintf(w, "Selected file types: %s\n", formatExtensions(extensions))
	printExcludedPaths(w, excludedPaths)

	printSection(w, "FILE TYPE STATISTICS")
	fmt.Fprintf(w, "%-18s %8s %12s %10s %10s\n", "Type", "Files", "Size", "Encrypt", "Skip")
	for _, stat := range plan.FileTypes {
		fmt.Fprintf(
			w,
			"%-18s %8d %12s %10d %10d\n",
			stat.Extension,
			stat.Files,
			crypttool.FormatBytes(stat.Bytes),
			stat.PlannedFiles,
			stat.Files-stat.PlannedFiles,
		)
	}

	printSection(w, "SUMMARY")
	fmt.Fprintf(w, "%s %d file(s), %s\n", colorize(w, ansiGreen, "Would encrypt:"), len(plan.Tasks), crypttool.FormatBytes(plan.Bytes))
	fmt.Fprintf(w, "Would skip: %d scanned regular file(s), %s\n", plan.ScannedFiles-len(plan.Tasks), crypttool.FormatBytes(plan.ScannedBytes-plan.Bytes))
	if len(plan.ExistingAge) > 0 {
		fmt.Fprintf(w, "Existing .age files: %d\n", len(plan.ExistingAge))
	}
	if len(plan.Skipped) > 0 {
		fmt.Fprintf(w, "Excluded from scan: %d item(s)\n", len(plan.Skipped))
		printSkippedReasons(w, plan)
	}
	if len(plan.Conflicts) > 0 {
		fmt.Fprintf(w, "%s %d\n", colorize(w, ansiRed, "Conflicts:"), len(plan.Conflicts))
		for _, conflict := range plan.Conflicts {
			fmt.Fprintf(w, "  - %s\n", conflict)
		}
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `fileencrypt encrypt [--yes] [--workers N] [--ext EXT] [--include EXT] <directory>
fileencrypt decrypt [--yes] [--workers N] [--ext EXT|all] [--include EXT] <directory>
fileencrypt change-password [--yes] [--workers N] [--ext EXT|all] [--include EXT] <directory>
fileencrypt preview [--ext EXT] [--include EXT] <directory>
fileencrypt version

Policy priority: --ext, then <directory>/.ageconfig, then built-in defaults.
--include adds file types to the selected policy.
Exclusions in .ageconfig always apply; --ext and --include do not override them.`)
}

func readLineTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open terminal: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, colorize(tty, ansiBold, prompt))
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func extensionSet(operation crypttool.Operation, options cliOptions) (map[string]struct{}, error) {
	return extensionSetWithBase(operation, options, crypttool.DefaultExtensions)
}

func extensionSetWithBase(operation crypttool.Operation, options cliOptions, base []string) (map[string]struct{}, error) {
	values := options.only
	if len(values) == 0 {
		values = base
	}
	values = append(append([]string{}, values...), options.include...)
	expanded := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.EqualFold(part, "all") || part == "*" {
				if operation == crypttool.Encrypt {
					return nil, errors.New("--ext all is not allowed for encryption; list the desired extensions explicitly")
				}
				return map[string]struct{}{"*": {}}, nil
			}
			expanded = append(expanded, part)
		}
	}
	normalized, err := crypttool.ValidateExtensionList(expanded)
	if err != nil {
		return nil, err
	}
	return crypttool.NormalizeExtensionList(normalized), nil
}

func resolveExtensionPolicy(operation crypttool.Operation, options cliOptions, config crypttool.ExtensionConfig, configPath string, configFound bool) (resolvedPolicy, error) {
	base := crypttool.DefaultExtensions
	source := "built-in defaults"
	if configFound {
		base = config.Extensions
		source = fmt.Sprintf("%s (%s)", crypttool.ExtensionConfigName, configPath)
	}
	if len(options.only) > 0 {
		if configFound {
			source = fmt.Sprintf("--ext (overrides file types from %s; its exclusions still apply)", configPath)
		} else {
			source = "--ext"
		}
	}
	if len(options.include) > 0 {
		source += " + --include"
	}
	exts, err := extensionSetWithBase(operation, options, base)
	if err != nil {
		return resolvedPolicy{}, err
	}
	return resolvedPolicy{extensions: exts, exclude: config.Exclude, source: source}, nil
}

func promptEncryptExtensions(w io.Writer, current map[string]struct{}, excludedPaths []string, source string) (map[string]struct{}, string, error) {
	printSection(w, "ENCRYPTION POLICY")
	fmt.Fprintf(w, "Policy source: %s\n", source)
	fmt.Fprintf(w, "Files matching %s will be encrypted.\n", formatExtensions(current))
	printExcludedPaths(w, excludedPaths)
	answer, err := readLineTTY("Press Enter to use this policy, or enter a replacement list (for example .md,.wav): ")
	if err != nil || strings.TrimSpace(answer) == "" {
		return current, source, err
	}
	replacement, err := replacementExtensionSet(answer, crypttool.Encrypt)
	return replacement, "interactive replacement", err
}

func promptAgeExtensions(w io.Writer, current map[string]struct{}, excludedPaths []string, unselected []string, source string) (map[string]struct{}, string, error) {
	printSection(w, "ENCRYPTED FILE SELECTION")
	fmt.Fprintf(w, "Policy source: %s\n", source)
	fmt.Fprintf(w, "Selected original types: %s\n", formatExtensions(current))
	printExcludedPaths(w, excludedPaths)
	fmt.Fprintf(w, "Also found outside this selection: %s\n", formatAgeExtensions(unselected))
	answer, err := readLineTTY("Press Enter to keep this selection, type 'all' for every non-excluded .age file, or enter a replacement list: ")
	if err != nil || strings.TrimSpace(answer) == "" {
		return current, source, err
	}
	replacement, err := replacementExtensionSet(answer, crypttool.Decrypt)
	return replacement, "interactive replacement", err
}

func replacementExtensionSet(answer string, operation crypttool.Operation) (map[string]struct{}, error) {
	return extensionSet(operation, cliOptions{only: []string{answer}})
}

func formatExtensions(extensions map[string]struct{}) string {
	if _, all := extensions["*"]; all {
		return "all types"
	}
	values := make([]string, 0, len(extensions))
	for ext := range extensions {
		values = append(values, ext)
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func formatAgeExtensions(paths []string) string {
	counts := make(map[string]int)
	for _, path := range paths {
		base := strings.TrimSuffix(path, filepath.Ext(path))
		ext := strings.ToLower(filepath.Ext(base))
		if ext == "" {
			ext = "(no extension)"
		}
		counts[ext]++
	}
	values := make([]string, 0, len(counts))
	for ext, count := range counts {
		values = append(values, fmt.Sprintf("%s (%d)", ext, count))
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func printExcludedPaths(w io.Writer, excludedPaths []string) {
	if len(excludedPaths) == 0 {
		fmt.Fprintln(w, "Excluded paths: none")
		return
	}
	fmt.Fprintf(w, "Excluded paths: %s\n", strings.Join(excludedPaths, ", "))
}

func printSkippedReasons(w io.Writer, plan crypttool.Plan) {
	counts := make(map[string]int)
	for _, item := range plan.Skipped {
		counts[item.Reason]++
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		fmt.Fprintf(w, "  - %s: %d\n", reason, counts[reason])
	}
}

func printSection(w io.Writer, title string) {
	line := fmt.Sprintf("-------------------- %s --------------------", title)
	fmt.Fprintln(w, colorize(w, ansiCyan+ansiBold, line))
}

func printWarning(w io.Writer, message string) {
	fmt.Fprintf(w, "%s %s\n", colorize(w, ansiYellow+ansiBold, "Warning:"), message)
}

func printError(w io.Writer, err error) {
	fmt.Fprintf(w, "%s %v\n", colorize(w, ansiRed+ansiBold, "Error:"), err)
}

func colorize(w io.Writer, code, value string) string {
	if !supportsColor(w) {
		return value
	}
	return code + value + ansiReset
}

func supportsColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func readPassword(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open terminal: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, colorize(tty, ansiBold, prompt))
	value, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(value) == 0 {
		return "", errors.New("password cannot be empty")
	}
	return string(value), nil
}

func readNewPassword(prompt, confirmPrompt string) (string, error) {
	first, err := readPassword(prompt)
	if err != nil {
		return "", err
	}
	second, err := readPassword(confirmPrompt)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	if len([]rune(first)) < 12 {
		printWarning(os.Stderr, "Passwords shorter than 12 characters are easy to guess offline.")
		ok, err := confirmTTY("Use this weak password anyway? [y/N]: ")
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("weak password rejected")
		}
	}
	return first, nil
}

func confirmTTY(prompt string) (bool, error) {
	line, err := readLineTTY(prompt)
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "y" || line == "yes" {
		return true, nil
	}
	if _, err := strconv.ParseBool(line); err == nil && line == "true" {
		return true, nil
	}
	return false, nil
}

func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
