package crypttool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ExtensionConfigName = ".ageconfig"

const maxExtensionConfigBytes = 64 * 1024

type ExtensionConfig struct {
	Extensions []string `json:"extensions"`
	Exclude    []string `json:"exclude,omitempty"`
}

func LoadExtensionConfig(root string) (ExtensionConfig, string, bool, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ExtensionConfig{}, "", false, fmt.Errorf("resolve root: %w", err)
	}
	path := filepath.Join(absRoot, ExtensionConfigName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ExtensionConfig{}, path, false, nil
	}
	if err != nil {
		return ExtensionConfig{}, path, false, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return ExtensionConfig{}, path, false, fmt.Errorf("%s must be a regular file", path)
	}
	if info.Size() > maxExtensionConfigBytes {
		return ExtensionConfig{}, path, false, fmt.Errorf("%s is larger than 64 KiB", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return ExtensionConfig{}, path, false, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	var config ExtensionConfig
	decoder := json.NewDecoder(io.LimitReader(file, maxExtensionConfigBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return ExtensionConfig{}, path, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return ExtensionConfig{}, path, false, fmt.Errorf("parse %s: %w", path, err)
	}

	extensions := config.Extensions
	if extensions == nil {
		extensions = DefaultExtensions
	}
	normalized, err := ValidateExtensionList(extensions)
	if err != nil {
		return ExtensionConfig{}, path, false, fmt.Errorf("validate %s: %w", path, err)
	}
	config.Extensions = normalized
	config.Exclude, err = ValidateExcludeList(config.Exclude)
	if err != nil {
		return ExtensionConfig{}, path, false, fmt.Errorf("validate %s: %w", path, err)
	}
	return config, path, true, nil
}

func ValidateExtensionList(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("extensions must contain at least one file extension")
	}

	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		ext := strings.TrimSpace(strings.ToLower(value))
		if ext == "" {
			return nil, errors.New("extensions cannot contain an empty value")
		}
		if strings.EqualFold(ext, "all") || ext == "*" {
			return nil, errors.New("extensions cannot contain all or *")
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		if ext == ".age" {
			return nil, errors.New(".age cannot be selected as a plaintext file type")
		}
		if ext == "." || strings.ContainsAny(ext, `/\\`) || filepath.Ext("file"+ext) != ext {
			return nil, fmt.Errorf("invalid file extension %q", value)
		}
		set[ext] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for ext := range set {
		out = append(out, ext)
	}
	sort.Strings(out)
	return out, nil
}

// ValidateExcludeList normalizes target-root-relative file and directory paths.
// A directory entry excludes that directory and everything below it. Globs are
// intentionally unsupported so the same policy behaves identically in the CLI
// and the Obsidian plugin.
func ValidateExcludeList(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		excluded := strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
		for strings.HasPrefix(excluded, "./") {
			excluded = strings.TrimPrefix(excluded, "./")
		}
		excluded = strings.TrimSuffix(excluded, "/")
		if excluded == "" {
			return nil, errors.New("exclude cannot contain an empty path")
		}
		if strings.HasPrefix(excluded, "/") || filepath.IsAbs(value) || isWindowsAbsolutePath(excluded) {
			return nil, fmt.Errorf("exclude path %q must be relative to the target directory", value)
		}
		if strings.ContainsAny(excluded, "*?[") {
			return nil, fmt.Errorf("exclude path %q cannot contain glob characters", value)
		}
		for _, segment := range strings.Split(excluded, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return nil, fmt.Errorf("invalid exclude path %q", value)
			}
		}
		set[excluded] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for excluded := range set {
		out = append(out, excluded)
	}
	sort.Strings(out)
	return out, nil
}

func isWindowsAbsolutePath(path string) bool {
	return len(path) >= 3 && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1] == ':' && path[2] == '/'
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected data after the JSON object")
	}
	return err
}
