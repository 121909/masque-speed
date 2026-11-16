package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

// Preserve the upstream notice verbatim without requiring the development-only
// .tools directory to be present on the release builder.
const usqueLicense = `The MIT License (MIT)
=====================

Copyright © 2025, github.com/Diniboy1123

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

`

func main() {
	out := flag.String("out", "dist", "release output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "release-notices: unexpected positional arguments; use -out DIRECTORY")
		os.Exit(1)
	}
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "release-notices:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	modules, err := listModules()
	if err != nil {
		return err
	}
	var goroot bytes.Buffer
	cmd := exec.Command("go", "env", "GOROOT")
	cmd.Stdout = &goroot
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go env GOROOT failed: %w; install Go and ensure it is on PATH", err)
	}
	root := strings.TrimSpace(goroot.String())
	if root == "" {
		return errors.New("go env GOROOT returned an empty directory")
	}
	licenses := filepath.Join(out, "licenses")
	if err := os.MkdirAll(licenses, 0o755); err != nil {
		return fmt.Errorf("create license output directory: %w", err)
	}
	var manifest strings.Builder
	for _, mod := range modules {
		source := mod
		fmt.Fprintf(&manifest, "%s %s", mod.Path, mod.Version)
		if mod.Replace != nil {
			source = *mod.Replace
			fmt.Fprintf(&manifest, " => %s %s", source.Path, source.Version)
		}
		manifest.WriteByte('\n')
		if source.Dir == "" {
			return fmt.Errorf("module %s %s has no source directory; run go mod download before packaging (check local replacements if present)", mod.Path, mod.Version)
		}
		dest := filepath.Join(licenses, moduleDirectory(mod))
		if err := copyModuleNotices(source.Dir, dest); err != nil {
			return fmt.Errorf("module %s %s: %w", mod.Path, mod.Version, err)
		}
	}
	for _, name := range []string{"LICENSE", "PATENTS"} {
		if err := copyFile(filepath.Join(root, name), filepath.Join(licenses, "go", name)); err != nil {
			return fmt.Errorf("copy Go runtime %s from GOROOT %q: %w", name, root, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(licenses, "usque"), 0o755); err != nil {
		return fmt.Errorf("create usque notice directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(licenses, "usque", "LICENSE"), []byte(usqueLicense), 0o644); err != nil {
		return fmt.Errorf("write usque license: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, "modules.txt"), []byte(manifest.String()), 0o644); err != nil {
		return fmt.Errorf("write module manifest: %w", err)
	}
	return nil
}

func listModules() ([]module, error) {
	// A temporary stream keeps go list output out of memory while allowing Run
	// to complete (and report its exit status) before JSON is consumed.
	stream, err := os.CreateTemp("", "release-modules-*.json")
	if err != nil {
		return nil, fmt.Errorf("create module list stream: %w", err)
	}
	defer os.Remove(stream.Name())
	defer stream.Close()
	cmd := exec.Command("go", "list", "-m", "-json", "all")
	cmd.Stdout = stream
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list -m -json all failed: %w; run from the repository root after go mod tidy and go mod download", err)
	}
	if _, err := stream.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind module list: %w", err)
	}
	decoder := json.NewDecoder(stream)
	var modules []module
	for {
		var mod module
		if err := decoder.Decode(&mod); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list module JSON: %w", err)
		}
		if !mod.Main {
			modules = append(modules, mod)
		}
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, nil
}

func moduleDirectory(mod module) string {
	name := mod.Path + "@" + mod.Version
	return strings.NewReplacer("/", "__", "\\", "__", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_").Replace(name)
}

func copyModuleNotices(source, dest string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read source directory %q: %w; run go mod download before packaging", source, err)
	}
	foundLicense := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToUpper(entry.Name())
		isLicense := strings.HasPrefix(name, "LICENSE") || strings.HasPrefix(name, "COPYING")
		if !isLicense && !strings.HasPrefix(name, "NOTICE") && name != "PATENTS" {
			continue
		}
		if err := copyFile(filepath.Join(source, entry.Name()), filepath.Join(dest, entry.Name())); err != nil {
			return err
		}
		foundLicense = foundLicense || isLicense
	}
	if !foundLicense {
		return fmt.Errorf("no top-level LICENSE* or COPYING* file found in %q; inspect the module's license before packaging", source)
	}
	return nil
}

func copyFile(source, dest string) error {
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open %q: %w", source, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %q: %w", source, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("notice %q is not a regular file", source)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create notice directory: %w", err)
	}
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create %q: %w", dest, err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("copy %q to %q: %w", source, dest, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %q: %w", dest, closeErr)
	}
	return nil
}
