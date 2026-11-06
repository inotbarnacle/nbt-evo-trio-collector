package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type bundle struct {
	Name  string
	Data  []byte
	Files []string
}

type library struct {
	Name    string   `json:"name"`
	SHA256  string   `json:"sha256"`
	Size    int      `json:"size_bytes"`
	Exports []string `json:"dynamic_exports,omitempty"`
}

var frameworkNames = []string{"libAppFramework.A.so", "libCoreFramework.A.so"}
var hmiBuildPattern = regexp.MustCompile(`(?m)^(NBTevo_ID5_[A-Za-z0-9_.-]+ ID5_[A-Za-z0-9_.-]+ Build [0-9]+)[\r ]*$`)

func libraryInfo(name string, raw []byte) (library, error) {
	file, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return library{}, fmt.Errorf("%s is not a readable ELF library", name)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS32 || file.Machine != elf.EM_ARM || file.Data != elf.ELFDATA2LSB || file.Type != elf.ET_DYN {
		return library{}, fmt.Errorf("%s is not a 32-bit ARM shared library", name)
	}
	info := library{Name: name, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Size: len(raw)}
	symbols, err := file.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return library{}, fmt.Errorf("could not read %s export table", name)
	}
	seen := map[string]bool{}
	for _, sym := range symbols {
		if sym.Name != "" && sym.Section != elf.SHN_UNDEF && !seen[sym.Name] {
			info.Exports = append(info.Exports, sym.Name)
			seen[sym.Name] = true
		}
	}
	sort.Strings(info.Exports)
	return info, nil
}

func collect(r remoteRunner, screenVersion string, includeLibraries bool) (bundle, error) {
	system, err := r.run("uname -s", nil, 128)
	if err != nil || strings.TrimSpace(string(system)) != "QNX" {
		return bundle{}, errors.New("the SSH endpoint did not identify as QNX")
	}
	rawVersion, _ := r.run("cat /opt/sys/etc/nbt_version.txt", nil, 1024)
	version := firmwareName(string(rawVersion))
	entered := firmwareName(screenVersion)
	if screenVersion != "" && entered == "" {
		return bundle{}, errors.New("enter the complete NBTevo code from the iDrive screen")
	}
	if entered != "" && version != "" && entered != version {
		return bundle{}, errors.New("the iDrive screen code and SSH firmware code differ")
	}
	if version == "" {
		version = entered
	}
	if version == "" {
		return bundle{}, errors.New("firmware code unavailable over SSH; enter the code shown in iDrive")
	}
	hmi, _ := r.run("cat /opt/hmi/ID5/version.txt", nil, 1024)
	report := struct {
		Schema    int       `json:"schema"`
		Firmware  string    `json:"firmware"`
		HMIBuild  string    `json:"hmi_build,omitempty"`
		Libraries []library `json:"framework_libraries"`
	}{Schema: 1, Firmware: version}
	if build := hmiBuildPattern.FindSubmatch(hmi); len(build) > 1 {
		report.HMIBuild = string(build[1])
	}

	// Read only the two fixed library paths. Never package a filesystem tree.
	files := make(map[string][]byte)
	for _, name := range frameworkNames {
		raw, err := r.run("cat /opt/hmi/ID5/lib/"+name, nil, 4<<20)
		if err != nil {
			return bundle{}, fmt.Errorf("could not read %s from the ID5 framework directory", name)
		}
		info, err := libraryInfo(name, raw)
		if err != nil {
			return bundle{}, err
		}
		report.Libraries = append(report.Libraries, info)
		if includeLibraries {
			files["frameworks/"+name] = raw
		}
	}
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return bundle{}, err
	}
	files["compatibility.json"] = append(reportJSON, '\n')
	var result bundle
	result.Name = "Trio-compatibility-" + version + ".zip"
	for path := range files {
		result.Files = append(result.Files, path)
	}
	sort.Strings(result.Files)
	var output bytes.Buffer
	z := zip.NewWriter(&output)
	for _, path := range result.Files {
		w, err := z.Create(path)
		if err != nil {
			return bundle{}, err
		}
		if _, err = w.Write(files[path]); err != nil {
			return bundle{}, err
		}
	}
	if err = z.Close(); err != nil {
		return bundle{}, err
	}
	result.Data = output.Bytes()
	return result, nil
}
