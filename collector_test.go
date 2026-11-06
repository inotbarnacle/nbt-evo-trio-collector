package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type firmwareFixture struct{ t *testing.T }

func (f firmwareFixture) run(cmd string, _ []byte, _ int) ([]byte, error) {
	switch cmd {
	case "uname -s":
		return []byte("QNX\n"), nil
	case "cat /opt/sys/etc/nbt_version.txt":
		return []byte("NBTevo_N18032I\n"), nil
	case "cat /opt/hmi/ID5/version.txt":
		return []byte("NBTevo_ID5_1803_Release ID5_1803-510-1749I Build 66\n"), nil
	case "cat /opt/hmi/ID5/lib/libAppFramework.A.so", "cat /opt/hmi/ID5/lib/libCoreFramework.A.so":
		if folder := os.Getenv("TRIO_TEST_FRAMEWORKS"); folder != "" {
			return os.ReadFile(filepath.Join(folder, filepath.Base(cmd)))
		}
		// Minimal ARM ELF shared object, no section tables or private fixtures.
		header := make([]byte, 52)
		copy(header, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1})
		binary.LittleEndian.PutUint16(header[16:], 3)
		binary.LittleEndian.PutUint16(header[18:], 40)
		binary.LittleEndian.PutUint32(header[20:], 1)
		binary.LittleEndian.PutUint16(header[40:], 52)
		return header, nil
	default:
		f.t.Fatalf("unexpected collection command %q", cmd)
		return nil, nil
	}
}

func TestBundleContents(t *testing.T) {
	for _, raw := range []bool{false, true} {
		got, err := collect(firmwareFixture{t}, "NBTevo_N18032I", raw)
		if err != nil {
			t.Fatal(err)
		}
		z, err := zip.NewReader(bytes.NewReader(got.Data), int64(len(got.Data)))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, f := range z.File {
			names = append(names, f.Name)
		}
		want := []string{"compatibility.json"}
		if raw {
			want = append(want, "frameworks/libAppFramework.A.so", "frameworks/libCoreFramework.A.so")
		}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("got %v, want %v", names, want)
		}
	}
	if _, err := collect(firmwareFixture{t}, "NBTevo_Y24073J", false); err == nil {
		t.Fatal("accepted conflicting firmware")
	}
}
