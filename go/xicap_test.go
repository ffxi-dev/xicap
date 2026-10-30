package xicap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Written by tools/xicap_make_fixture: one extension, one 50-packet frame at
// offset 269, and a footer.
const fixture = "../js/test/fixtures/sample.xicap"

func load(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func write(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.xicap")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadClosed(t *testing.T) {
	s, err := Read(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Closed || s.Packets != 50 || s.Frames != 1 || s.CaptureAgent != "xicap_make_fixture" || s.ClientVersion != "fixture-1.0" {
		t.Fatalf("unexpected summary %+v", s)
	}
}

func TestReadCutOff(t *testing.T) {
	b := load(t)
	s, err := Read(write(t, b[:len(b)-3])) // footer broken, frame whole
	if err != nil {
		t.Fatal(err)
	}
	if s.Closed || s.Packets != 50 {
		t.Fatalf("footer-less capture: %+v", s)
	}
	s, err = Read(write(t, b[:400])) // the only frame is half written
	if err != nil {
		t.Fatal(err)
	}
	if s.Closed || s.Packets != 0 {
		t.Fatalf("half-written frame: %+v", s)
	}
}

func TestReadCorruptFrame(t *testing.T) {
	b := load(t)
	b[269+20+50] ^= 0xFF
	if _, err := Read(write(t, b)); err == nil || !strings.Contains(err.Error(), "crc mismatch") {
		t.Fatalf("want a CRC error, got %v", err)
	}
}

func TestCheckHeader(t *testing.T) {
	b := load(t)
	if err := CheckHeader(b[:HeaderSize]); err != nil {
		t.Fatal(err)
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, HeaderSize)...)
	if CheckHeader(png) == nil {
		t.Fatal("PNG accepted")
	}
	if CheckHeader(b[:100]) == nil {
		t.Fatal("short header accepted")
	}
	v3 := append([]byte(nil), b[:HeaderSize]...)
	v3[4] = 3
	if CheckHeader(v3) == nil {
		t.Fatal("version 3 accepted")
	}
}

func TestSameExceptPatched(t *testing.T) {
	a := load(t)[:HeaderSize]
	b := append([]byte(nil), a...)
	b[74]++  // startTimestamp
	b[132]++ // endTimestamp
	b[140]++ // totalPacketCount
	b[148]++ // endZoneId
	if !SameExceptPatched(a, b) {
		t.Fatal("patched fields should be ignored")
	}
	b[72]++ // startZoneId
	if SameExceptPatched(a, b) {
		t.Fatal("startZoneId change accepted")
	}
}
