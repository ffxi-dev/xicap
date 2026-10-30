package xicap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const t0 = 1790000000000

// 0x015 with 4 words: id low byte, then size<<1 | id bit 8.
var pkt = []byte{0x15, 0x08, 0x01, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

func info() WriterInfo {
	return WriterInfo{
		CaptureAgent:  "test",
		ClientVersion: "v1",
		Character:     Character{ContentID: 0x01020304, CharacterID: 7, WorldID: 42, Name: "Nouurs", World: "Asura"},
		ClockSource:   ClockLive,
		Origin:        OriginLive,
		Network:       NetworkRetail,
		StartContext:  StartLogin,
		SigningSeed:   [32]byte{1, 2, 3},
	}
}

// capture writes frames of three packets each, one second apart, and returns its path.
func capture(t *testing.T, frames int, wi WriterInfo) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.xicap")
	w, err := Create(p, wi)
	if err != nil {
		t.Fatal(err)
	}
	for f := range frames {
		for i := range 3 {
			if err := w.Write(t0+uint64(f)*1000+uint64(i), i%2 == 0, pkt); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func write(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "w.xicap")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// frameOffsets finds packet and checkpoint frames by their magic.
func frameOffsets(b []byte) []int {
	var out []int
	for i := 0; ; {
		j := bytes.Index(b[i:], []byte("XCFR"))
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + 4
	}
}

func TestWriteThenRead(t *testing.T) {
	p := capture(t, 2, info())
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Closed || s.Packets != 6 || s.Frames != 2 || s.VersionMajor != 3 || s.CaptureAgent != "test" ||
		s.Character.Name != "Nouurs" || s.Character.ContentID != 0x01020304 || s.Network != NetworkRetail ||
		s.StartContext != StartLogin || s.StartTimestamp != t0 || s.EndTimestamp != t0+1002 ||
		s.Policy.Name != "xicap-default" || s.RuleCount != 5 || len(s.Policy.Rules) != 5 || !s.SignedToEnd || s.VerifiedPackets != 6 || s.Source != nil {
		t.Fatalf("unexpected summary %+v", s)
	}
}

func TestIDsMatchTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.xicap")
	w, err := Create(p, info())
	if err != nil {
		t.Fatal(err)
	}
	id, key := w.IDs()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.CaptureID != id || s.SigningKey != key || id == [16]byte{} {
		t.Fatalf("ids %x %x, file %x %x", id, key, s.CaptureID, s.SigningKey)
	}
}

func TestReadCutOff(t *testing.T) {
	b := load(t, capture(t, 3, info()))
	s, err := Read(write(t, b[:len(b)-3])) // footer magic gone, frames whole
	if err != nil {
		t.Fatal(err)
	}
	if s.Closed || s.FooterDamaged || s.Packets != 9 || s.SignedToEnd || s.UnreadBytes == 0 {
		t.Fatalf("footer-less capture: %+v", s)
	}
	frames := frameOffsets(b)
	s, err = Read(write(t, b[:frames[len(frames)-1]+10])) // last frame half written
	if err != nil {
		t.Fatal(err)
	}
	if s.Closed || s.UnreadBytes != 10 {
		t.Fatalf("half-written frame: %+v", s)
	}
}

func TestReadCorruptFrame(t *testing.T) {
	b := load(t, capture(t, 2, info()))
	b[frameOffsets(b)[0]+40] ^= 0xFF
	if _, err := Read(write(t, b)); err == nil || !strings.Contains(err.Error(), "bad frame") {
		t.Fatalf("want a bad frame error, got %v", err)
	}
}

func TestCheckHeader(t *testing.T) {
	b := load(t, capture(t, 1, info()))
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
	flipped := append([]byte(nil), b[:HeaderSize]...)
	flipped[200] ^= 1
	if CheckHeader(flipped) == nil {
		t.Fatal("damaged header accepted")
	}
	v4 := append([]byte(nil), b[:HeaderSize]...)
	v4[8] = 4
	if CheckHeader(v4) == nil {
		t.Fatal("version 4 accepted")
	}
}

func TestConvertedCapture(t *testing.T) {
	wi := info()
	wi.Origin, wi.ClockSource, wi.Network = OriginConverted, ClockConverted, NetworkPrivate
	wi.Source = &Source{Format: "captain", FormatVersion: "1.13.0", Skipped: 2, UTCOffsetSeconds: 21600, Metadata: []byte("{ StartTime = 1 }")}
	s, err := Read(capture(t, 1, wi))
	if err != nil {
		t.Fatal(err)
	}
	if s.Origin != OriginConverted || s.Source == nil || s.Source.Format != "captain" || s.Source.Skipped != 2 {
		t.Fatalf("converted capture: %+v %+v", s, s.Source)
	}
	if _, err := Create(filepath.Join(t.TempDir(), "x.xicap"), WriterInfo{Origin: OriginConverted}); err == nil {
		t.Fatal("converted capture without a source accepted")
	}
}

func TestChannelsAndMarkers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.xicap")
	w, err := Create(p, info())
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.Mark(MarkerLogin, ""))
	must(w.WritePacket(Packet{Timestamp: t0, Data: pkt, Provenance: FlagInjected}))
	must(w.WritePacket(Packet{Timestamp: t0 + 1, Data: []byte("search reply"), Channel: ChannelSearch, Opcode: 5}))
	if w.AddExtension(0x8000, []byte{1}) == nil {
		t.Fatal("extension after a packet accepted")
	}
	must(w.Close())
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Packets != 2 {
		t.Fatalf("packets %d", s.Packets)
	}
}

// TestConformanceSet reads the conformance set and compares what a Summary
// holds with each recorded reading.
func TestConformanceSet(t *testing.T) {
	files, err := filepath.Glob("../tests/vectors/*.xicap")
	if err != nil || len(files) < 17 {
		t.Fatalf("conformance set: %d files, %v", len(files), err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			var want struct {
				Refusal           string
				Packets           []json.RawMessage
				Complete          bool
				FooterDamaged     bool
				UnreadBytes       uint64
				CharacterMismatch bool
				Verify            []json.RawMessage
			}
			b, err := os.ReadFile(strings.TrimSuffix(f, ".xicap") + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &want); err != nil {
				t.Fatal(err)
			}
			s, err := Read(f)
			if want.Refusal != "" {
				if err == nil {
					t.Fatalf("read a file that must be refused (%s)", want.Refusal)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var signed bool
			var verified uint64
			json.Unmarshal(want.Verify[0], &signed)
			json.Unmarshal(want.Verify[1], &verified)
			if s.Packets != uint64(len(want.Packets)) || s.Closed != want.Complete || s.FooterDamaged != want.FooterDamaged ||
				s.UnreadBytes != want.UnreadBytes || s.CharacterMismatch != want.CharacterMismatch ||
				s.SignedToEnd != signed || s.VerifiedPackets != verified {
				t.Fatalf("summary %+v, recorded %s", s, b)
			}
		})
	}
}

func TestCustomPolicy(t *testing.T) {
	wi := info()
	wi.Policy = &Policy{Name: "mine", Version: 7, Rules: []Rule{
		{Channel: ChannelGame, Direction: DirBoth, Action: ActionZeroRange, Opcode: 0x015, Ranges: [][2]uint32{{8, 4}}},
	}}
	s, err := Read(capture(t, 1, wi))
	if err != nil {
		t.Fatal(err)
	}
	if s.Policy.Name != "mine" || s.Policy.Version != 7 || s.RuleCount != 1 || s.Policy.Rules[0].Opcode != 0x015 || s.Policy.Rules[0].Action != ActionZeroRange {
		t.Fatalf("policy %+v", s.Policy)
	}
}
