package xicap

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
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
	if !s.Closed || s.Packets != 6 || s.Frames != 2 || s.VersionMajor != 4 || s.CaptureAgent != "test" ||
		s.Character.Name != "Nouurs" || s.Character.ContentID != 0x01020304 || s.Network != NetworkRetail ||
		s.StartContext != StartLogin || s.StartTimestamp != t0 || s.EndTimestamp != t0+1002 ||
		s.Policy.Name != "xicap-default" || s.RuleCount != 6 || len(s.Policy.Rules) != 6 || !s.SignedToEnd || s.VerifiedPackets != 6 || s.Source != nil {
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
	v5 := append([]byte(nil), b[:HeaderSize]...)
	v5[8] = 5
	if CheckHeader(v5) == nil {
		t.Fatal("version 5 accepted")
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

// TestSearchRoundTrip writes the packets of the search vector, recorded
// search messages on channel 1 between game packets, and reads them back.
// The Go binding reads only a Summary; the conformance set checks the bytes.
func TestSearchRoundTrip(t *testing.T) {
	b, err := os.ReadFile("../tests/vectors/4-search.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct{ Packets [][]json.RawMessage }
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "s.xicap")
	w, err := Create(p, info())
	if err != nil {
		t.Fatal(err)
	}
	searches := 0
	for _, f := range v.Packets {
		var pk Packet
		var flags uint16
		var data string
		for i, dst := range []any{&pk.Timestamp, &pk.Channel, &pk.Opcode, &flags, &data} {
			if err := json.Unmarshal(f[i], dst); err != nil {
				t.Fatal(err)
			}
		}
		pk.ClientToServer = flags&1 != 0
		if pk.Data, err = hex.DecodeString(data); err != nil {
			t.Fatal(err)
		}
		if pk.Channel == ChannelSearch {
			searches++
			if pk.Opcode != uint16(pk.Data[0x0B]) {
				t.Fatalf("opcode %#x, byte 0x0B %#x", pk.Opcode, pk.Data[0x0B])
			}
		}
		if err := w.WritePacket(pk); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if searches != 4 || s.Packets != uint64(len(v.Packets)) || !s.SignedToEnd || s.EndTimestamp != t0+744 {
		t.Fatalf("searches %d, summary %+v", searches, s)
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
			var signed, failed bool
			var verified uint64
			json.Unmarshal(want.Verify[0], &signed)
			json.Unmarshal(want.Verify[1], &verified)
			json.Unmarshal(want.Verify[3], &failed)
			if s.Packets != uint64(len(want.Packets)) || s.Closed != want.Complete || s.FooterDamaged != want.FooterDamaged ||
				s.UnreadBytes != want.UnreadBytes || s.CharacterMismatch != want.CharacterMismatch ||
				s.SignedToEnd != signed || s.VerifiedPackets != verified || (s.FirstFailure != 0) != failed {
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

func TestRangeCountLimit(t *testing.T) {
	policy := func(n int) *Policy {
		return &Policy{Name: "many", Version: 1, Rules: []Rule{
			{Channel: ChannelGame, Direction: DirBoth, Action: ActionZeroRange, Opcode: 0x015, Ranges: make([][2]uint32, n)},
		}}
	}
	many := policy(math.MaxUint16)
	for i := range many.Rules[0].Ranges {
		many.Rules[0].Ranges[i] = [2]uint32{8, 4}
	}
	wi := info()
	wi.Policy = many
	if _, err := Read(capture(t, 1, wi)); err != nil {
		t.Fatalf("65,535 ranges: %v", err)
	}
	wi.Policy = policy(math.MaxUint16 + 1)
	if _, err := Create(filepath.Join(t.TempDir(), "over.xicap"), wi); err == nil {
		t.Fatal("65,536 ranges were accepted")
	}
}

func TestPolicyAction(t *testing.T) {
	s, err := Read(capture(t, 1, info()))
	if err != nil {
		t.Fatal(err)
	}
	if a := s.Policy.Action(ChannelGame, DirServerToClient, 0x017); a != ActionZeroRange || !s.CoversDefault {
		t.Fatalf("chat to the client: action %d", a)
	}
	if a := s.Policy.Action(ChannelGame, DirClientToServer, 0x017); a != 0 {
		t.Fatalf("0x017 from the client: action %d", a)
	}
	first := Policy{Rules: []Rule{
		{Channel: ChannelGame, Direction: DirBoth, Action: ActionZeroRange, Opcode: 0x0B5},
		{Channel: ChannelGame, Direction: DirClientToServer, Action: ActionStub, Opcode: 0x0B5},
	}}
	if a := first.Action(ChannelGame, DirClientToServer, 0x0B5); a != ActionZeroRange {
		t.Fatalf("the first matching rule decides: action %d", a)
	}
	if a := (Policy{}).Action(ChannelGame, DirServerToClient, 0x017); a != 0 {
		t.Fatalf("no rules: action %d", a)
	}
}

func TestHeaderLength(t *testing.T) {
	b := load(t, capture(t, 1, info()))
	if n, err := HeaderLength(b[:HeaderPrefix]); err != nil || n != HeaderSize {
		t.Fatalf("header length %d, %v", n, err)
	}
	if _, err := HeaderLength([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x00")); err == nil {
		t.Fatal("PNG accepted")
	}
}

func TestMarkers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.xicap")
	w, err := Create(p, info())
	if err != nil {
		t.Fatal(err)
	}
	step := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	step(w.Mark(MarkerLogin, ""))
	step(w.Write(t0, false, pkt))
	step(w.Mark(MarkerNote, "cap start quest"))
	step(w.Write(t0+10, true, pkt))
	step(w.Write(t0+20, false, pkt))
	step(w.Flush())
	step(w.Mark(MarkerNote, "cap stop quest"))
	step(w.Mark(MarkerNote, "approved\x00revoked")) // marker text is length-delimited: a NUL is text
	step(w.Mark(MarkerLogout, ""))
	step(w.Write(t0+30, false, pkt))
	step(w.Close())

	got, err := Markers(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []Marker{
		{MarkerLogin, "", 0, t0},
		{MarkerNote, "cap start quest", 1, t0 + 10},
		{MarkerNote, "cap stop quest", 3, t0 + 30},
		{MarkerNote, "approved\x00revoked", 3, t0 + 30},
		{MarkerLogout, "", 3, t0 + 30},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("markers:\n got %+v\nwant %+v", got, want)
	}

	if got, err := Markers(capture(t, 2, info())); err != nil || len(got) != 0 {
		t.Fatalf("a capture with no markers: %v %v", got, err)
	}
	if _, err := Markers(filepath.Join(t.TempDir(), "missing.xicap")); err == nil {
		t.Fatal("a missing file: no error")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTranscode(t *testing.T) {
	src := capture(t, 4, info())
	dst := filepath.Join(t.TempDir(), "sealed.xicap")
	mogsafe := [32]byte{9}
	if err := Transcode(src, dst, TranscodeOptions{Seal: true, Agent: "mogsafe test", Seed: mogsafe}); err != nil {
		t.Fatal(err)
	}
	in, _ := Read(src)
	s, err := Read(dst)
	if err != nil {
		t.Fatal(err)
	}
	if s.Packets != in.Packets || !s.SignedToEnd || s.SigningKey != in.SigningKey || s.Seal == nil || !s.Seal.OK || s.Seal.Agent != "mogsafe test" || s.Seal.Key == in.SigningKey {
		t.Fatalf("sealed: %+v, seal %+v", s, s.Seal)
	}
	if in.Seal != nil {
		t.Fatal("a recorder's own file has a seal")
	}

	if in.RecordingMode != ModeDefault {
		t.Fatalf("mode: %v", in.RecordingMode)
	}
	everything := info()
	everything.RecordingMode = ModeEverything
	everything.Policy = &Policy{Name: "none", Version: 1}
	if s, err := Read(capture(t, 1, everything)); err != nil || s.RecordingMode != ModeEverything || s.RuleCount != 0 {
		t.Fatalf("everything: %+v %v", s, err)
	}
	if !reflect.DeepEqual(in.Channels, []uint8{0}) {
		t.Fatalf("channels: %v", in.Channels)
	}

	// The signer writes its own converted file again, naming a signed source.
	ci := info()
	ci.Origin = OriginConverted
	ci.Source = &Source{Format: "xicap", FormatVersion: "3.0", Metadata: []byte("x")}
	conv := capture(t, 2, ci)
	reissued := filepath.Join(t.TempDir(), "reissued.xicap")
	signer := SourceSigner{Key: [32]byte{5}, VerifiedPackets: 6}
	if err := Transcode(conv, reissued, TranscodeOptions{Seed: ci.SigningSeed, Signer: &signer}); err != nil {
		t.Fatal(err)
	}
	s, err = Read(reissued)
	if err != nil {
		t.Fatal(err)
	}
	if !s.SignedToEnd || s.Seal != nil || s.Source == nil || s.Source.Signer == nil || *s.Source.Signer != signer {
		t.Fatalf("reissued: %+v %+v", s, s.Source)
	}

	// Another signer's seed is refused and leaves no file.
	refused := filepath.Join(t.TempDir(), "refused.xicap")
	if err := Transcode(conv, refused, TranscodeOptions{Seed: mogsafe, Signer: &signer}); err == nil {
		t.Fatal("reissued another signer's file")
	}
	if _, err := os.Stat(refused); !os.IsNotExist(err) {
		t.Fatal("a refused transcode left a file")
	}
}

func TestArchivePreset(t *testing.T) {
	wi := info()
	wi.Preset = PresetArchive
	s, err := Read(capture(t, 3, wi))
	if err != nil {
		t.Fatal(err)
	}
	if s.Packets != 9 || !s.SignedToEnd {
		t.Fatalf("archive preset: %+v", s)
	}
}
