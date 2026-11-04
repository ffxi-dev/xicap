package xicap

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// vector is the reading tests/vectors/<name>.json gives for <name>.xicap.
type vector struct {
	Refused      bool
	Complete     bool
	EndTimestamp uint64
	PacketCount  uint64
	Metadata     struct {
		CaptureID         string
		PreviousCaptureID string
		StartTimestamp    uint64
		Origin            Origin
		Network           Network
		CaptureAgent      string
		ClientVersion     string
		Character         struct {
			ContentID   uint32
			CharacterID uint32
			Name        string
			World       string
		}
		Policy struct {
			Name    string
			Version uint32
			Rules   []json.RawMessage
		}
		Source *struct {
			Format         string
			FormatVersion  string
			SkippedRecords uint32
			Metadata       string
		}
	}
	Packets []struct {
		Timestamp uint64
		Channel   uint8
		Markers   []struct {
			Kind MarkerKind
			Text string
		}
	}
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// want is the Summary a vector's JSON describes.
func (v vector) want(t *testing.T) Summary {
	m := v.Metadata
	s := Summary{
		StartTimestamp: m.StartTimestamp,
		Origin:         m.Origin,
		Network:        m.Network,
		CaptureAgent:   m.CaptureAgent,
		ClientVersion:  m.ClientVersion,
		Character:      Character(m.Character),
		Policy:         Policy{Name: m.Policy.Name, Version: m.Policy.Version, Rules: len(m.Policy.Rules)},
		Packets:        uint64(len(v.Packets)),
		Complete:       v.Complete,
	}
	copy(s.CaptureID[:], unhex(t, m.CaptureID))
	copy(s.PreviousCaptureID[:], unhex(t, m.PreviousCaptureID))
	if src := m.Source; src != nil {
		s.Source = &Source{Format: src.Format, FormatVersion: src.FormatVersion, Skipped: src.SkippedRecords, Metadata: unhex(t, src.Metadata)}
	}
	seen := map[uint8]bool{}
	for i, p := range v.Packets {
		s.EndTimestamp = p.Timestamp
		if !seen[p.Channel] {
			seen[p.Channel] = true
			s.Channels = append(s.Channels, p.Channel)
		}
		for _, mk := range p.Markers {
			s.Markers = append(s.Markers, Marker{Kind: mk.Kind, Text: string(unhex(t, mk.Text)), Packet: uint64(i), Timestamp: p.Timestamp})
		}
	}
	return s
}

func TestVectors(t *testing.T) {
	names, _ := filepath.Glob("../tests/vectors/*.json")
	if len(names) < 15 {
		t.Fatalf("found %d vectors", len(names))
	}
	for _, name := range names {
		t.Run(filepath.Base(name), func(t *testing.T) {
			b, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			var v vector
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			got, err := Read(strings.TrimSuffix(name, ".json") + ".xicap")
			if v.Refused {
				if err == nil {
					t.Fatal("read a capture it must refuse")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := v.want(t)
			slices.Sort(want.Channels) // Read gives them in channel order
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got  %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestWriteThenRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.xicap")
	w, err := Create(path, WriterInfo{
		CaptureAgent: "mogsafe", ClientVersion: "1.0", Character: Character{CharacterID: 7, Name: "Rhavyn"},
		Origin: OriginConverted, Network: NetworkPrivate, KeepChat: true, Archive: true,
		Source: &Source{Format: "captain", FormatVersion: "1.4", Skipped: 2, Metadata: []byte("manifest")},
	})
	if err != nil {
		t.Fatal(err)
	}
	chat := append([]byte{0x17, 0x08, 0x01, 0x00}, make([]byte, 28)...)
	chat[30] = 'x'
	for i := range 3 {
		if err := w.Write(Packet{Timestamp: 1000 + uint64(i), Data: chat}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Write(Packet{Timestamp: 1003, Data: []byte{1, 2}, Channel: ChannelSearch, Opcode: 0x0B, Provenance: FlagInjected}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Packet{Timestamp: 1003, Channel: ChannelSearch, Opcode: 0x0B}); err != nil {
		t.Errorf("an empty search packet: %v", err)
	}
	if w.Write(Packet{Timestamp: 1003}) == nil {
		t.Error("an empty game packet is written")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Complete || s.Packets != 5 || s.Policy.Rules != 0 || s.Source.Format != "captain" || string(s.Source.Metadata) != "manifest" ||
		!reflect.DeepEqual(s.Channels, []uint8{0, 1}) || s.StartTimestamp != 1000 || s.EndTimestamp != 1003 {
		t.Errorf("%+v", s)
	}

	b, _ := os.ReadFile(path)
	if err := CheckHeader(b[:HeaderSize]); err != nil {
		t.Error(err)
	}
	b[20] ^= 1
	if CheckHeader(b[:HeaderSize]) == nil {
		t.Error("a damaged header passes")
	}

	dst := filepath.Join(t.TempDir(), "archived.xicap")
	if err := Transcode(path, dst); err != nil {
		t.Fatal(err)
	}
	if a, _ := Read(dst); !reflect.DeepEqual(a, s) {
		t.Errorf("transcode changed the capture: %+v", a)
	}
}
