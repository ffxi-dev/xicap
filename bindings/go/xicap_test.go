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

// hexBytes reads the lowercase hex the vectors hold bytes as.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) (err error) {
	var s string
	if err = json.Unmarshal(b, &s); err == nil {
		*h, err = hex.DecodeString(s)
	}
	return err
}

// vector is the reading tests/vectors/<name>.json gives for <name>.xicap.
type vector struct {
	Refused      bool
	Complete     bool
	EndTimestamp uint64
	PacketCount  uint64
	Metadata     struct {
		CaptureID, PreviousCaptureID hexBytes
		StartTimestamp               uint64
		Origin                       Origin
		ServerKind                   ServerKind
		CaptureAgent, ClientVersion  string
		Character                    Character
		Policy                       struct {
			Name    string
			Version uint32
			Rules   []json.RawMessage
		}
		Source *struct {
			Format, FormatVersion string
			SkippedRecords        uint32
			Metadata              hexBytes
		}
	}
	Packets []struct {
		Timestamp uint64
		Channel   uint8
		Markers   []struct {
			Kind MarkerKind
			Text hexBytes
		}
	}
}

// summary is what Read must make of the vector's capture.
func (v vector) summary() Summary {
	m := v.Metadata
	s := Summary{
		Metadata: Metadata{
			CaptureID:         [16]byte(m.CaptureID),
			PreviousCaptureID: [16]byte(m.PreviousCaptureID),
			StartTimestamp:    m.StartTimestamp,
			Origin:            m.Origin,
			ServerKind:        m.ServerKind,
			CaptureAgent:      m.CaptureAgent,
			ClientVersion:     m.ClientVersion,
			Character:         m.Character,
			Policy:            Policy{m.Policy.Name, m.Policy.Version, len(m.Policy.Rules)},
		},
		Complete:     v.Complete,
		EndTimestamp: v.EndTimestamp,
		PacketCount:  v.PacketCount,
		PacketsRead:  uint64(len(v.Packets)),
	}
	if src := m.Source; src != nil {
		s.Source = &Source{src.Format, src.FormatVersion, src.SkippedRecords, src.Metadata}
	}
	for i, p := range v.Packets {
		s.LastTimestamp = p.Timestamp
		if !slices.Contains(s.Channels, p.Channel) {
			s.Channels = append(s.Channels, p.Channel)
		}
		for _, mk := range p.Markers {
			s.Markers = append(s.Markers, Marker{mk.Kind, string(mk.Text), uint64(i), p.Timestamp})
		}
	}
	slices.Sort(s.Channels)
	return s
}

func TestVectors(t *testing.T) {
	names, _ := filepath.Glob("../../tests/vectors/*.json")
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
			if want := v.summary(); !reflect.DeepEqual(got, want) {
				t.Errorf("got  %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestWriteThenRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.xicap")
	w, err := Create(path, WriterInfo{
		CaptureAgent: "mogsafe", ClientVersion: "1.0", Character: Character{CharacterID: 7, Name: "Rhavyn"},
		Origin: OriginConverted, ServerKind: ServerKindPrivate, KeepChat: true, Archive: true,
		Source: &Source{Format: "captain", FormatVersion: "1.4", SkippedRecords: 2, Metadata: []byte("manifest")},
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
	if !s.Complete || s.PacketCount != 5 || s.PacketsRead != 5 || s.Policy.Rules != 0 || s.Source.Format != "captain" || string(s.Source.Metadata) != "manifest" ||
		!reflect.DeepEqual(s.Channels, []uint8{0, 1}) || s.StartTimestamp != 1000 || s.EndTimestamp != 1003 || s.LastTimestamp != 1003 {
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
