package xicap

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
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
		Source                       *struct {
			Format, FormatVersion string
			SkippedRecords        uint32
			Metadata              hexBytes
		}
	}
	Packets []struct {
		Timestamp uint64
		Flags     uint16
		Channel   uint8
		Opcode    uint16
		Data      hexBytes
		Markers   []struct {
			Kind MarkerKind
			Text hexBytes
		}
	}
}

// capture is what a Reader makes of a file: its metadata, trailer, and every packet.
type capture struct {
	Metadata     Metadata
	Complete     bool
	EndTimestamp uint64
	PacketCount  uint64
	Packets      []Packet
}

func read(path string) (capture, error) {
	r, err := Open(path)
	if err != nil {
		return capture{}, err
	}
	defer r.Close()
	c := capture{r.Metadata, r.Complete, r.EndTimestamp, r.PacketCount, nil}
	for {
		p, err := r.Next()
		if errors.Is(err, io.EOF) {
			return c, nil
		}
		if err != nil {
			return capture{}, err
		}
		c.Packets = append(c.Packets, p)
	}
}

func (v vector) capture() capture {
	m := v.Metadata
	c := capture{
		Metadata: Metadata{
			CaptureID:         [16]byte(m.CaptureID),
			PreviousCaptureID: [16]byte(m.PreviousCaptureID),
			StartTimestamp:    m.StartTimestamp,
			Origin:            m.Origin,
			ServerKind:        m.ServerKind,
			CaptureAgent:      m.CaptureAgent,
			ClientVersion:     m.ClientVersion,
			Character:         m.Character,
		},
		Complete:     v.Complete,
		EndTimestamp: v.EndTimestamp,
		PacketCount:  v.PacketCount,
	}
	if src := m.Source; src != nil {
		c.Metadata.Source = &Source{src.Format, src.FormatVersion, src.SkippedRecords, src.Metadata}
	}
	for _, p := range v.Packets {
		out := Packet{Timestamp: p.Timestamp, Flags: p.Flags, Channel: p.Channel, Opcode: p.Opcode, Data: p.Data}
		for _, mk := range p.Markers {
			out.Markers = append(out.Markers, Marker{mk.Kind, string(mk.Text)})
		}
		c.Packets = append(c.Packets, out)
	}
	return c
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
			got, err := read(strings.TrimSuffix(name, ".json") + ".xicap")
			if v.Refused {
				if err == nil {
					t.Fatal("read a capture it must refuse")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := v.capture(); !reflect.DeepEqual(got, want) {
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
		if err := w.Write(OutPacket{Timestamp: 1000 + uint64(i), Data: chat}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Write(OutPacket{Timestamp: 1003, Data: []byte{1, 2}, Channel: ChannelSearch, Opcode: 0x0B, Provenance: FlagInjected}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(OutPacket{Timestamp: 1003, Channel: ChannelSearch, Opcode: 0x0B}); err != nil {
		t.Errorf("an empty search packet: %v", err)
	}
	if w.Write(OutPacket{Timestamp: 1003}) == nil {
		t.Error("an empty game packet is written")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	c, err := read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Complete || c.PacketCount != 5 || len(c.Packets) != 5 || c.Metadata.Source.Format != "captain" || string(c.Metadata.Source.Metadata) != "manifest" ||
		c.Metadata.StartTimestamp != 1000 || c.EndTimestamp != 1003 || c.Packets[0].Data[30] != 'x' || c.Packets[0].Flags&FlagRedacted != 0 {
		t.Errorf("%+v", c)
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
	if a, _ := read(dst); !reflect.DeepEqual(a, c) {
		t.Errorf("transcode changed the capture: %+v", a)
	}
}
