// Package xicap reads and writes xicap captures through the C++ library, with cgo. It needs a C++23 compiler and
// libzstd.
package xicap

/*
#cgo CXXFLAGS: -std=c++23 -I${SRCDIR}/../../include -I${SRCDIR}/../../src
#cgo LDFLAGS: -lzstd
#include <stdlib.h>
#include "capi.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// HeaderSize is the length of a capture's header.
const HeaderSize = 160

type (
	Origin     uint8
	Network    uint8
	MarkerKind uint8
)

// See FORMAT.md.
const (
	OriginUnknown   Origin = 0
	OriginLive      Origin = 1
	OriginConverted Origin = 2

	NetworkUnknown Network = 0
	NetworkRetail  Network = 1
	NetworkPrivate Network = 2

	MarkerNote   MarkerKind = 0
	MarkerLogin  MarkerKind = 1
	MarkerLogout MarkerKind = 2

	ChannelGame   uint8 = 0
	ChannelSearch uint8 = 1

	FlagInjected     uint16 = 0x0002
	FlagBlocked      uint16 = 0x0004
	FlagModified     uint16 = 0x0008
	FlagFirstInChunk uint16 = 0x0010
)

type Character struct {
	ContentID   uint32
	CharacterID uint32
	Name        string
	World       string
}

// Source is what a converted capture records about the file it came from.
type Source struct {
	Format         string
	FormatVersion  string
	SkippedRecords uint32
	Metadata       []byte // such as captain's manifest.txt
}

// Policy names the exclusion policy a capture was written with. One with no rules kept chat.
type Policy struct {
	Name    string
	Version uint32
	Rules   int
}

// Metadata is what a capture's header and blocks say about it.
type Metadata struct {
	CaptureID         [16]byte
	PreviousCaptureID [16]byte
	StartTimestamp    uint64 // Unix ms
	Origin            Origin
	Network           Network
	CaptureAgent      string
	ClientVersion     string
	Character         Character
	Policy            Policy
	Source            *Source
}

// Marker is a note, login, or logout, with the packet it precedes.
type Marker struct {
	Kind      MarkerKind
	Text      string
	Packet    uint64
	Timestamp uint64
}

// Summary is what Read learns from a capture. EndTimestamp and PacketCount come from the packets read, so a cut-off
// capture has them too.
type Summary struct {
	Metadata
	EndTimestamp uint64
	PacketCount  uint64
	Complete     bool    // a trailer ends the file
	Channels     []uint8 // in order
	Markers      []Marker
}

func check(err *C.char) error {
	if err == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(err))
	return errors.New(C.GoString(err))
}

// CheckHeader checks that b starts with a whole header this library reads.
func CheckHeader(b []byte) error {
	if len(b) < HeaderSize {
		return errors.New("xicap: short header")
	}
	return check(C.xicap_check_header((*C.uint8_t)(unsafe.SliceData(b)), C.size_t(len(b))))
}

// Read reads the capture at path. A cut-off capture reads up to its last whole frame; a bad frame in a complete one
// is an error.
func Read(path string) (Summary, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var s C.xicap_summary
	if err := check(C.xicap_read(p, &s)); err != nil {
		return Summary{}, err
	}
	defer C.xicap_free_summary(&s)

	out := Summary{
		Metadata: Metadata{
			CaptureID:         *(*[16]byte)(unsafe.Pointer(&s.capture_id)),
			PreviousCaptureID: *(*[16]byte)(unsafe.Pointer(&s.previous_capture_id)),
			StartTimestamp:    uint64(s.start_timestamp),
			Origin:            Origin(s.origin),
			Network:           Network(s.network),
			CaptureAgent:      C.GoString(&s.capture_agent[0]),
			ClientVersion:     C.GoString(&s.client_version[0]),
			Character: Character{
				ContentID:   uint32(s.content_id),
				CharacterID: uint32(s.character_id),
				Name:        C.GoString(&s.character_name[0]),
				World:       C.GoString(&s.world_name[0]),
			},
			Policy: Policy{Name: C.GoString(&s.policy_name[0]), Version: uint32(s.policy_version), Rules: int(s.policy_rules)},
		},
		EndTimestamp: uint64(s.end_timestamp),
		PacketCount:  uint64(s.packet_count),
		Complete:     bool(s.complete),
	}
	if s.has_source {
		out.Source = &Source{
			Format:         C.GoString(&s.source_format[0]),
			FormatVersion:  C.GoString(&s.source_format_version[0]),
			SkippedRecords: uint32(s.skipped_records),
			Metadata:       C.GoBytes(unsafe.Pointer(s.source_metadata), C.int(s.source_metadata_size)),
		}
	}
	for c, used := range s.channels {
		if used {
			out.Channels = append(out.Channels, uint8(c))
		}
	}
	for _, m := range unsafe.Slice(s.markers, s.marker_count) {
		out.Markers = append(out.Markers, Marker{MarkerKind(m.kind), C.GoStringN(m.text, C.int(m.text_size)), uint64(m.packet), uint64(m.timestamp)})
	}
	return out, nil
}

// WriterInfo is what a new capture's header and blocks record.
type WriterInfo struct {
	CaptureAgent  string
	ClientVersion string
	Character     Character
	Origin        Origin
	Network       Network
	Source        *Source
	KeepChat      bool // write no exclusion rules; by default xicap zeroes the text of chat
	Archive       bool // smaller files, written more slowly
}

// Packet is one packet to write.
type Packet struct {
	Timestamp      uint64 // Unix ms
	ClientToServer bool
	Data           []byte
	Channel        uint8
	Opcode         uint16 // off the game channel; a game packet's header holds its own
	Provenance     uint16 // FlagInjected, FlagBlocked, FlagModified, FlagFirstInChunk
}

// Writer writes a capture. It is not safe for concurrent use.
type Writer struct{ w *C.xicap_writer }

// Create starts a capture at path.
func Create(path string, info WriterInfo) (*Writer, error) {
	var owned []unsafe.Pointer
	defer func() {
		for _, p := range owned {
			C.free(p)
		}
	}()
	str := func(s string) *C.char {
		c := C.CString(s)
		owned = append(owned, unsafe.Pointer(c))
		return c
	}
	ci := C.xicap_writer_info{
		capture_agent:  str(info.CaptureAgent),
		client_version: str(info.ClientVersion),
		content_id:     C.uint32_t(info.Character.ContentID),
		character_id:   C.uint32_t(info.Character.CharacterID),
		character_name: str(info.Character.Name),
		world_name:     str(info.Character.World),
		origin:         C.uint8_t(info.Origin),
		network:        C.uint8_t(info.Network),
		keep_chat:      C.bool(info.KeepChat),
		archive:        C.bool(info.Archive),
	}
	if src := info.Source; src != nil {
		ci.has_source = true
		ci.source_format = str(src.Format)
		ci.source_format_version = str(src.FormatVersion)
		ci.skipped_records = C.uint32_t(src.SkippedRecords)
		if len(src.Metadata) > 0 {
			m := C.CBytes(src.Metadata)
			owned = append(owned, m)
			ci.source_metadata, ci.source_metadata_size = (*C.uint8_t)(m), C.size_t(len(src.Metadata))
		}
	}
	var w Writer
	if err := check(C.xicap_writer_open(str(path), &ci, &w.w)); err != nil {
		return nil, err
	}
	return &w, nil
}

// Write adds one packet, after the exclusion policy.
func (w *Writer) Write(p Packet) error {
	return check(C.xicap_writer_write(w.w, C.uint64_t(p.Timestamp), C.bool(p.ClientToServer), C.uint8_t(p.Channel), C.uint16_t(p.Opcode),
		C.uint16_t(p.Provenance), (*C.uint8_t)(unsafe.SliceData(p.Data)), C.size_t(len(p.Data))))
}

// Close writes the last frame and the trailer. The Writer cannot be used afterwards.
func (w *Writer) Close() error {
	err := check(C.xicap_writer_close(w.w))
	w.w = nil
	return err
}

// Transcode rewrites src at dst at archive size, then reads dst back and compares it with src packet by packet. On any
// difference it returns an error and leaves dst as it was.
func Transcode(src, dst string) error {
	s, d := C.CString(src), C.CString(dst)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	return check(C.xicap_transcode(s, d))
}
