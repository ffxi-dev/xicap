// Package xicap reads and writes xicap captures through the C++ library, with cgo. It needs a C++23 compiler and
// libzstd.
package xicap

/*
#cgo CXXFLAGS: -std=c++23 -I${SRCDIR}/../include -I${SRCDIR}/../src
#cgo LDFLAGS: -lzstd
#include <stdlib.h>
#include "capi.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// HeaderSize is the length of a capture's header, the least CheckHeader needs.
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

// Source is what a converted capture records about what it was converted from.
type Source struct {
	Format        string
	FormatVersion string
	Skipped       uint32
	Metadata      []byte // such as captain's manifest.txt
}

// Policy names the exclusion policy a capture was written with. A policy with no rules kept chat.
type Policy struct {
	Name    string
	Version uint32
	Rules   int
}

// Marker is a note, login, or logout, with the packet it sits before.
type Marker struct {
	Kind      MarkerKind
	Text      string
	Packet    uint64 // that packet's index
	Timestamp uint64 // that packet's time, Unix ms
}

// Summary is what Read learns from a capture's header, blocks, and every packet.
type Summary struct {
	CaptureID         [16]byte
	PreviousCaptureID [16]byte
	StartTimestamp    uint64 // Unix ms
	EndTimestamp      uint64 // Unix ms of the last packet read
	Origin            Origin
	Network           Network
	CaptureAgent      string
	ClientVersion     string
	Character         Character
	Policy            Policy
	Source            *Source // set on converted captures
	Packets           uint64
	Complete          bool    // a trailer ends the file
	Channels          []uint8 // the channels the packets use
	Markers           []Marker
}

type errBuf [256]C.char

func (e *errBuf) err() error { return errors.New(C.GoString(&e[0])) }

// CheckHeader checks that b starts with a whole header this library reads.
func CheckHeader(b []byte) error {
	if len(b) < HeaderSize {
		return errors.New("xicap: short header")
	}
	var e errBuf
	if C.xicap_check_header((*C.uint8_t)(unsafe.SliceData(b)), C.size_t(len(b)), &e[0], C.size_t(len(e))) != 0 {
		return e.err()
	}
	return nil
}

// Read reads the capture at path. A cut-off capture reads up to its last whole frame; a bad frame in a complete one
// is an error.
func Read(path string) (Summary, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var s C.xicap_summary
	var e errBuf
	if C.xicap_read(p, &s, &e[0], C.size_t(len(e))) != 0 {
		return Summary{}, e.err()
	}
	defer C.xicap_free_summary(&s)
	out := Summary{
		CaptureID:         *(*[16]byte)(unsafe.Pointer(&s.capture_id[0])),
		PreviousCaptureID: *(*[16]byte)(unsafe.Pointer(&s.previous_capture_id[0])),
		StartTimestamp:    uint64(s.start_timestamp),
		EndTimestamp:      uint64(s.end_timestamp),
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
		Policy:   Policy{Name: C.GoString(&s.policy_name[0]), Version: uint32(s.policy_version), Rules: int(s.policy_rules)},
		Packets:  uint64(s.packets),
		Complete: s.complete != 0,
	}
	if s.has_source != 0 {
		out.Source = &Source{Format: C.GoString(&s.source_format[0]), FormatVersion: C.GoString(&s.source_format_version[0]), Skipped: uint32(s.skipped_records),
			Metadata: C.GoBytes(unsafe.Pointer(s.source_metadata), C.int(s.source_metadata_size))}
	}
	for c := range 256 {
		if s.channels[c/8]&(1<<(c%8)) != 0 {
			out.Channels = append(out.Channels, uint8(c))
		}
	}
	for _, m := range unsafe.Slice(s.markers, int(s.marker_count)) {
		out.Markers = append(out.Markers, Marker{Kind: MarkerKind(m.kind), Text: C.GoStringN(m.text, C.int(m.text_size)), Packet: uint64(m.packet), Timestamp: uint64(m.timestamp)})
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
	KeepChat      bool // write no exclusion rules; otherwise xicap's default policy zeroes the text of chat
	Archive       bool // smaller files, written more slowly
}

// Packet is one packet to write.
type Packet struct {
	Timestamp      uint64 // Unix ms
	ClientToServer bool
	Data           []byte
	Channel        uint8
	Opcode         uint16 // off the game channel; game packets carry their own
	Provenance     uint16 // FlagInjected, FlagBlocked, FlagModified, FlagFirstInChunk
}

// Writer writes a capture. It is not safe for concurrent use.
type Writer struct{ w *C.xicap_writer }

// Create starts a capture at path.
func Create(path string, info WriterInfo) (*Writer, error) {
	var free []unsafe.Pointer
	defer func() {
		for _, p := range free {
			C.free(p)
		}
	}()
	cstr := func(s string) *C.char {
		c := C.CString(s)
		free = append(free, unsafe.Pointer(c))
		return c
	}
	ci := C.xicap_writer_info{
		capture_agent:  cstr(info.CaptureAgent),
		client_version: cstr(info.ClientVersion),
		content_id:     C.uint32_t(info.Character.ContentID),
		character_id:   C.uint32_t(info.Character.CharacterID),
		character_name: cstr(info.Character.Name),
		world_name:     cstr(info.Character.World),
		origin:         C.uint8_t(info.Origin),
		network:        C.uint8_t(info.Network),
		keep_chat:      cbool(info.KeepChat),
		archive:        cbool(info.Archive),
	}
	if src := info.Source; src != nil {
		ci.has_source = 1
		ci.source_format = cstr(src.Format)
		ci.source_format_version = cstr(src.FormatVersion)
		ci.skipped_records = C.uint32_t(src.Skipped)
		if len(src.Metadata) > 0 {
			m := C.CBytes(src.Metadata)
			free = append(free, m)
			ci.source_metadata, ci.source_metadata_size = (*C.uint8_t)(m), C.size_t(len(src.Metadata))
		}
	}
	p := cstr(path)
	var e errBuf
	w := C.xicap_writer_open(p, &ci, &e[0], C.size_t(len(e)))
	if w == nil {
		return nil, e.err()
	}
	return &Writer{w}, nil
}

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// Write adds one packet, after the exclusion policy.
func (w *Writer) Write(p Packet) error {
	var e errBuf
	if C.xicap_writer_write(w.w, C.uint64_t(p.Timestamp), cbool(p.ClientToServer), C.uint8_t(p.Channel), C.uint16_t(p.Opcode), C.uint16_t(p.Provenance),
		(*C.uint8_t)(unsafe.SliceData(p.Data)), C.size_t(len(p.Data)), &e[0], C.size_t(len(e))) != 0 {
		return e.err()
	}
	return nil
}

// Close writes the last frame and the trailer. The Writer cannot be used afterwards.
func (w *Writer) Close() error {
	var e errBuf
	rc := C.xicap_writer_close(w.w, &e[0], C.size_t(len(e)))
	w.w = nil
	if rc != 0 {
		return e.err()
	}
	return nil
}

// Transcode rewrites src at dst at archive size, then reads dst back and compares it with src packet by packet. On any
// difference it returns an error and leaves dst as it was.
func Transcode(src, dst string) error {
	s, d := C.CString(src), C.CString(dst)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	var e errBuf
	if C.xicap_transcode(s, d, &e[0], C.size_t(len(e))) != 0 {
		return e.err()
	}
	return nil
}
