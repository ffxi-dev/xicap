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
	"io"
	"unsafe"
)

// HeaderSize is the length of a capture's header.
const HeaderSize = 160

type (
	Origin     uint8
	ServerKind uint8
	MarkerKind uint8
	Channel    uint8
)

// See FORMAT.md.
const (
	OriginUnknown   Origin = 0
	OriginLive      Origin = 1
	OriginConverted Origin = 2

	ServerKindUnknown ServerKind = 0
	ServerKindRetail  ServerKind = 1
	ServerKindPrivate ServerKind = 2

	MarkerNote   MarkerKind = 0
	MarkerLogin  MarkerKind = 1
	MarkerLogout MarkerKind = 2

	ChannelGame   Channel = 0
	ChannelSearch Channel = 1

	FlagClientToServer  uint16 = 0x0001
	FlagInjected        uint16 = 0x0002
	FlagBlocked         uint16 = 0x0004
	FlagModified        uint16 = 0x0008
	FlagFirstInDatagram uint16 = 0x0010
	FlagExcluded        uint16 = 0x0100
	FlagRedacted        uint16 = 0x0200
)

type Character struct {
	ContentID   uint32
	CharacterID uint32
	Name        string
	World       string
}

type Source struct {
	Format         string
	FormatVersion  string
	SkippedRecords uint32
	Metadata       []byte // such as captain's manifest.txt
}

type Metadata struct {
	CaptureID         [16]byte
	PreviousCaptureID [16]byte
	StartTimestamp    uint64 // Unix ms
	Origin            Origin
	ServerKind        ServerKind
	CaptureAgent      string
	ClientVersion     string
	Character         Character
	Source            *Source
}

type Marker struct {
	Kind MarkerKind
	Text string
}

type Packet struct {
	Timestamp uint64 // Unix ms
	Flags     uint16
	Channel   Channel
	Opcode    uint16
	Data      []byte
	Markers   []Marker // the markers just before this packet
}

func fromC(c *C.xicap_metadata) Metadata {
	m := Metadata{
		StartTimestamp: uint64(c.start_timestamp),
		Origin:         Origin(c.origin),
		ServerKind:     ServerKind(c.server_kind),
		CaptureAgent:   C.GoString(c.capture_agent),
		ClientVersion:  C.GoString(c.client_version),
		Character: Character{
			ContentID:   uint32(c.content_id),
			CharacterID: uint32(c.character_id),
			Name:        C.GoString(c.character_name),
			World:       C.GoString(c.world_name),
		},
	}
	for i := range 16 {
		m.CaptureID[i], m.PreviousCaptureID[i] = byte(c.capture_id[i]), byte(c.previous_capture_id[i])
	}
	if c.has_source {
		m.Source = &Source{
			Format:         C.GoString(c.source_format),
			FormatVersion:  C.GoString(c.source_format_version),
			SkippedRecords: uint32(c.skipped_records),
			Metadata:       C.GoBytes(unsafe.Pointer(c.source_metadata), C.int(c.source_metadata_size)),
		}
	}
	return m
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

// Reader reads a capture. A cut-off capture reads up to its last whole frame; a bad frame in a complete one is an
// error. It is not safe for concurrent use.
type Reader struct {
	r        *C.xicap_reader
	Metadata Metadata
	// From the trailer: zero in a cut-off capture.
	Complete     bool
	EndTimestamp uint64
	PacketCount  uint64
}

// Open reads the header and blocks of the capture at path.
func Open(path string) (*Reader, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var r Reader
	var i C.xicap_info
	if err := check(C.xicap_reader_open(p, &r.r, &i)); err != nil {
		return nil, err
	}
	r.Metadata = fromC(&i.metadata)
	r.Complete, r.EndTimestamp, r.PacketCount = bool(i.complete), uint64(i.end_timestamp), uint64(i.packet_count)
	return &r, nil
}

// Next returns the next packet, or io.EOF after the last.
func (r *Reader) Next() (Packet, error) {
	var p C.xicap_packet
	var more C.bool
	if err := check(C.xicap_reader_next(r.r, &p, &more)); err != nil {
		return Packet{}, err
	}
	if !more {
		return Packet{}, io.EOF
	}
	out := Packet{
		Timestamp: uint64(p.timestamp),
		Flags:     uint16(p.flags),
		Channel:   Channel(p.channel),
		Opcode:    uint16(p.opcode),
		Data:      C.GoBytes(unsafe.Pointer(p.data), C.int(p.size)),
	}
	for _, m := range unsafe.Slice(p.markers, p.marker_count) {
		out.Markers = append(out.Markers, Marker{MarkerKind(m.kind), C.GoStringN(m.text, C.int(m.text_size))})
	}
	return out, nil
}

// Close frees the reader.
func (r *Reader) Close() {
	C.xicap_reader_close(r.r)
	r.r = nil
}

type WriterOptions struct {
	KeepChat bool // by default xicap zeroes the text of chat
	Archive  bool // smaller files, written more slowly
}

type OutPacket struct {
	Timestamp      uint64 // Unix ms
	ClientToServer bool
	Data           []byte
	Channel        Channel
	Opcode         uint16 // off the game channel; a game packet's header holds its own
	Provenance     uint16 // FlagInjected, FlagBlocked, FlagModified, FlagFirstInDatagram
}

// Writer writes a capture. It is not safe for concurrent use.
type Writer struct{ w *C.xicap_writer }

// Create starts a capture at path. A zero CaptureID gets a random one.
func Create(path string, m Metadata, opt WriterOptions) (*Writer, error) {
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
	cm := C.xicap_metadata{
		start_timestamp: C.uint64_t(m.StartTimestamp),
		origin:          C.uint8_t(m.Origin),
		server_kind:     C.uint8_t(m.ServerKind),
		capture_agent:   str(m.CaptureAgent),
		client_version:  str(m.ClientVersion),
		content_id:      C.uint32_t(m.Character.ContentID),
		character_id:    C.uint32_t(m.Character.CharacterID),
		character_name:  str(m.Character.Name),
		world_name:      str(m.Character.World),
	}
	for i := range 16 {
		cm.capture_id[i], cm.previous_capture_id[i] = C.uint8_t(m.CaptureID[i]), C.uint8_t(m.PreviousCaptureID[i])
	}
	if src := m.Source; src != nil {
		cm.has_source = true
		cm.source_format = str(src.Format)
		cm.source_format_version = str(src.FormatVersion)
		cm.skipped_records = C.uint32_t(src.SkippedRecords)
		if len(src.Metadata) > 0 {
			b := C.CBytes(src.Metadata)
			owned = append(owned, b)
			cm.source_metadata, cm.source_metadata_size = (*C.uint8_t)(b), C.size_t(len(src.Metadata))
		}
	}
	var w Writer
	if err := check(C.xicap_writer_open(str(path), &cm, C.bool(opt.KeepChat), C.bool(opt.Archive), &w.w)); err != nil {
		return nil, err
	}
	return &w, nil
}

// Write adds one packet, with its chat text zeroed unless the writer keeps chat.
func (w *Writer) Write(p OutPacket) error {
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
// difference it returns an error. src and dst must be different files; an existing dst is overwritten, and removed if
// the rewrite then fails.
func Transcode(src, dst string) error {
	s, d := C.CString(src), C.CString(dst)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	return check(C.xicap_transcode(s, d))
}
