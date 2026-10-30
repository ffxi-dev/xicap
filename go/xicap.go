// Package xicap is the Go binding for the xicap C++ library. It needs cgo, a
// C++20 compiler, and libzstd.
package xicap

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/monocypher
#cgo CXXFLAGS: -std=c++20 -I${SRCDIR}/../include -I${SRCDIR}/../src -I${SRCDIR}/../third_party/monocypher
#cgo LDFLAGS: -lzstd
#include <stdlib.h>
#include "capi.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// HeaderSize is the length of a format 3.0 header, the least a capture's
// first bytes must hold before CheckHeader can judge them.
const HeaderSize = 384

// Values of the header's provenance fields. See FORMAT.md.
type (
	ClockSource  uint8
	Origin       uint8
	Network      uint8
	StartContext uint8
	MarkerKind   uint8
)

const (
	ClockUnknown   ClockSource = 0
	ClockLive      ClockSource = 1
	ClockConverted ClockSource = 2

	OriginUnknown   Origin = 0
	OriginLive      Origin = 1
	OriginConverted Origin = 2

	NetworkUnknown Network = 0
	NetworkRetail  Network = 1
	NetworkPrivate Network = 2

	StartUnknown    StartContext = 0
	StartLogin      StartContext = 1
	StartMidSession StartContext = 2

	MarkerNote   MarkerKind = 0
	MarkerLogin  MarkerKind = 1
	MarkerLogout MarkerKind = 2
)

// Channels and packet flags. See FORMAT.md.
const (
	ChannelGame   uint8 = 0
	ChannelSearch uint8 = 1

	FlagInjected     uint16 = 0x0002
	FlagBlocked      uint16 = 0x0004
	FlagModified     uint16 = 0x0008
	FlagFirstInChunk uint16 = 0x0010
)

// Character is the capture's character, from its header.
type Character struct {
	ContentID   uint32
	CharacterID uint32
	WorldID     uint16
	Name        string
	World       string
}

// SourceSummary describes what a converted capture was converted from.
type SourceSummary struct {
	Format        string
	FormatVersion string
	Skipped       uint32
}

// Summary describes a capture after reading every frame and checking its
// signatures.
type Summary struct {
	VersionMajor      uint8
	VersionMinor      uint8
	CaptureAgent      string
	ClientVersion     string
	CaptureID         [16]byte
	PreviousCaptureID [16]byte
	Character         Character
	ClockSource       ClockSource
	Origin            Origin
	Network           Network
	StartContext      StartContext
	StartZoneID       uint16 // the first packet frame's zone
	EndZoneID         uint16 // the last packet frame's zone
	StartTimestamp    uint64 // Unix ms
	EndTimestamp      uint64 // Unix ms of the last packet read
	Packets           uint64
	Frames            uint64 // packet frames
	Closed            bool   // a valid footer ends the file
	FooterDamaged     bool
	UnreadBytes       uint64 // after the last intact frame of a cut-off capture
	CharacterMismatch bool   // a zone-in names a character other than the header's
	PolicyName        string
	PolicyVersion     uint32
	Source            *SourceSummary // set on converted captures
	SigningKey        [32]byte
	SignedToEnd       bool   // the footer's signature verifies
	VerifiedPackets   uint64 // packets covered by the last good signature
}

func cerr(msg *[256]C.char) error { return errors.New(C.GoString(&msg[0])) }

// CheckHeader checks that b starts with a whole header this library can read.
func CheckHeader(b []byte) error {
	if len(b) < HeaderSize {
		return errors.New("xicap: short header")
	}
	var msg [256]C.char
	if C.xicap_check_header((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &msg[0], C.size_t(len(msg))) != 0 {
		return cerr(&msg)
	}
	return nil
}

// Read reads the capture at path, decoding every frame and checking its
// signatures. A cut-off capture reads up to its last intact frame; a bad frame
// in a closed capture is an error.
func Read(path string) (Summary, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var s C.xicap_summary
	var msg [256]C.char
	if C.xicap_read(p, &s, &msg[0], C.size_t(len(msg))) != 0 {
		return Summary{}, cerr(&msg)
	}
	out := Summary{
		VersionMajor:      uint8(s.version_major),
		VersionMinor:      uint8(s.version_minor),
		CaptureAgent:      C.GoString(&s.capture_agent[0]),
		ClientVersion:     C.GoString(&s.client_version[0]),
		CaptureID:         *(*[16]byte)(unsafe.Pointer(&s.capture_id[0])),
		PreviousCaptureID: *(*[16]byte)(unsafe.Pointer(&s.previous_capture_id[0])),
		Character: Character{
			ContentID:   uint32(s.content_id),
			CharacterID: uint32(s.character_id),
			WorldID:     uint16(s.world_id),
			Name:        C.GoString(&s.character_name[0]),
			World:       C.GoString(&s.world_name[0]),
		},
		ClockSource:       ClockSource(s.clock_source),
		Origin:            Origin(s.origin),
		Network:           Network(s.network),
		StartContext:      StartContext(s.start_context),
		StartZoneID:       uint16(s.start_zone_id),
		EndZoneID:         uint16(s.end_zone_id),
		StartTimestamp:    uint64(s.start_timestamp),
		EndTimestamp:      uint64(s.end_timestamp),
		Packets:           uint64(s.packets),
		Frames:            uint64(s.frames),
		Closed:            s.complete != 0,
		FooterDamaged:     s.footer_damaged != 0,
		UnreadBytes:       uint64(s.unread_bytes),
		CharacterMismatch: s.character_mismatch != 0,
		PolicyName:        C.GoString(&s.policy_name[0]),
		PolicyVersion:     uint32(s.policy_version),
		SigningKey:        *(*[32]byte)(unsafe.Pointer(&s.signing_key[0])),
		SignedToEnd:       s.signed_to_end != 0,
		VerifiedPackets:   uint64(s.verified_packets),
	}
	if s.has_source != 0 {
		out.Source = &SourceSummary{
			Format:        C.GoString(&s.source_format[0]),
			FormatVersion: C.GoString(&s.source_format_version[0]),
			Skipped:       uint32(s.skipped_records),
		}
	}
	return out, nil
}

// Source is what a converted capture records about its source.
type Source struct {
	Format           string
	FormatVersion    string
	Skipped          uint32
	UTCOffsetSeconds int32
	Hash             [64]byte // SHA-512 of the source file
	Metadata         []byte   // such as captain's manifest.txt
}

// WriterInfo is what a new capture's header and format-level blocks record.
type WriterInfo struct {
	CaptureAgent      string
	ClientVersion     string
	Character         Character
	ClockSource       ClockSource
	Origin            Origin
	Network           Network
	StartContext      StartContext
	PreviousCaptureID [16]byte
	SigningSeed       [32]byte // the recorder's Ed25519 seed
	Source            *Source  // required with OriginConverted
	NoDictionary      bool
}

// Writer creates a capture. It is not safe for concurrent use.
type Writer struct{ w *C.xicap_writer }

// Create starts a capture at path.
func Create(path string, info WriterInfo) (*Writer, error) {
	var allocs []unsafe.Pointer
	defer func() {
		for _, a := range allocs {
			C.free(a)
		}
	}()
	cstr := func(s string) *C.char {
		c := C.CString(s)
		allocs = append(allocs, unsafe.Pointer(c))
		return c
	}
	ci := C.xicap_writer_info{
		capture_agent:  cstr(info.CaptureAgent),
		client_version: cstr(info.ClientVersion),
		content_id:     C.uint32_t(info.Character.ContentID),
		character_id:   C.uint32_t(info.Character.CharacterID),
		world_id:       C.uint16_t(info.Character.WorldID),
		character_name: cstr(info.Character.Name),
		world_name:     cstr(info.Character.World),
		clock_source:   C.uint8_t(info.ClockSource),
		origin:         C.uint8_t(info.Origin),
		network:        C.uint8_t(info.Network),
		start_context:  C.uint8_t(info.StartContext),
	}
	if !info.NoDictionary {
		ci.dictionary = 1
	}
	*(*[16]byte)(unsafe.Pointer(&ci.previous_capture_id[0])) = info.PreviousCaptureID
	*(*[32]byte)(unsafe.Pointer(&ci.signing_seed[0])) = info.SigningSeed
	if src := info.Source; src != nil {
		ci.has_source = 1
		ci.source_format = cstr(src.Format)
		ci.source_format_version = cstr(src.FormatVersion)
		ci.skipped_records = C.uint32_t(src.Skipped)
		ci.utc_offset_seconds = C.int32_t(src.UTCOffsetSeconds)
		*(*[64]byte)(unsafe.Pointer(&ci.source_hash[0])) = src.Hash
		if len(src.Metadata) > 0 {
			m := C.CBytes(src.Metadata)
			allocs = append(allocs, m)
			ci.metadata = (*C.uint8_t)(m)
			ci.metadata_size = C.size_t(len(src.Metadata))
		}
	}
	p := cstr(path)
	var msg [256]C.char
	w := C.xicap_writer_open(p, &ci, &msg[0], C.size_t(len(msg)))
	if w == nil {
		return nil, cerr(&msg)
	}
	return &Writer{w}, nil
}

// Packet is one packet to write.
type Packet struct {
	Timestamp      uint64 // Unix ms
	ClientToServer bool
	Data           []byte
	Channel        uint8
	Opcode         uint16 // used off the game channel; game packets carry their own
	Provenance     uint16 // FlagInjected, FlagBlocked, FlagModified, FlagFirstInChunk
}

// WritePacket adds one packet.
func (w *Writer) WritePacket(p Packet) error {
	if len(p.Data) == 0 {
		return errors.New("xicap: empty packet")
	}
	dir := C.int(0)
	if p.ClientToServer {
		dir = 1
	}
	var msg [256]C.char
	if C.xicap_writer_write(w.w, C.uint64_t(p.Timestamp), dir, C.uint8_t(p.Channel), C.uint16_t(p.Opcode), C.uint16_t(p.Provenance),
		(*C.uint8_t)(unsafe.Pointer(&p.Data[0])), C.size_t(len(p.Data)), &msg[0], C.size_t(len(msg))) != 0 {
		return cerr(&msg)
	}
	return nil
}

// Write adds one game packet; timestamp is Unix ms.
func (w *Writer) Write(timestamp uint64, clientToServer bool, data []byte) error {
	return w.WritePacket(Packet{Timestamp: timestamp, ClientToServer: clientToServer, Data: data})
}

// AddExtension adds a metadata block (type 0x8000 and up) before the first packet.
func (w *Writer) AddExtension(typ uint32, data []byte) error {
	var msg [256]C.char
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	if C.xicap_writer_add_extension(w.w, C.uint32_t(typ), ptr, C.size_t(len(data)), &msg[0], C.size_t(len(msg))) != 0 {
		return cerr(&msg)
	}
	return nil
}

// Mark places a marker just before the next packet. A login or logout also
// ends the frame being built and signs what came before.
func (w *Writer) Mark(kind MarkerKind, text string) error {
	t := C.CString(text)
	defer C.free(unsafe.Pointer(t))
	var msg [256]C.char
	if C.xicap_writer_mark(w.w, C.uint8_t(kind), t, &msg[0], C.size_t(len(msg))) != 0 {
		return cerr(&msg)
	}
	return nil
}

// Flush ends the frame being built, or signs an idle capture's last frames.
func (w *Writer) Flush() error {
	var msg [256]C.char
	if C.xicap_writer_flush(w.w, &msg[0], C.size_t(len(msg))) != 0 {
		return cerr(&msg)
	}
	return nil
}

// IDs returns the capture's id and the recorder's public key.
func (w *Writer) IDs() (captureID [16]byte, publicKey [32]byte) {
	C.xicap_writer_ids(w.w, (*C.uint8_t)(unsafe.Pointer(&captureID[0])), (*C.uint8_t)(unsafe.Pointer(&publicKey[0])))
	return
}

// Close writes the footer. The Writer cannot be used afterwards.
func (w *Writer) Close() error {
	var msg [256]C.char
	rc := C.xicap_writer_close(w.w, &msg[0], C.size_t(len(msg)))
	w.w = nil
	if rc != 0 {
		return cerr(&msg)
	}
	return nil
}
