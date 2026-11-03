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
	"fmt"
	"math"
	"os"
	"unsafe"
)

// HeaderSize is the length of a format 3.0 or 4.0 header, the least a
// capture's first bytes must hold before CheckHeader can judge them.
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

// Exclusion rule directions and actions. See FORMAT.md, Exclusion.
const (
	DirServerToClient uint8 = 0
	DirClientToServer uint8 = 1
	DirBoth           uint8 = 2

	ActionStub      uint8 = 1
	ActionZeroRange uint8 = 2
)

// Rule is one exclusion rule. A summary's rules carry no Ranges.
type Rule struct {
	Channel   uint8
	Direction uint8
	Action    uint8
	Opcode    uint16
	Ranges    [][2]uint32 // offset, length
}

// Policy is an exclusion policy.
type Policy struct {
	Name    string
	Version uint32
	Rules   []Rule
}

// Action is what the writer does to a packet with this channel, direction (DirServerToClient or DirClientToServer), and opcode:
// the action of the first rule that matches, or 0 when none does.
func (p Policy) Action(channel, direction uint8, opcode uint16) uint8 {
	if len(p.Rules) == 0 {
		return 0
	}
	rules := make([]C.xicap_rule, len(p.Rules))
	for i, r := range p.Rules {
		rules[i] = C.xicap_rule{channel: C.uint8_t(r.Channel), direction: C.uint8_t(r.Direction), action: C.uint8_t(r.Action), opcode: C.uint16_t(r.Opcode)}
	}
	return uint8(C.xicap_policy_action(&rules[0], C.size_t(len(rules)), C.uint8_t(channel), C.uint8_t(direction), C.uint16_t(opcode)))
}

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
	Policy            Policy // its first 256 rules; RuleCount says how many there are
	RuleCount         uint32
	Source            *SourceSummary // set on converted captures
	SigningKey        [32]byte
	SignedToEnd       bool   // the footer's signature verifies
	VerifiedPackets   uint64 // packets covered by the last good signature
	Seal              *Seal  // set on a format-4 file another program rewrote
}

// Seal is what a program that rewrote a capture signed: every packet, with its key, name, and time.
type Seal struct {
	Key      [32]byte
	Agent    string
	SealedAt uint64 // Unix ms
	OK       bool   // its signature verifies
}

func cerr(msg *[256]C.char) error { return errors.New(C.GoString(&msg[0])) }

// HeaderPrefix is how many bytes HeaderLength needs.
const HeaderPrefix = 12

// HeaderLength returns the length of the header b starts with, from its first
// HeaderPrefix bytes. A later minor version may have a longer header.
func HeaderLength(b []byte) (int, error) {
	if len(b) < HeaderPrefix {
		return 0, errors.New("xicap: short header")
	}
	n := C.xicap_header_size((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	if n < 0 {
		return 0, errors.New("xicap: not a format 3 or 4 header")
	}
	return int(n), nil
}

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
		Policy:            Policy{Name: C.GoString(&s.policy_name[0]), Version: uint32(s.policy_version)},
		RuleCount:         uint32(s.rule_count),
		SigningKey:        *(*[32]byte)(unsafe.Pointer(&s.signing_key[0])),
		SignedToEnd:       s.signed_to_end != 0,
		VerifiedPackets:   uint64(s.verified_packets),
	}
	if s.sealed != 0 {
		out.Seal = &Seal{
			Key:      *(*[32]byte)(unsafe.Pointer(&s.seal_key[0])),
			Agent:    C.GoString(&s.seal_agent[0]),
			SealedAt: uint64(s.sealed_at),
			OK:       s.seal_ok != 0,
		}
	}
	for i := 0; i < int(min(s.rule_count, C.XICAP_SUMMARY_RULES)); i++ {
		r := s.rules[i]
		out.Policy.Rules = append(out.Policy.Rules, Rule{Channel: uint8(r.channel), Direction: uint8(r.direction), Action: uint8(r.action), Opcode: uint16(r.opcode)})
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

// Marker is a note, login, or logout, with the packet it comes just before.
type Marker struct {
	Kind      MarkerKind
	Text      string
	Packet    uint64 // the index of that packet
	Timestamp uint64 // that packet's, Unix ms
}

// Markers reads every marker of a capture, in order; a cut-off capture up to its last intact frame.
func Markers(path string) ([]Marker, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var list *C.xicap_marker
	var n C.size_t
	var msg [256]C.char
	if C.xicap_markers(p, &list, &n, &msg[0], C.size_t(len(msg))) != 0 {
		return nil, cerr(&msg)
	}
	if n == 0 {
		return nil, nil
	}
	defer C.free(unsafe.Pointer(list))
	defer C.xicap_free_markers(list, n)
	out := make([]Marker, 0, int(n))
	for _, m := range unsafe.Slice(list, int(n)) {
		out = append(out, Marker{Kind: MarkerKind(m.kind), Text: C.GoString(m.text), Packet: uint64(m.packet), Timestamp: uint64(m.timestamp)})
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
	Policy            *Policy  // nil: the default, which stubs chat
	Preset            Preset
	Level             int // zstd level; 0 for the preset's. Level 3 holds a live writer's compressor to about 3.7 MB
}

// Preset is how a writer frames and compresses. See FORMAT.md, Writer rules.
type Preset int

const (
	// PresetLive is what a recorder writes: level 7, small frames, checkpoints. The default.
	PresetLive Preset = 0
	// PresetArchive is what an archive writes: level 19, frames to each zone-in, no checkpoints.
	PresetArchive Preset = 1
)

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
	ci.preset = C.int(info.Preset)
	ci.level = C.int(info.Level)
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
	if pol := info.Policy; pol != nil {
		for _, r := range pol.Rules {
			if len(r.Ranges) > math.MaxUint16 {
				return nil, fmt.Errorf("xicap: a rule has %d byte ranges, over %d", len(r.Ranges), math.MaxUint16)
			}
		}
		ci.has_policy = 1
		ci.policy_name = cstr(pol.Name)
		ci.policy_version = C.uint32_t(pol.Version)
		var ranges [][2]uint32
		for _, r := range pol.Rules {
			ranges = append(ranges, r.Ranges...)
		}
		if len(pol.Rules) > 0 {
			rules := unsafe.Slice((*C.xicap_rule)(C.malloc(C.size_t(len(pol.Rules))*C.size_t(unsafe.Sizeof(C.xicap_rule{})))), len(pol.Rules))
			allocs = append(allocs, unsafe.Pointer(&rules[0]))
			for i, r := range pol.Rules {
				rules[i] = C.xicap_rule{channel: C.uint8_t(r.Channel), direction: C.uint8_t(r.Direction), action: C.uint8_t(r.Action), opcode: C.uint16_t(r.Opcode), range_count: C.uint16_t(len(r.Ranges))}
			}
			ci.rules, ci.rule_count = &rules[0], C.size_t(len(pol.Rules))
		}
		if len(ranges) > 0 {
			cr := unsafe.Slice((*C.xicap_range)(C.malloc(C.size_t(len(ranges))*C.size_t(unsafe.Sizeof(C.xicap_range{})))), len(ranges))
			allocs = append(allocs, unsafe.Pointer(&cr[0]))
			for i, r := range ranges {
				cr[i] = C.xicap_range{offset: C.uint32_t(r[0]), length: C.uint32_t(r[1])}
			}
			ci.ranges, ci.range_count = &cr[0], C.size_t(len(ranges))
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

// Cut writes packets first to last of the capture at src, counting from 0, with the markers before each, as a new
// capture at dst signed with seed. The cut keeps src's client version, character, clock, network and exclusion policy;
// it is converted (OriginConverted), and its source block names format "xicap" with hash and metadata. On error dst is
// removed.
func Cut(src, dst string, first, last uint64, agent string, seed [32]byte, hash [64]byte, metadata []byte) error {
	s, d, a := C.CString(src), C.CString(dst), C.CString(agent)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	defer C.free(unsafe.Pointer(a))
	var m *C.uint8_t
	if len(metadata) > 0 {
		cm := C.CBytes(metadata)
		defer C.free(cm)
		m = (*C.uint8_t)(cm)
	}
	var msg [256]C.char
	if C.xicap_cut(s, d, C.uint64_t(first), C.uint64_t(last), a, (*C.uint8_t)(unsafe.Pointer(&seed[0])),
		(*C.uint8_t)(unsafe.Pointer(&hash[0])), m, C.size_t(len(metadata)), &msg[0], C.size_t(len(msg))) != 0 {
		os.Remove(dst)
		return cerr(&msg)
	}
	return nil
}

// TranscodeOptions says how Transcode signs and compresses.
type TranscodeOptions struct {
	// Seal keeps the signer's signatures and adds a seal made with Seed: format 4, complete and signed to the end,
	// or cut off. Without it, Transcode signs anew with Seed, and names a format-3 src in a source block.
	Seal       bool
	Level      int // zstd level; 0 for the archive preset's 19
	Agent      string
	Seed       [32]byte
	SourceHash [64]byte // without Seal: the SHA-512 of src as stored
	Metadata   []byte   // without Seal: added to the source block's metadata
}

// Transcode rewrites src as format 4 at dst with the archive preset, then reads dst back and checks that it holds
// the same packets and markers as src and that its signatures verify. On any difference it returns an error and
// leaves no file at dst.
func Transcode(src, dst string, opt TranscodeOptions) error {
	s, d, a := C.CString(src), C.CString(dst), C.CString(opt.Agent)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	defer C.free(unsafe.Pointer(a))
	ci := C.xicap_transcode_info{level: C.int(opt.Level), agent: a, metadata_size: C.size_t(len(opt.Metadata))}
	if opt.Seal {
		ci.seal = 1
	}
	*(*[32]byte)(unsafe.Pointer(&ci.seed[0])) = opt.Seed
	*(*[64]byte)(unsafe.Pointer(&ci.source_hash[0])) = opt.SourceHash
	if len(opt.Metadata) > 0 {
		m := C.CBytes(opt.Metadata)
		defer C.free(m)
		ci.metadata = (*C.uint8_t)(m)
	}
	var msg [256]C.char
	if C.xicap_transcode(s, d, &ci, &msg[0], C.size_t(len(msg))) != 0 {
		return cerr(&msg)
	}
	return nil
}
