// Package xicap is the Go binding for the xicap C++ library. It needs cgo, a
// C++20 compiler, and libzstd.
package xicap

/*
#cgo CXXFLAGS: -std=c++20 -I${SRCDIR}/../include -I${SRCDIR}/../src
#cgo LDFLAGS: -lzstd
#include <stdlib.h>
#include "capi.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// HeaderSize is the length of the fixed header at the start of every capture.
const HeaderSize = 256

// Summary describes a capture after reading every frame.
type Summary struct {
	VersionMajor   uint8
	VersionMinor   uint8
	CaptureAgent   string
	ClientVersion  string
	CharacterName  string
	WorldName      string
	StartZoneID    uint16
	EndZoneID      uint16
	StartTimestamp uint64 // Unix ms
	EndTimestamp   uint64 // Unix ms of the last packet read
	Packets        uint64
	Frames         uint64
	Closed         bool // a valid footer ends the file
}

// CheckHeader checks that b starts with a header this library can read.
func CheckHeader(b []byte) error {
	if len(b) < HeaderSize {
		return errors.New("xicap: short header")
	}
	var msg [256]C.char
	if C.xicap_check_header((*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)), &msg[0], C.size_t(len(msg))) != 0 {
		return errors.New(C.GoString(&msg[0]))
	}
	return nil
}

// Read reads the capture at path, decoding every frame. A cut-off capture
// reads up to its last whole frame; a corrupt frame is an error.
func Read(path string) (Summary, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	var s C.xicap_summary
	var msg [256]C.char
	if C.xicap_read(p, &s, &msg[0], C.size_t(len(msg))) != 0 {
		return Summary{}, errors.New(C.GoString(&msg[0]))
	}
	return Summary{
		VersionMajor:   uint8(s.version_major),
		VersionMinor:   uint8(s.version_minor),
		CaptureAgent:   C.GoString(&s.capture_agent[0]),
		ClientVersion:  C.GoString(&s.client_version[0]),
		CharacterName:  C.GoString(&s.character_name[0]),
		WorldName:      C.GoString(&s.world_name[0]),
		StartZoneID:    uint16(s.start_zone_id),
		EndZoneID:      uint16(s.end_zone_id),
		StartTimestamp: uint64(s.start_timestamp),
		EndTimestamp:   uint64(s.end_timestamp),
		Packets:        uint64(s.packets),
		Frames:         uint64(s.frames),
		Closed:         s.closed != 0,
	}, nil
}

// SameExceptPatched reports whether two headers differ only in the fields the
// writer fills in after writing the header: the start timestamp and the
// end-of-capture fields.
func SameExceptPatched(a, b []byte) bool {
	if len(a) < HeaderSize || len(b) < HeaderSize {
		return false
	}
	return C.xicap_same_except_patched((*C.uint8_t)(unsafe.Pointer(&a[0])), (*C.uint8_t)(unsafe.Pointer(&b[0]))) == 1
}
