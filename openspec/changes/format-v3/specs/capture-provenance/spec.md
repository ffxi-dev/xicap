# Spec Delta

## Purpose

Records where a capture and each of its packets came from, so a researcher can trust what the file says happened and link files that belong together.

## ADDED Requirements

### Requirement: Timestamps are UTC milliseconds that never go backwards
Every packet's timestamp SHALL be milliseconds since the Unix epoch in UTC, and timestamps SHALL never decrease in file order; equal timestamps are allowed. A writer given an earlier time than the last one SHALL record the last time again. The header SHALL say how the times were obtained: recorded live, or converted with an inferred offset.

#### Scenario: Clock steps back
- **WHEN** the host clock steps back two seconds during a capture
- **THEN** the packets recorded in those two seconds carry the last timestamp written before the step, and the file stays in order

#### Scenario: Burst of packets
- **WHEN** ten packets arrive in the same millisecond
- **THEN** all ten carry that millisecond

### Requirement: Packets carry their provenance
Each packet SHALL record its direction and whether the game client's hook reported it as injected by an addon, blocked by an addon, or modified by an addon, and whether it was the first packet of its datagram. A packet's bytes SHALL be the decrypted, decompressed packet as the hook delivered it, before any addon changed it, starting with its 4-byte FFXI header.

#### Scenario: Addon-injected packet
- **WHEN** an addon injects a packet the server never sent
- **THEN** the capture holds it with the injected flag set

### Requirement: The header says where a capture came from
The header SHALL record whether the capture was recorded live or converted from another format, whether it is from retail, a private server, or unknown, the server's name, the client build, and the program that recorded it. A converted capture SHALL carry its source's metadata, such as a captain manifest, in a source extension, with the number of source records it skipped.

#### Scenario: Private-server captain log
- **WHEN** a captain log whose manifest says `IsRetail = false` is converted
- **THEN** the capture's header says converted and private server, and its source extension holds the manifest

### Requirement: Captures have ids and link up
Each capture SHALL carry a random 128-bit id and the id of the capture it continues, or zero when it continues none. The header SHALL describe one character for the whole file.

#### Scenario: Recorder restarts mid-session
- **WHEN** the recorder crashes and starts again on the same character
- **THEN** the new capture names the cut-off one as the capture it continues

### Requirement: When a recorder starts a new file
A recorder SHALL start a new capture when a different character logs in, when the recorder starts, and when the current capture reaches 24 hours. When the same character logs out and back in, the recorder SHALL keep writing the same capture and mark the login.

#### Scenario: Same character relogs
- **WHEN** a character logs out to character select and logs back in
- **THEN** the capture continues in the same file with a marker at the login

#### Scenario: Switching to a mule
- **WHEN** a different character logs in after a logout
- **THEN** the recorder closes the current capture and starts one that names it as the capture it continues
