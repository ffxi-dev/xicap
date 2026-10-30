# Spec Delta

## Purpose

Records where a capture and each of its packets came from, pins each capture to one character, and keeps every packet a replay needs, so a researcher can trust what the file says happened and a custom client can replay it.

## ADDED Requirements

### Requirement: Packets are the whole context
A capture SHALL hold its context only as packets. A capture that starts at a login SHALL hold every recorded packet, on every recorded channel, from that login on, so a replay needs nothing outside the file and the captures it continues. The format SHALL not carry copies of client memory.

#### Scenario: Replay from a login
- **WHEN** a custom client replays a capture that starts at a login
- **THEN** every packet the game client received and sent from that login on is in the file, in order

### Requirement: Packets name their channel
Each packet SHALL name the channel it travelled on, such as the game server or the search server. `FORMAT.md` SHALL keep a registry of channels and define what a packet's bytes and opcode hold on each; new channels, such as IRC or profile traffic, SHALL be added without breaking existing readers. Readers SHALL pass on packets of a channel they do not know, with its number, rather than refuse the file. A packet on any channel MAY be longer than 64 KiB.

#### Scenario: Search between zone packets
- **WHEN** a player runs `/search` while game packets arrive
- **THEN** the search request and its results are in the capture on the search channel, in time order with the game packets

### Requirement: Timestamps are UTC milliseconds that never go backwards
Every packet's timestamp, on every channel, SHALL be milliseconds since the Unix epoch in UTC, and timestamps SHALL never decrease in file order; equal timestamps are allowed. A writer given an earlier time than the last one SHALL record the last time again. The header SHALL say how the times were obtained: recorded live, or converted with an inferred offset.

#### Scenario: Clock steps back
- **WHEN** the host clock steps back two seconds during a capture
- **THEN** the packets recorded in those two seconds carry the last timestamp written before the step, and the file stays in order

#### Scenario: Burst of packets
- **WHEN** ten packets arrive in the same millisecond
- **THEN** all ten carry that millisecond

### Requirement: Packets carry their provenance
Each packet SHALL record its direction and whether the game client's hook reported it as injected by an addon, blocked by an addon, or modified by an addon, and whether it was the first packet of its datagram. A packet's bytes SHALL be the decrypted, decompressed packet as the hook delivered it, before any addon changed it.

#### Scenario: Addon-injected packet
- **WHEN** an addon injects a packet the server never sent
- **THEN** the capture holds it with the injected flag set

### Requirement: The header says where a capture came from
The header SHALL record whether the capture was recorded live or converted from another format, whether it is from retail, a private server, or unknown, the client build, the program that recorded it, and whether the capture starts at a login, mid-session, or unknown. A converted capture SHALL carry its source's metadata, such as a captain manifest, in a source extension, with the number of source records it skipped.

#### Scenario: Private-server captain log
- **WHEN** a captain log whose manifest says `IsRetail = false` is converted
- **THEN** the capture's header says converted and private server, and its source extension holds the manifest

### Requirement: One character per capture
Each capture SHALL hold one character's session, and the header SHALL name that character: content id, world, and name. The character the header names SHALL be the one the capture's zone-in packets name, and a reader SHALL report a capture whose packets name another character.

#### Scenario: Header claims another character
- **WHEN** a capture's header names one character and its zone-in packets name another
- **THEN** a reader reports the mismatch

### Requirement: Captures have ids and link up
Each capture SHALL carry a random 128-bit id and the id of the capture it continues, or zero when it continues none.

#### Scenario: Recorder restarts mid-session
- **WHEN** the recorder crashes and starts again on the same character
- **THEN** the new capture is marked as starting mid-session and names the cut-off one as the capture it continues

### Requirement: Captures start at a login
A recorder SHALL start a new capture only at a login: when a character logs in and the current capture holds another character or none. When the same character logs out and back in, the recorder SHALL keep writing the same capture and mark the login. A recorder that starts after a login has passed, or after a crash, SHALL mark its capture as starting mid-session.

#### Scenario: Same character relogs
- **WHEN** a character logs out to character select and logs back in
- **THEN** the capture continues in the same file with a marker at the login

#### Scenario: Switching to a mule
- **WHEN** a different character logs in after a logout
- **THEN** the recorder closes the current capture and starts one at the login that names it as the capture it continues

#### Scenario: Week-long session
- **WHEN** a character stays logged in for a week
- **THEN** the session is one capture, never cut mid-session by a timer
