# Spec Delta

## Purpose

Lets anyone check which recorder made a capture and that nobody changed it since, so captures stay traceable to one key and a bad actor's uploads can be found by key.

## ADDED Requirements

### Requirement: Each recorder signs with its own key
A writer SHALL sign every capture with an Ed25519 key belonging to one recorder install, and the header SHALL carry the public key.

#### Scenario: Two installs
- **WHEN** two installs record captures
- **THEN** each capture names the public key of the install that recorded it

### Requirement: A hash chain covers the whole file
The writer SHALL keep a SHA-512 hash chain over the header, every extension block, and every frame in file order, and every signature SHALL sign the chain's value at its place in the file.

#### Scenario: Frame swapped
- **WHEN** two frames of a signed capture are swapped
- **THEN** the signature check fails from the first swapped frame on

### Requirement: Checkpoints sign a capture as it records
While recording, the writer SHALL write a signed checkpoint covering every frame written so far at the first frame boundary after 60 seconds of unsigned frames, when a flush finds the capture idle with unsigned frames, and before a login or logout marker. It SHALL not write a checkpoint when no frame was written since the last one, and SHALL sign the chain's final value in the footer on close.

#### Scenario: Busy session
- **WHEN** packets arrive steadily for ten minutes
- **THEN** the capture holds about ten checkpoints, and no stretch of more than 60 seconds of frames is unsigned

#### Scenario: Idle at the auction house
- **WHEN** a session goes quiet after a burst of packets
- **THEN** the next timed flush signs the burst, and no further checkpoints are written until packets arrive again

#### Scenario: Cut-off capture
- **WHEN** a signed capture is cut off by a crash
- **THEN** a reader verifies every frame up to its last checkpoint and reports the frames after it as unsigned

### Requirement: Readers report what the signatures prove
A reader SHALL report, for each capture, the signing key, whether the signatures verify, and how many packets the verified part covers. A signature failure SHALL not stop a reader from reading packets.

#### Scenario: Edited packet
- **WHEN** one byte of a packet is changed and the frame's checksum is recomputed
- **THEN** the reader still reads the packets and reports the signatures as failed from that frame on
