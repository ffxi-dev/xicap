# Spec Delta

## Purpose

Keeps private traffic such as chat out of captures before it reaches disk, while showing readers what was left out.

## ADDED Requirements

### Requirement: The writer applies an exclusion policy
A writer SHALL apply its exclusion policy to every packet before the packet reaches disk. A policy rule names a direction and an opcode, and either stubs the packet or zeroes byte ranges in it.

#### Scenario: Chat never touches disk
- **WHEN** a chat packet arrives under a policy that stubs chat
- **THEN** no byte of the chat text is written to the file at any time

### Requirement: Stubs keep the packet's header
A stubbed packet SHALL keep its timestamp, direction, provenance flags, and its 4-byte FFXI header (opcode, size, and sequence), and SHALL drop the rest. A redacted packet SHALL keep its length with the named ranges zeroed.

#### Scenario: Stubbed chat packet
- **WHEN** a reader reads a stubbed chat packet
- **THEN** it yields the opcode, the original size from the FFXI header, the sequence, and the time, with the excluded flag set and no body

### Requirement: Readers know what was left out
The file SHALL record the policy it was written with, including its name and version, inside the signed part of the file. The excluded and redacted flags SHALL be packet flags a reader must understand.

#### Scenario: Policy shown to readers
- **WHEN** a reader opens a capture written under a policy
- **THEN** it reports the policy's name, version, and rules

#### Scenario: Reader without exclusion support
- **WHEN** a reader that does not know the excluded flag meets an excluded packet
- **THEN** it refuses the file rather than read a stub as a whole packet

### Requirement: Chat is stubbed by default
The library's default policy SHALL stub every chat packet in both directions. A recorder MAY add rules; leaving chat in takes an explicit choice.

#### Scenario: Default writer
- **WHEN** a writer is opened without naming a policy
- **THEN** chat packets are written as stubs
