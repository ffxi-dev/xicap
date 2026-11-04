# Spec Delta

## Purpose

Lets a capture name no player, its recorder included, while each player keeps one stand-in across packets and captures.

## ADDED Requirements

### Requirement: Pseudonyms are keyed and stable
The pseudonymizer SHALL replace each player name and player id with a pseudonym computed from it and a 32-byte key, so that the same name or id under one key always gives the same pseudonym, and no one without the key can tell which real name gave one.

#### Scenario: One player, many packets
- **WHEN** a player's name appears in a party list, a treasure lot, and a search reply under one key
- **THEN** each carries the same pseudonym

#### Scenario: Guessing a name
- **WHEN** someone without the key hashes a guessed name
- **THEN** nothing they compute matches the pseudonym better than chance

### Requirement: Pseudonyms keep the field's shape
A name's pseudonym SHALL have the name's length and be letters with the first a capital. A player id's pseudonym SHALL stay below `0x01000000` and never be 0, and no two player ids SHALL share one. NPC and mob ids SHALL pass unchanged.

#### Scenario: A zone-in
- **WHEN** a zone-in is pseudonymized
- **THEN** its size and every byte outside its id and name fields stay as they were

### Requirement: Nothing real reaches the file
The writer's caller SHALL pseudonymize every packet and the header character before the writer takes them, under the `xicap-anonymous` policy, which stubs or zeroes what the field map cannot rewrite.

#### Scenario: Scanning an anonymous capture
- **WHEN** real packets are written as an anonymous capture
- **THEN** no real name or id from them appears in the file or in any packet read back
