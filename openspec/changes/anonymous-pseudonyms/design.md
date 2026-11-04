# Design

FORMAT.md, Anonymous captures, states exactly what the pseudonymizer changes; `pseudonym_fields.tsv` lists the fixed fields as data, for tools that check anonymous captures. This note says why.

## Keep the layout

The owner wants anonymous captures to serve analysis for years, so every packet keeps its layout. Nothing is stubbed beyond what the default policy stubs. Names and ids are rewritten in place, and only text players write is zeroed, byte range by byte range. Where a layout is not known, only the bytes no layout explains are zeroed: search types this library does not read, GM call blocks of unknown types, and tags past the last known one in a search bit stream.

## The key

A pseudonym is BLAKE2b keyed with a 32-byte key. An install linked to a Mogsafe account uses the account's key, which Mogsafe hands to Memoria with the mode, so live captures and imports of one account agree. An unlinked install uses `deriveKey(seed, "xicap pseudonym key")`, from the Ed25519 seed it already has: no new secret file. Anonymous captures sign with `deriveKey(seed, "xicap anonymous signing")`, so the header's signing key does not link them to the install's other captures.

## Pseudonyms

- **Names** keep their length, so every name is rewritten in place: in byte fields, in the search server's 7-bit fields, and in crafters' 6-bit signatures. The cost, which the owner accepts: a name's length shows.
- **Player ids** sit below `0x01000000`, NPC and mob ids above. A keyed 4-round Feistel permutation of the low 20 bits, which is all the search server sends, means two players never share a pseudonym and a pseudonym is never an NPC's id.
- **Content ids** appear only in the header; bit 31 keeps Mogsafe from taking one for a real character.

## The field map

`FIELD_MAP` in `src/pseudonym.cpp` came from every field of `ffxi-dev/packets` v1.4 whose name says id, name, or owner, from LandSandBoat's packet definitions (`0x048`, `0x078`, `0x079`, `0x0A0`, `0x0A1`, `0x0D3`, `0x0E6`, the search server's packets), and from a scan of four public Mogsafe captures (`QWFQtl0r5ciu`, `AIxeAsqgUD5p`, `M2avxadK-fb7`, `h3Eu8ohjSCFE`; 955,066 packets) for every known player name and id. The TSV marks which rows were seen on those captures and which come from a layout only.

The scan also corrected the map:
- Retail's `0x041` does not match the blacklist layout, so its ids were other numbers. It is out of the map.
- Party lists name trusts too, so a name next to an id is rewritten only when that id is a player's.
- The sweep checks ids at every byte. It checks every bit only in `0x062`, where retail leaves action streams: over every bit of every packet it rewrote positions and flags that happened to equal an id.

## Known gaps, accepted

- A pseudonym shows the name's length.
- A player met only in stale bytes, before any mapped field names them, keeps their real name or id there.
- A number that equals an id already met, such as an auction price, is rewritten too: 19 bytes in the four captures.

## Implementation Notes

- The pseudonymizer keeps every real name and id it has met, for the sweep, with no limit: one session meets thousands at most. Revisit if a session's memory grows.
- `0x0D3`'s typed text is zeroed by the pseudonymizer, not by a policy range, since its place depends on the blocks before it; the redacted flag does not mark it.
