# Design

## The key

A pseudonym is BLAKE2b keyed with a 32-byte key. An install linked to a Mogsafe account uses the account's key, which Mogsafe hands to Memoria with the mode, so live captures and imports of one account agree. An unlinked install uses `deriveKey(seed, "xicap pseudonym key")`, from the Ed25519 seed it already has: no new secret file. Without the key, no one can test a guessed name against a pseudonym.

Anonymous captures sign with `deriveKey(seed, "xicap anonymous signing")`, so the header's signing key does not link them to the install's other captures. Mogsafe ties that second key to the install and never shows the tie.

## Pseudonyms

- **Names** keep their length and stay letters, the first a capital. Same length lets every name be rewritten in place, in byte fields, in the search server's 7-bit fields, and in crafters' 6-bit signatures, without moving another byte. The cost: a name's length shows.
- **Player ids** are below `0x01000000`; NPC and mob ids carry the zone from there up and pass unchanged. The low 20 bits, all the search server sends, go through a keyed 4-round Feistel permutation that never gives 0, and bits 20 to 23 stay: two players never share a pseudonym, and a pseudonym is never an NPC's id. ActIndex values are per zone and stay.
- **Content ids** appear only in the header. The pseudonym sets bit 31, which real content ids never use, so Mogsafe never takes it for a real character.

## The field map

`FIELD_MAP` in `src/pseudonym.cpp` lists, per direction and opcode, each field holding a player's id (u32), name (text), or an item's extra data (a crafter's signature at bytes 12 to 23), with an optional byte test for unions. It came from every field of `ffxi-dev/packets` v1.4 whose name says id, name, or owner, read with LandSandBoat, and checked on four public Mogsafe captures (`QWFQtl0r5ciu`, `AIxeAsqgUD5p`, `M2avxadK-fb7`, `h3Eu8ohjSCFE`; 955,066 packets): a scan for every known player name and id showed where each sits.

| Checked on | Fields |
| --- | --- |
| captures, to the client | `0x00A`, `0x00D` id, target, name; `0x00E` target; `0x029`, `0x02A`, `0x02D`, `0x032`, `0x034`, `0x036`, `0x037`, `0x038`, `0x058`, `0x05B`, `0x065`, `0x067`, `0x068`, `0x0C9`, `0x0DF` ids; `0x076`, `0x0C8` member ids; `0x0CA` name; `0x0D3` ids, names; `0x0DC`, `0x0DD`, `0x0E2` id, name; `0x020` signature; `0x028` actor and targets, in its bit stream |
| captures, from the client | `0x00A`, `0x017`, `0x01A`, `0x037`, `0x05B`, `0x05C`, `0x0DD`, `0x105` ids |
| captures, search | request `0x01` ids; reply `0x81` names and ids |
| layout only | `0x009`; blacklist `0x041`, `0x042`, `0x03D`; `0x043`; delivery box `0x04B`, `0x04D`; auction `0x04C`; emote `0x05A`; `0x070`; `0x0A0`; `0x0B7`; treasure `0x0D2`; `0x0F9`; bazaar `0x106` to `0x10A` and `0x105` signature; `0x11D`; party `0x06E`, `0x071`, `0x073`, `0x077`; the other ids from the client |

A name field is rewritten only when it holds letters, 1 to 15 of them, and the bytes after the name are zeroed, since they may be left from a longer name.

**The sweep.** Retail does not clear its packet buffers: fields it does not fill carry bytes of earlier packets, such as a name at byte 90 of a `0x062`, or an action packet's ids in a `0x062` or `0x04F`. After the field map, every real name and id met so far is replaced wherever else it sits: a name between non-letters, an id at any bit. Ids under `0x10000` are left out, since they match too many other numbers.

## Stubbed or zeroed

The anonymous policy stubs what the map cannot place: `0x014`, `0x016`, `0x048`, `0x078`, `0x079`, `0x0E6` to the client, and `0x0A0`, `0x0A1`, `0x0B7`, `0x0D3` from the client. On the search channel, where a stub is not defined, it zeroes from byte 12 the request types `0x00`, `0x02`, `0x03`, `0x05`, `0x06`, `0x08` and their replies; the pseudonymizer also zeroes any other search type it does not read, except the auction house's item lists. The file marks all this with its policy: name `xicap-anonymous`, its rules, and the field map's version.

## Known gaps

- A name or id that appears only in stale bytes, before any mapped field names it, stays.
- Text players write in fields the default policy keeps (bazaar and search comments, `0x0CA`) keeps any name typed in it, unless it is a name already met.
- Names in the event and message string fields (`0x027`, `0x02A`, `0x033`, `0x05D`) and in widescan (`0x0F4`) are rewritten only by the sweep. Linkshell names stay.
- Two real names of one length can share a pseudonym; with 26 letters a place, that is rare below thousands of names.

## Implementation Notes

- The pseudonymizer keeps every real name and id it has met, for the sweep, with no limit: one session meets thousands at most. Revisit if a session's memory grows.
