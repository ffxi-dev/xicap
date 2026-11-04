# Tasks

## 1. Library

- [x] 1.1 `Pseudonymizer`, `deriveKey`, `pseudonymFieldMap` and `anonymousExclusionPolicy` in `include/xicap/pseudonym.h` and `src/pseudonym.cpp`; verify the tests in `tests/pseudonym_tests.cpp`
- [x] 1.2 Real packets from public captures in `tests/pseudonym_corpus.txt`; verify that only the bytes `pseudonym_fields.tsv` names change, and to their pseudonyms, for game, action and search packets
- [x] 1.3 Keep every packet's layout: no stubs beyond the default's, text zeroed by range; verify on packets built from LandSandBoat's layouts for chat, proposals, votes, ballista, the concierge, the GM call, and every search type
- [x] 1.4 Verify no real name or id from the corpus appears in an anonymous capture written from it, in the file or any decompressed packet, at any byte or bit
- [x] 1.5 `pseudonym_fields.tsv`: the field map as data; verify it lists the library's map and the policy's text ranges
- [x] 1.6 Go binding: `Pseudonymizer`, `AnonymousPolicy`, `DeriveKey`; verify `TestPseudonymizer`

## 2. Specification

- [x] 2.1 `FORMAT.md`: Anonymous captures, precise enough to check a capture against
- [ ] 2.2 Rebase onto v5.0.0: set the header's recording mode to anonymous with this policy, drop the 0x0B7 stub the default now covers, Go `/v5`, release v5.1.0
