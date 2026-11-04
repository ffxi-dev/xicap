# Tasks

## 1. Library

- [x] 1.1 `Pseudonymizer`, `deriveKey`, and `anonymousExclusionPolicy` in `include/xicap/pseudonym.h` and `src/pseudonym.cpp`; verify the tests in `tests/pseudonym_tests.cpp`
- [x] 1.2 Real packets from public captures in `tests/pseudonym_corpus.txt`; verify every mapped field changes to its pseudonym and no other byte changes, for game, action, and search packets
- [x] 1.3 Verify no real name or id from the corpus appears in an anonymous capture written from it, in the file or any decompressed packet, at any byte or bit
- [x] 1.4 Go binding: `Pseudonymizer`, `AnonymousPolicy`, `DeriveKey`; verify `TestPseudonymizer`

## 2. Specification

- [x] 2.1 `FORMAT.md`: anonymous captures and the `xicap-anonymous` policy
- [ ] 2.2 Set the header mode field to anonymous once the format redesign adds it
