# Proposal

## Why

Captures on Mogsafe are public. The owner chose three recording modes, set per Mogsafe account and in Memoria: default (chat stubbed), everything (no policy), and anonymous. An anonymous capture must name no player, the recorder included, yet stay useful: the same player must keep the same stand-in across packets and captures, or no one can follow a fight or a party. Memoria records live and Mogsafe converts captain logs in Go, so the rewriting belongs in this library, where both reach it.

## What Changes

- `xicap::Pseudonymizer` replaces player names and ids in packets, in place, with keyed pseudonyms, driven by a field map in `src/pseudonym.cpp`. Its caller runs it before the writer, so the file and its signatures hold only pseudonyms.
- `xicap::anonymousExclusionPolicy()`, `xicap-anonymous` version 1: the default policy plus stubs and zeroed ranges for packets the field map cannot rewrite.
- `xicap::deriveKey()` derives the pseudonym key and the anonymous signing seed from an install's seed.
- The Go binding gets `Pseudonymizer`, `AnonymousPolicy`, and `DeriveKey`, for Mogsafe's imports.
- `FORMAT.md` describes anonymous captures and their policy. The layout does not change: no new field, flag, or block.

## Impact

- Memoria calls the pseudonymizer before its writer in anonymous mode. Mogsafe calls it in imports for accounts in anonymous mode.
- The header mode field the format redesign adds says a capture is anonymous; until then the policy's name says so.
