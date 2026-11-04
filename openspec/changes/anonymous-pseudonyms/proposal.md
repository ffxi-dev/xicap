# Proposal

## Why

Captures on Mogsafe are public. The owner chose three recording modes, set per Mogsafe account and in Memoria: default, everything, and anonymous. An anonymous capture must name no player, the recorder included, yet serve analysis for years: every packet keeps its layout, and the same player keeps the same stand-in across packets and captures. Memoria records live and Mogsafe converts captain logs in Go, so the rewriting belongs in this library, where both reach it.

## What Changes

- `xicap::Pseudonymizer` replaces player names and ids in packets, in place, with keyed pseudonyms: fixed fields from a field map, walkers for bit streams and block lists, and a sweep for the stale copies retail leaves.
- `xicap::anonymousExclusionPolicy()`, `xicap-anonymous` version 2: the default policy plus zeroed ranges over the text players write. It stubs nothing more.
- `xicap::deriveKey()` derives the pseudonym key and the anonymous signing seed from an install's seed. `xicap::pseudonymFieldMap()` exposes the map.
- `pseudonym_fields.tsv` lists the map as data for checking tools.
- The Go binding gets `Pseudonymizer`, `AnonymousPolicy`, and `DeriveKey`, for Mogsafe's imports.
- `FORMAT.md` says exactly what an anonymous capture changes. The layout of the format does not change.

## Impact

- Memoria calls the pseudonymizer before its writer in anonymous mode. Mogsafe calls it in imports for accounts in anonymous mode.
- The header's recording mode (v5) says a capture is anonymous; the policy's name says so too.
