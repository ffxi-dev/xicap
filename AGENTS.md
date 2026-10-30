# xicap

xicap is Vault's capture binary format and its C++20 library, built for replay and long-term archival: zstd-compressed frames, an index, and the dictionary embedded in each capture. `FORMAT.md` is the normative specification; `README.md` shows the library API. Every Vault brick that writes, stores, plays, or queries captures depends on it, so treat it as a contract.

## Commands

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DXICAP_BUILD_TOOLS=OFF -DXICAP_BUILD_TESTS=ON
cmake --build build --target xicap_tests
ctest --test-dir build --output-on-failure --build-config Release
```

On Windows run these from an MSVC developer shell (x64). The tools (`xicap_dump`) need the Ashita SDK (`ASHITA4_SDK_PATH`) and an x86 build, because FFXI is a 32-bit client; keep `-DXICAP_BUILD_TOOLS=OFF` otherwise.

Bindings, each with its own CI workflow:

```bash
pip install ./python[test] && pytest python/tests      # Python; needs the fixture from xicap_make_fixture
cd js && node ./scripts/build-wasm.mjs                 # JavaScript and Wasm; needs Emscripten
```

## Rules

- A change to the on-disk format updates `FORMAT.md`, bumps the version in the header constants, and adds reader and writer tests, including reading captures written by the previous version. Captures are archived for the long term, so readers keep reading every released version.
- The C++ library, the Python bindings, and the JavaScript bindings change together.

## Part of Vault

This repository is one brick of Vault, the owner's platform for capturing retail FFXI and keeping the captures for the long term. The core repository is `ffxi-dev/vault`; the bricks are `lens`, `res`, `xicap`, `pilot`, and `patch`. On the owner's PC they sit side by side in `C:/Users/sruon/Documents/GitHub/Vault/`.

- **CI** calls shared workflows from `ffxi-dev/vault` (`uses: ffxi-dev/vault/.github/workflows/<name>.yml@ci/v1`). Change CI logic there, not here.
- **Contracts** come from `ffxi-dev/vault` at a tagged release. Pin a tag; never copy a schema in.
- **Specs.** A behavior change to this brick gets an OpenSpec change in this repository's `openspec/` (run `openspec init` the first time). A change that spans bricks goes in `ffxi-dev/vault`'s `openspec/`.
- **Private.** Every Vault repository is private. Never commit credentials, and never make a repository public without the owner.
- **Commits** are small and say why. Every bug fix adds a test that fails without it. Match the surrounding code.
- **Writing** (docs, commit messages, UI text) follows the rules in `ffxi-dev/vault`'s AGENTS.md: short plain words, active voice, no filler.
