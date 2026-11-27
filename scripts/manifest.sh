#!/usr/bin/env bash
# Prints a release's manifest.json: the format it writes, every package's name, and the commit and run that tested
# it, for people and for other bricks' checks. The release workflow attaches it; CI runs it on every change.
# Usage: scripts/manifest.sh <version>. Needs jq; reads GITHUB_SHA and the run from GitHub's environment.
set -euo pipefail
v="$1"
format=$(sed -nE 's/.*uint8_t +VERSION += ([0-9]+);/\1/p' src/format/layout.h)
module=$(sed -n 's/^module //p' go.mod)
run="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-ffxi-dev/xicap}/actions/runs/${GITHUB_RUN_ID:-0}"
jq -n --arg v "$v" --argjson format "$format" --arg module "$module" --arg commit "${GITHUB_SHA:-unknown}" --arg run "$run" '{
  xicap: $v,
  format: $format,
  commit: $commit,
  tested: $run,
  packages: {
    npm: "@ffxi-dev/xicap@\($v)",
    go: "\($module)@v\($v)",
    python: "xicap @ git+https://github.com/ffxi-dev/xicap@v\($v)#subdirectory=bindings/python",
    cmake: "https://github.com/ffxi-dev/xicap/archive/refs/tags/v\($v).tar.gz"
  },
  summary: "xicap \($v) writes format \($format). Commit \($commit), tested by \($run). manifest.json lists every package."
}'
