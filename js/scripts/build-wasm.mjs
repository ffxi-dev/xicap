// Driver for the Emscripten build of @xicap/wasm.
//
// Looks up the Emscripten install via $EMSDK (or a default of ~/emsdk on
// posix, C:/Users/$USER/emsdk on Windows). Uses ninja from $PATH; set $NINJA
// to override.

import { execSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const jsDir = path.resolve(here, "..");
const buildDir = path.join(jsDir, "build");
const isWin = process.platform === "win32";

function defaultEmsdkRoot() {
    if (process.env.EMSDK) return process.env.EMSDK;
    const home = os.homedir();
    return path.join(home, "emsdk");
}
const emsdkRoot = defaultEmsdkRoot().replace(/\\/g, "/");
if (!existsSync(emsdkRoot)) {
    console.error(`emsdk not found at ${emsdkRoot}. Set EMSDK or install emsdk.`);
    process.exit(1);
}

const emscriptenBin = `${emsdkRoot}/upstream/emscripten`;
const ext = isWin ? ".bat" : "";
const emcmake = `${emscriptenBin}/emcmake${ext}`;
const emmake  = `${emscriptenBin}/emmake${ext}`;

if (existsSync(buildDir)) rmSync(buildDir, { recursive: true });
mkdirSync(buildDir, { recursive: true });

function buildEnv() {
    const env = { ...process.env };
    env.EMSDK = isWin ? emsdkRoot.replace(/\//g, "\\") : emsdkRoot;
    if (isWin) {
        // emsdk's bundled python/node aren't on PATH unless emsdk_env was sourced;
        // add them here explicitly so emcmake.bat finds its interpreters.
        const winRoot = emsdkRoot.replace(/\//g, "\\");
        const extras = [
            winRoot,
            `${winRoot}\\upstream\\emscripten`,
        ];
        // The bundled tool dirs use versioned subdirectories; add anything that
        // looks plausible. emsdk install layout is stable enough.
        const possiblePythonDirs = ["python/3.13.3_64bit", "python/3.13.3-1_64bit", "python/3.12_64bit"];
        const possibleNodeDirs   = ["node/22.16.0_64bit/bin", "node/20_64bit/bin"];
        for (const sub of [...possiblePythonDirs, ...possibleNodeDirs]) {
            const p = `${winRoot}\\${sub.replace(/\//g, "\\")}`;
            if (existsSync(p)) extras.push(p);
        }
        env.Path = `${extras.join(";")};${env.Path || env.PATH || ""}`;
    }
    return env;
}

function run(cmd) {
    console.log(`> ${cmd}`);
    execSync(cmd, { cwd: buildDir, stdio: "inherit", env: buildEnv() });
}

const winify = (p) => (isWin ? p.replace(/\//g, "\\") : p);

const ninjaArg = process.env.NINJA
    ? ` -DCMAKE_MAKE_PROGRAM="${process.env.NINJA}"`
    : "";

console.log("Configuring with emcmake...");
run(`"${winify(emcmake)}" cmake -G Ninja${ninjaArg} -DCMAKE_BUILD_TYPE=Release ..`);

console.log("Building wasm...");
const ninjaCmd = process.env.NINJA ? `"${process.env.NINJA}"` : "ninja";
run(`"${winify(emmake)}" ${ninjaCmd}`);

console.log("Done. dist/xicap.js + dist/xicap.wasm produced.");
