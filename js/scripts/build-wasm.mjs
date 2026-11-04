// Builds @xicap/wasm with Emscripten: emsdk from $EMSDK, or ~/emsdk; ninja from $PATH, or $NINJA.

import { execSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const jsDir = path.resolve(here, "..");
const buildDir = path.join(jsDir, "build");
const isWin = process.platform === "win32";

const emsdkRoot = (process.env.EMSDK || path.join(os.homedir(), "emsdk")).replace(/\\/g, "/");
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
        // Without emsdk_env, emcmake.bat finds neither emsdk's python nor its node. Their folders carry versions.
        const winRoot = emsdkRoot.replace(/\//g, "\\");
        const extras = [
            winRoot,
            `${winRoot}\\upstream\\emscripten`,
        ];
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
