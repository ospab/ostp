// Stages ostp-tun-helper where Tauri expects a sidecar.
//
// tauri.windows.conf.json declares `externalBin: ["binaries/ostp-tun-helper"]`,
// and Tauri resolves that to `binaries/ostp-tun-helper-<target-triple>.exe` at
// build time, failing the build outright when the file is absent. Cargo writes
// the plain name instead, so every Windows build — dev, portable zip and
// installer alike — has to copy it across first.
//
// A no-op off Windows: externalBin lives in the Windows-only config, so the
// Linux and macOS GUI builds neither need nor have a helper sidecar.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

if (process.platform !== 'win32') {
  process.exit(0);
}

// --target may be passed through; fall back to the host triple rustc reports.
const targetFlag = process.argv.indexOf('--target');
const triple =
  targetFlag !== -1 && process.argv[targetFlag + 1]
    ? process.argv[targetFlag + 1]
    : execFileSync('rustc', ['-vV'], { encoding: 'utf8' })
        .split('\n')
        .find((l) => l.startsWith('host:'))
        .slice('host:'.length)
        .trim();

const profile = process.argv.includes('--release') ? 'release' : 'debug';
const repoRoot = path.resolve(__dirname, '..');

// Cargo drops a --target build under target/<triple>/, and a host build
// straight into target/. CI always passes --target; local builds usually do not.
const candidates = [
  path.join(repoRoot, 'target', triple, profile, 'ostp-tun-helper.exe'),
  path.join(repoRoot, 'target', profile, 'ostp-tun-helper.exe'),
];
const src = candidates.find((p) => fs.existsSync(p));
if (!src) {
  console.error(
    'stage-sidecar: ostp-tun-helper.exe not found. Looked in:\n  ' +
      candidates.join('\n  ') +
      `\nBuild it first: cargo build -p ostp-tun-helper${profile === 'release' ? ' --release' : ''}`
  );
  process.exit(1);
}

const destDir = path.join(__dirname, 'src-tauri', 'binaries');
fs.mkdirSync(destDir, { recursive: true });
const dest = path.join(destDir, `ostp-tun-helper-${triple}.exe`);
fs.copyFileSync(src, dest);
console.log(`stage-sidecar: ${path.relative(repoRoot, src)} -> ${path.relative(repoRoot, dest)}`);

// wintun.dll rides along as a bundled resource. It is only fetched by the
// release workflow, so a local build without it should warn rather than fail —
// the installer just ends up unable to bring a tunnel up.
const dllSrc = [
  path.join(repoRoot, 'target', triple, profile, 'wintun.dll'),
  path.join(repoRoot, 'target', profile, 'wintun.dll'),
].find((p) => fs.existsSync(p));
if (dllSrc) {
  fs.copyFileSync(dllSrc, path.join(destDir, 'wintun.dll'));
  console.log(`stage-sidecar: ${path.relative(repoRoot, dllSrc)} -> binaries/wintun.dll`);
} else if (fs.existsSync(path.join(destDir, 'wintun.dll'))) {
  console.log('stage-sidecar: reusing the previously staged binaries/wintun.dll');
} else {
  console.warn('stage-sidecar: WARNING wintun.dll not found; a bundle build will fail on the missing resource');
}
