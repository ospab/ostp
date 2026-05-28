import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const workspaceRoot = path.resolve(__dirname, '..');
const distDir = path.join(__dirname, 'dist');

if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

const filesToCopy = [
  {
    src: path.join(__dirname, 'src-tauri', 'target', 'release', 'ostp-gui.exe'),
    dest: path.join(distDir, 'ostp-gui.exe')
  },
  {
    src: path.join(workspaceRoot, 'target', 'release', 'ostp-tun-helper.exe'),
    dest: path.join(distDir, 'ostp-tun-helper.exe')
  },
  {
    src: path.join(workspaceRoot, 't2s_tmp', 'tun2socks-windows-amd64.exe'),
    dest: path.join(distDir, 'tun2socks.exe')
  },
  {
    src: path.join(workspaceRoot, 'target', 'release', 'wintun.dll'),
    dest: path.join(distDir, 'wintun.dll')
  }
];

let success = true;

for (const file of filesToCopy) {
  if (fs.existsSync(file.src)) {
    fs.copyFileSync(file.src, file.dest);
    console.log(`Copied ${path.basename(file.src)} -> dist/${path.basename(file.dest)}`);
  } else {
    console.error(`Error: Missing file ${file.src}`);
    success = false;
  }
}

if (success) {
  console.log('\nSuccess! All files have been gathered in the ostp-gui/dist/ directory.');
} else {
  console.error('\nSome files were missing. Make sure you have run the build first!');
  process.exit(1);
}
