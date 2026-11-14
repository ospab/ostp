# OSTP desktop client

Desktop client for Windows and Linux, built with [Tauri 2](https://tauri.app/). The window is plain HTML/CSS/JS (`src/`). Proxy mode runs inside the app;
TUN mode needs administrator/root rights, so the tunnel then runs in `ostpd`, a separate privileged process the window talks to over a
local TCP socket.

Ready-made builds are on the [Releases](https://github.com/ospab/ostp/releases) page. User documentation: [docs/en/client.md](../docs/en/client.md).

## Build

Needs Rust, Node.js 18+ and the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```bash
cd ostp-gui
npm install
npm run dev               # debug build with hot reload
npm run build             # release binaries, no installer
npm run build:installer   # Windows NSIS installer
```

`npm run dev` and `npm run build` build `ostpd` from the main workspace first. `src-tauri/` is a separate Cargo project with its own
`Cargo.lock`, not a member of the workspace.

---

# Десктопный клиент OSTP

Клиент для Windows и Linux на [Tauri 2](https://tauri.app/). Окно — обычные HTML/CSS/JS (`src/`). Режим прокси работает прямо в
приложении. Режиму TUN нужны права администратора (root), поэтому туннель тогда работает в `ostpd`: отдельном привилегированном
процессе, с которым окно общается через локальный TCP-сокет.

Готовые сборки — на странице [Releases](https://github.com/ospab/ostp/releases). Документация для пользователя: [docs/ru/client.md](../docs/ru/client.md).

Сборка — командами выше. Нужны Rust, Node.js 18+ и [зависимости Tauri](https://tauri.app/start/prerequisites/). `src-tauri/` — отдельный Cargo-проект
со своим `Cargo.lock`, в workspace он не входит.
