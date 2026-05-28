# Contributing to OSTP

Thank you for your interest in contributing to **OSTP (Ospab Stealth Transport Protocol)**! We welcome contributions from developers, security researchers, testers, and documentation writers of all skill levels.

By contributing to this project, you agree to abide by our code of conduct and license terms.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Project Structure](#project-structure)
3. [Development Workflow](#development-workflow)
4. [Coding Guidelines](#coding-guidelines)
5. [Submitting Pull Requests](#submitting-pull-requests)
6. [Security Vulnerabilities](#security-vulnerabilities)

---

## Development Setup

To build and test OSTP locally, you will need:

*   **Rust Toolchain (1.75+)**: Install via [rustup](https://rustup.rs/).
*   **Node.js (18+) & npm**: Required to build the frontend control panel (`ostp-control`) and compile Tauri GUI resources.
*   **Git**: For version control.

### Building the Project

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/ospab/ostp.git
    cd ostp
    ```

2.  **Build the control panel frontend**:
    ```bash
    cd ostp-control
    npm install
    npm run build
    cd ..
    ```

3.  **Build the entire Cargo workspace**:
    ```bash
    cargo build
    ```

4.  **Run tests**:
    ```bash
    cargo test --workspace
    ```

---

## Project Structure

The repository is organized as a Cargo workspace containing the following crates:

*   [`ostp-core/`](file:///d:/ospab-projects/ostp/ostp-core): Core protocol logic, including packet formatting, serialization, selective ACK/NACK (ARQ) state machine, and the Noise protocol (`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`) handshake.
*   [`ostp-client/`](file:///d:/ospab-projects/ostp/ostp-client): Client implementations, including SOCKS5/HTTP local proxies, `tun2socks` integration, native TUN interface routing, and split-tunneling bypass mechanisms.
*   [`ostp-server/`](file:///d:/ospab-projects/ostp/ostp-server): Server logic, session dispatcher, anti-probing fallback server proxying, access key database, and the REST API for control panel communication.
*   [`ostp-control/`](file:///d:/ospab-projects/ostp/ostp-control): A modern web dashboard for server administration (user management, real-time metrics, bandwidth limits).
*   [`ostp-gui/`](file:///d:/ospab-projects/ostp/ostp-gui): Tauri-based desktop GUI application for Windows and Linux.
*   [`ostp-flutter/`](file:///d:/ospab-projects/ostp/ostp-flutter): Mobile client code for Android platforms.

---

## Development Workflow

1.  **Check for existing issues** or open a new one to discuss proposed changes before starting work.
2.  **Fork the repository** and create a new branch from `master`:
    ```bash
    git checkout -b feat/your-feature-name
    ```
3.  **Implement your changes**, ensuring you write appropriate unit or integration tests.
4.  **Format your code**:
    ```bash
    cargo fmt --all
    ```
5.  **Run linter checks**:
    ```bash
    cargo clippy --workspace --all-targets -- -D warnings
    ```
6.  **Ensure all tests pass**:
    ```bash
    cargo test --workspace
    ```

---

## Coding Guidelines

*   **Safety**: Avoid using `unsafe` blocks unless absolutely necessary for low-level system bindings (e.g., FFI configurations like `setsockopt`). When using `unsafe`, add safety doc comments explaining why it is safe.
*   **Documentation**: Document public modules, structs, and functions. Maintain comment integrity across codebase changes.
*   **Logging**: Use the `tracing` framework for structured logging. Avoid `println!` for production logs.
*   **Aesthetics**: When editing GUI or Web components, adhere to premium, modern web design aesthetics (vibrant color palettes, glassmorphism, responsive grids).

---

## Submitting Pull Requests

1.  Push your branch to your GitHub fork:
    ```bash
    git push origin feat/your-feature-name
    ```
2.  Open a Pull Request (PR) targeting the `master` branch.
3.  In your PR description, explain the rationale behind your changes, what was fixed/added, and how it was tested.
4.  Verify that GitHub Actions CI runs successfully on your PR.

---

## Security Vulnerabilities

If you discover a security-related vulnerability, please do **not** open a public issue. Instead, report it privately by emailing the core maintainers at [gvoprgrg@gmail.com](mailto:gvoprgrg@gmail.com). We will coordinate a swift disclosure and fix.
