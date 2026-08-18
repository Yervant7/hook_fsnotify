# hook_fsnotify

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**hook_fsnotify** is a KernelPatch Module (KPM) that hooks the `fsnotify` syscall on Linux kernels ranging from **5.10** up to **6.12**.

---

## 📖 Overview

- **Name**: `hook_fsnotify`
- **Version**: `1.1.0`
- **License**: MIT
- **Author**: Yervant7
- **Target Architecture**: ARM64 (`aarch64`)
- **Supported Kernel Range**: 5.10 – 6.12 (GKI Android kernels)

---

## ✨ Features

- Inline‑hook of `fsnotify` to filter out notifications from `/proc`.
- Runtime control commands: `enable`, `disable`, `status`, `toggle`.
- Safe pointer handling – every struct traversal checks for `NULL` to avoid kernel panics.
- Fully compatible with KernelPatch's symbol resolution and hooking APIs.

---

## 📦 Build & Release

The project uses a standard Makefile to produce a `.kpm` binary.

```bash
# Clone the repository
git clone --recurse-submodules https://github.com/Yervant7/hook_fsnotify.git
cd hook_fsnotify

# Build the KPM (requires aarch64-none-elf-gcc)
make
```

The resulting artifact will be placed in `hook_fsnotify.kpm`.

## 🛠️ Usage

After loading the KPM on the target device, you can control it using the KPM control interface:

---

## 📜 License

This project is licensed under the **MIT License** – see the `LICENSE` file for details.

---

## 🙋‍♂️ Author

**Yervant7** – <https://github.com/Yervant7>
