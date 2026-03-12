# universal-flutter-ssl-pinning

Reverse-engineers `libflutter.so` with PyGhidra to locate the SSL certificate verification function, then emits ready-to-use bypass scripts for both **Frida** and **Renef**.

## How it works

1. PyGhidra loads `libflutter.so` headlessly and scans all defined strings for `ssl_client`
2. Cross-references from that string are resolved to their containing functions
3. Each function is decompiled to get an accurate parameter count
4. The 3-parameter function is selected — this is `ssl_crypto_x509_session_verify_cert_chain`
5. Its RVA is baked into:
   - A **Frida** script (`flutter_ssl_pinning.js`) that patches the return value to `ptr(1)` (SSL_VERIFY_OK) at runtime
   - A **Renef** script (`flutter_ssl_pinning.lua`) that uses `Memory.patch` to overwrite the function entry with `MOV X0, #1 ; RET` (ARM64)

## Requirements

- [Ghidra](https://ghidra-sre.org/) — `brew install ghidra`
- [pyghidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraBridge) — `pip install pyghidra`
- **Frida** — `pip install frida-tools`  *or*  **Renef** — [renef.io](https://renef.io)

> Set `GHIDRA_INSTALL_DIR` in your environment, or pass `--ghidra-install-dir`.

## Usage

```bash
# Analyse libflutter.so and generate both scripts
python3 flutter_ssl_pinning.py libflutter.so

# Run with Frida
frida -U -f com.example.app -l flutter_ssl_pinning.js

# Run with Renef
renef -s com.example.app -l flutter_ssl_pinning.lua
```

## Options

| Argument | Default | Description |
|---|---|---|
| `binary` | *(required)* | Path to `libflutter.so` |
| `output` | `flutter_ssl_pinning` | Output base name (generates `<name>.js` and `<name>.lua`) |
| `--module` | `libflutter.so` | Module name in target process |
| `--ghidra-install-dir` | auto | Ghidra installation directory |

## Output files

| File | Tool | Mechanism |
|---|---|---|
| `flutter_ssl_pinning.js` | Frida | `Interceptor.attach` + `retval.replace(ptr(1))` |
| `flutter_ssl_pinning.lua` | Renef | `Memory.patch` (MOV X0, #1 ; RET) |

See the [`example/`](example/) directory for sample generated output.

---

## Tested on

| Target | Status |
|---|---|
| Google Flutter `libflutter.so` (arm64-v8a) | ✅ Working |
| Shorebird-patched Flutter builds | ✅ Working |
| Ghidra 12.x + pyghidra | ✅ Working |
| Frida 16.x | ✅ Working |
| Renef (latest) | ✅ Working |

> Both Google Flutter and Shorebird use the same `libflutter.so` SSL engine.
> The auto-discovered RVA is identical across build types for the same Flutter engine version.

---

## Disclaimer

This tool is intended for **authorised security research and penetration testing only**.  
Do not use against apps you do not own or have explicit written permission to test.
