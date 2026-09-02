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
| `-v`, `--verbose` | off | Show PyGhidra/Ghidra output and Python tracebacks |
| `--debug-report [PATH]` | off | Write environment, binary hash, timing, and analysis counters to JSON |
| `--keep-project` | off | Keep the unique temporary Ghidra project for manual inspection |

## Troubleshooting

Ghidra analysis is CPU-intensive and may take **2-5 minutes**, especially on the
first run. The tool now prints a heartbeat every 15 seconds, so a long analysis
does not look frozen.

For a reproducible support bundle, run:

```bash
python3 flutter_ssl_pinning.py libflutter.so \
  --verbose --debug-report debug.json > debug.log 2>&1
```

On Windows `cmd.exe`:

```bat
python flutter_ssl_pinning.py libflutter.so --ghidra-install-dir "G:\ghidra_12.0.4_PUBLIC" --verbose --debug-report debug.json > debug.log 2>&1
```

Attach `debug.log` and `debug.json` to the issue. The JSON report contains the
OS/Python/PyGhidra/Ghidra versions, SHA-256 and size of the input, raw
`ssl_client` matches, Ghidra-defined string matches, xref counts, function count,
and total duration. This distinguishes installation/analysis failures from a
Flutter binary whose expected anchor or xref shape has changed.

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
| Frida 17.x and 16.x | ✅ Working |
| Renef (latest) | ✅ Working |

> Both Google Flutter and Shorebird use the same `libflutter.so` SSL engine.
> The auto-discovered RVA is identical across build types for the same Flutter engine version.

---

## Quick Traffic Capture (no proxy)

Besides bypassing pinning for a proxy-based MITM, you can capture decrypted HTTP
traffic **directly in Frida** with the self-contained `flutter_http_monitor.py`.
It auto-locates BoringSSL `SSL_write`/`SSL_read` in `libflutter.so` (any Flutter
version, arm64) and generates a Frida script that prints plaintext requests and
responses — reassembled, de-chunked, gunzipped, and JSON pretty-printed.

```bash
pip install capstone pyelftools

# scan the binary and generate the monitor (or pass an .apk)
python3 flutter_http_monitor.py path/to/libflutter.so -o monitor.js

# run it against the app
frida -U -f com.target.app -l monitor.js
```

Optional, live in the Frida REPL: `addScope('api.example.com')` to watch only
specific hosts (Burp-style scope). Single file — nothing else to ship.


## Disclaimer

This tool is intended for **authorised security research and penetration testing only**.  
Do not use against apps you do not own or have explicit written permission to test.



<a href="https://www.star-history.com/?repos=vichhka-git%2Funiversal-flutter-ssl-pinning&type=date&legend=bottom-right">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/image?repos=vichhka-git/universal-flutter-ssl-pinning&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/image?repos=vichhka-git/universal-flutter-ssl-pinning&type=date&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/image?repos=vichhka-git/universal-flutter-ssl-pinning&type=date&legend=bottom-right" />
 </picture>
</a>
