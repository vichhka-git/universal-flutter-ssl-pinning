#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import os
import re
import shutil
import sys
import time
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


def _safe_str(value: object) -> str:
    try:
        return str(value)
    except Exception:
        return "<unprintable>"


def _to_hex_offset(program, address) -> Optional[str]:
    image_base = program.getImageBase()
    if image_base is None or address is None:
        return None
    try:
        return hex(int(address.subtract(image_base)))
    except Exception:
        return None


@dataclass
class FunctionRecord:
    name: str
    entry: str
    rva: Optional[str]
    parameter_count: int
    signature: str


def _iter_defined_strings(listing) -> Iterable:
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        try:
            if data.hasStringValue():
                yield data
        except Exception:
            continue


def _extract_function_record(program, func) -> FunctionRecord:
    entry = func.getEntryPoint()
    return FunctionRecord(
        name=_safe_str(func.getName()),
        entry=_safe_str(entry),
        rva=_to_hex_offset(program, entry),
        parameter_count=int(func.getParameterCount()),
        signature=_safe_str(func.getSignature()),
    )


def _count_params_from_signature(signature: str) -> Optional[int]:
    match = re.search(r"\((.*)\)", signature)
    if not match:
        return None
    content = match.group(1).strip()
    if not content or content == "void":
        return 0
    return len([p for p in content.split(",") if p.strip()])


def _decompile_signature_and_count(decomp_ifc, func) -> Tuple[Optional[str], Optional[int]]:
    try:
        result = decomp_ifc.decompileFunction(func, 60, None)
        if not result or not result.decompileCompleted():
            return None, None
        decompiled_fn = result.getDecompiledFunction()
        if decompiled_fn is None:
            return None, None
        signature = _safe_str(decompiled_fn.getSignature())
        return signature, _count_params_from_signature(signature)
    except Exception:
        return None, None


def _extract_function_record_with_fallback(program, func, decomp_ifc) -> FunctionRecord:
    record = _extract_function_record(program, func)
    if record.parameter_count != 0:
        return record
    decomp_sig, decomp_count = _decompile_signature_and_count(decomp_ifc, func)
    if decomp_sig is None or decomp_count is None:
        return record
    return FunctionRecord(
        name=record.name,
        entry=record.entry,
        rva=record.rva,
        parameter_count=int(decomp_count),
        signature=decomp_sig,
    )


def _analyze_program(flat_api, keyword: str) -> dict:
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp_ifc = DecompInterface()
    decomp_ifc.openProgram(program)

    keyword_lc = keyword.lower()
    unique_function_keys: Set[str] = set()
    unique_functions: List[FunctionRecord] = []
    candidate_three_arg: Dict[str, FunctionRecord] = {}

    try:
        for data in _iter_defined_strings(listing):
            value_text = _safe_str(data.getValue())
            if keyword_lc not in value_text.lower():
                continue

            refs_iter = reference_manager.getReferencesTo(data.getAddress())
            while refs_iter.hasNext():
                ref = refs_iter.next()
                from_func = function_manager.getFunctionContaining(ref.getFromAddress())
                if from_func is None:
                    continue
                func_record = _extract_function_record_with_fallback(program, from_func, decomp_ifc)
                func_key = func_record.entry
                if func_key not in unique_function_keys:
                    unique_function_keys.add(func_key)
                    unique_functions.append(func_record)
                if func_record.parameter_count == 3:
                    candidate_three_arg[func_key] = func_record
    finally:
        try:
            decomp_ifc.dispose()
        except Exception:
            pass

    return {
        "unique_functions_on_xrefs": [asdict(f) for f in sorted(unique_functions, key=lambda f: f.entry)],
        "candidate_functions_param_count_3": [asdict(f) for f in sorted(candidate_three_arg.values(), key=lambda f: f.entry)],
    }


@contextlib.contextmanager
def _suppress_java_output():
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    os.dup2(devnull_fd, 1)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)
    try:
        yield
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)


def _open_program_with_fallbacks(pyghidra_mod, binary_path: str, project_dir: str, project_name: str):
    attempts = [
        {"binary_path": binary_path, "project_location": project_dir, "project_name": project_name, "analyze": True},
        {"binary_path": binary_path, "analyze": True},
    ]
    last_error = None
    for params in attempts:
        try:
            return pyghidra_mod.open_program(**params)
        except TypeError as exc:
            last_error = exc
    raise RuntimeError(f"Unable to open program with pyghidra.open_program: {last_error}")


def _js_escape(text: str) -> str:
    return text.replace("*/", "* /").replace("\n", " ").replace("\r", "")


def generate_js(candidates: list[dict], module_name: str) -> str:
    lines = ["var HOOK_CANDIDATES = ["]
    for i, fn in enumerate(candidates):
        comma = "," if i < len(candidates) - 1 else ""
        sig = _js_escape(fn.get("signature", ""))
        lines.append(
            f'  {{ name: "{fn["name"]}", rva: "{fn["rva"]}", '
            f'params: {fn["parameter_count"]}, sig: "{sig}" }}{comma}'
        )
    lines.append("];")
    candidates_block = "\n".join(lines)
    return f'''"use strict";
var TARGET_MODULE = "{module_name}";
{candidates_block}

var IS_FRIDA_17 = typeof Module.getGlobalExportByName === "function";

function _findModuleExport(libName, symName) {{
    try {{
        if (IS_FRIDA_17) {{
            var m = Process.findModuleByName(libName);
            return m ? m.findExportByName(symName) : null;
        }}
        return Module.findExportByName(libName, symName);
    }} catch (_) {{ return null; }}
}}

function _findGlobalExport(symName) {{
    try {{
        if (IS_FRIDA_17) {{
            return Module.getGlobalExportByName(symName);
        }}
        return Module.findExportByName(null, symName);
    }} catch (_) {{ return null; }}
}}

function _findExportInModule(moduleObj, symName) {{
    try {{
        if (IS_FRIDA_17) {{
            return moduleObj.findExportByName(symName);
        }}
        return Module.findExportByName(moduleObj.name, symName);
    }} catch (_) {{ return null; }}
}}

function _resolveDlopen() {{
    var libNames    = ["libdl.so", "libdl-android.so"];
    var symNames    = ["android_dlopen_ext", "dlopen"];
    var linkerNames = ["linker64", "linker"];
    var linkerSyms  = ["android_dlopen_ext", "__loader_android_dlopen_ext", "dlopen"];

    for (var li = 0; li < libNames.length; li++)
        for (var si = 0; si < symNames.length; si++) {{
            var ep = _findModuleExport(libNames[li], symNames[si]);
            if (ep) return ep;
        }}

    for (var li2 = 0; li2 < linkerNames.length; li2++)
        for (var si2 = 0; si2 < linkerSyms.length; si2++) {{
            var ep2 = _findModuleExport(linkerNames[li2], linkerSyms[si2]);
            if (ep2) return ep2;
        }}

    for (var si3 = 0; si3 < symNames.length; si3++) {{
        var ep3 = _findGlobalExport(symNames[si3]);
        if (ep3) return ep3;
    }}

    var found = null;
    Process.enumerateModules().forEach(function (m) {{
        if (found) return;
        for (var si4 = 0; si4 < symNames.length; si4++) {{
            var ep4 = _findExportInModule(m, symNames[si4]);
            if (ep4) {{ found = ep4; break; }}
        }}
    }});
    return found;
}}

function hookCandidate(mod, candidate) {{
    var addr = mod.base.add(candidate.rva);
    if (addr.compare(mod.base.add(mod.size)) >= 0) {{
        return;
    }}
    try {{
        Interceptor.attach(addr, {{
            onLeave: function (retval) {{
                retval.replace(ptr(1));
            }}
        }});
    }} catch (e) {{ }}
}}

function bypassSslPinning(mod) {{
    HOOK_CANDIDATES.forEach(function (c) {{ hookCandidate(mod, c); }});
    console.log("[+] SSL pinning bypassed on " + mod.name + " @ " + mod.base);
}}

var mod = Process.findModuleByName(TARGET_MODULE);
if (mod) {{
    bypassSslPinning(mod);
}} else {{
    var dlopenPtr = _resolveDlopen();
    if (dlopenPtr) {{
        var listener = Interceptor.attach(dlopenPtr, {{
            onEnter: function (args) {{
                this.isTarget = false;
                if (args[0].isNull()) return;
                var path = args[0].readCString();
                if (path && path.indexOf("{module_name}") !== -1) {{
                    this.isTarget = true;
                }}
            }},
            onLeave: function (retval) {{
                if (!this.isTarget) return;
                var loadedMod = Process.findModuleByName(TARGET_MODULE);
                if (loadedMod) {{
                    bypassSslPinning(loadedMod);
                    listener.detach();
                }}
            }}
        }});
    }}
}}
'''

def generate_lua(candidates: list[dict], module_name: str) -> str:
    lines = ["local HOOK_CANDIDATES = {"]
    for i, fn in enumerate(candidates):
        comma = "," if i < len(candidates) - 1 else ""
        lines.append(
            f'  {{ name = "{fn["name"]}", rva = {fn["rva"]}, '
            f'params = {fn["parameter_count"]} }}{comma}'
        )
    lines.append("}")
    candidates_block = "\n".join(lines)

    return f'''local TARGET_MODULE = "{module_name}"

{candidates_block}

local base = Module.find(TARGET_MODULE)
if not base then
    print("[-] Module not found: " .. TARGET_MODULE)
    return
end

print("[*] SSL pinning bypass starting (" .. #HOOK_CANDIDATES .. " candidate(s))")
print(string.format("[+] %s found at: 0x%x", TARGET_MODULE, base))

-- ssl_crypto_x509_session_verify_cert_chain returns bool: true (1) = success.
-- Patch the function entry to: MOV X0, #1 ; RET
-- This avoids hook trampoline issues entirely.
-- MOV X0, #1 = \\x20\\x00\\x80\\xd2  (ARM64 little-endian)
-- RET         = \\xc0\\x03\\x5f\\xd6
for _, candidate in ipairs(HOOK_CANDIDATES) do
    local addr = base + candidate.rva
    Memory.patch(addr, "\\x20\\x00\\x80\\xd2\\xc0\\x03\\x5f\\xd6")
    print(string.format("[+] Patched %s @ 0x%x", candidate.name, addr))
end

print("[+] Done.")
'''


def main() -> int:
    parser = argparse.ArgumentParser(
        description="libflutter.so -> PyGhidra SSL recon -> Frida bypass script"
    )
    parser.add_argument("binary", help="Path to libflutter.so")
    parser.add_argument("output", nargs="?", default="flutter_ssl_pinning", help="Output base name (generates <name>.js and <name>.lua)")
    parser.add_argument("--module", default="libflutter.so", help="Module name in target process")
    parser.add_argument("--ghidra-install-dir", default=None, help="Ghidra installation directory")
    args = parser.parse_args()

    binary_path_obj = Path(args.binary).expanduser().resolve()
    if not binary_path_obj.exists():
        sys.exit(f"[!] Binary not found: {binary_path_obj}")

    binary_path = str(binary_path_obj)
    project_dir = str(Path(".ghidra_projects").resolve())
    os.makedirs(project_dir, exist_ok=True)

    import pyghidra
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    print(f"[*] Analyzing {binary_path_obj.name} ...")

    retry_project_name = None
    with _suppress_java_output():
        if args.ghidra_install_dir:
            pyghidra.start(args.ghidra_install_dir)
        else:
            pyghidra.start()

        try:
            with _open_program_with_fallbacks(pyghidra, binary_path, project_dir, "flutter_ssl_recon") as flat_api:
                report = _analyze_program(flat_api, "ssl_client")
        except Exception as exc:
            msg = _safe_str(exc)
            if "Unable to lock project" not in msg:
                raise
            retry_project_name = f"flutter_ssl_recon_{int(time.time())}_{os.getpid()}"
            with _open_program_with_fallbacks(pyghidra, binary_path, project_dir, retry_project_name) as flat_api:
                report = _analyze_program(flat_api, "ssl_client")

    shutil.rmtree(project_dir, ignore_errors=True)

    candidates = report.get("candidate_functions_param_count_3", [])
    if not candidates:
        candidates = report.get("unique_functions_on_xrefs", [])
    candidates = [fn for fn in candidates if fn.get("rva")]

    if not candidates:
        sys.exit("[!] No candidate functions found.")

    print(f"[+] Found {len(candidates)} candidate(s):")
    for fn in candidates:
        print(f"    {fn['name']}  RVA={fn['rva']}  params={fn['parameter_count']}")

    js_text = generate_js(candidates, args.module)
    output_base = Path(args.output).expanduser().resolve().with_suffix("")
    output_base.parent.mkdir(parents=True, exist_ok=True)
    output_path = output_base.with_suffix(".js")
    output_path.write_text(js_text, encoding="utf-8")

    lua_output_path = output_base.with_suffix(".lua")
    lua_text = generate_lua(candidates, args.module)
    lua_output_path.write_text(lua_text, encoding="utf-8")

    print(f"[+] Written: {output_path}")
    print(f"[+] Written: {lua_output_path}")
    print(f"\n    frida -U -f <package> -l {output_path.name}")
    print(f"    renef -s <package> -l {lua_output_path.name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
