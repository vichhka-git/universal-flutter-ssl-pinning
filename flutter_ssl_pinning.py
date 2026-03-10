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

function hookCandidate(mod, candidate) {{
    var addr = mod.base.add(candidate.rva);
    if (addr.compare(mod.base.add(mod.size)) >= 0) {{
        console.log("[-] " + candidate.name + ": RVA " + candidate.rva + " outside module bounds");
        return;
    }}
    try {{
        Interceptor.attach(addr, {{
            onLeave: function (retval) {{
                retval.replace(ptr(1));
            }}
        }});
        console.log("[+] Hooked " + candidate.name + " @ " + addr);
    }} catch (e) {{
        console.log("[-] Failed to hook " + candidate.name + ": " + e.message);
    }}
}}

function bypassSslPinning() {{
    var mod = Process.findModuleByName(TARGET_MODULE);
    if (!mod) {{
        console.log("[-] Module not found: " + TARGET_MODULE);
        return;
    }}
    console.log("[*] SSL pinning bypass starting (" + HOOK_CANDIDATES.length + " candidate(s))");
    HOOK_CANDIDATES.forEach(function (c) {{ hookCandidate(mod, c); }});
    console.log("[+] Done.");
}}

setTimeout(bypassSslPinning, 1000);
'''


def main() -> int:
    parser = argparse.ArgumentParser(
        description="libflutter.so -> PyGhidra SSL recon -> Frida bypass script"
    )
    parser.add_argument("binary", help="Path to libflutter.so")
    parser.add_argument("output", nargs="?", default="flutter_ssl_pinning.js", help="Output .js path")
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
    output_path = Path(args.output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(js_text, encoding="utf-8")

    print(f"[+] Written: {output_path}")
    print(f"\n    frida -U -f <package> -l {output_path.name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
