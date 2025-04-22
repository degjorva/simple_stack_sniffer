#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import re
import json
import shutil
from pathlib import Path

# Optional Graphviz support
try:
    import graphviz
except ImportError:
    graphviz = None

# ---- UTILS ----
def find_gcc_toolchain_prefix():
    for prefix in ["arm-none-eabi-", "riscv64-unknown-elf-", "riscv32-unknown-elf-"]:
        if shutil.which(prefix + "objdump"):
            return prefix
    if shutil.which("objdump"):
        return ""
    return None


def demangle_names(names, tool_prefix):
    filt = shutil.which(tool_prefix + "c++filt") if tool_prefix else shutil.which("c++filt")
    if not filt:
        return {n: n for n in names}
    proc = subprocess.run([filt], input="\n".join(names), text=True, capture_output=True)
    if proc.returncode != 0:
        return {n: n for n in names}
    return dict(zip(names, proc.stdout.strip().splitlines()))

# ---- SYMBOL AND PARSING STRUCTS ----
class FunctionSymbol:
    def __init__(self, name, address):
        self.name = name
        self.display_name = name
        self.address = address
        self.stack_size = None
        self.stack_qualifier = None
        self.callees = []
        self.callers = []

# ---- MAIN FUNCTIONS ----
def build_call_graph(elf_path, tool_prefix, verbose=False):
    cmd = [tool_prefix + "objdump", "-d", "-l", "-w", "-S", elf_path]
    try:
        asm = subprocess.check_output(cmd, text=True, errors="ignore")
    except subprocess.CalledProcessError as e:
        sys.exit(f"[ERROR] objdump failed: {e}")

    symbols = []
    sym_by_addr = {}
    call_links = []
    current_func = None
    func_pat = re.compile(r"^([0-9A-Fa-f]+) <(.+)>:")
    call_pat = re.compile(
        r"\s+[0-9a-f]+:\s+[0-9a-f ]+\s+(blx?|b\.w|bl)\s+([0-9a-f]+)", re.IGNORECASE
    )

    for line in asm.splitlines():
        m = func_pat.match(line)
        if m:
            addr = int(m.group(1), 16)
            name = m.group(2)
            current_func = FunctionSymbol(name, addr)
            symbols.append(current_func)
            sym_by_addr[addr] = current_func
        elif current_func:
            cm = call_pat.search(line)
            if cm:
                target = int(cm.group(2), 16)
                call_links.append((current_func, target))

    for caller, target in call_links:
        callee = sym_by_addr.get(target)
        if callee and callee not in caller.callees:
            caller.callees.append(callee)
            callee.callers.append(caller)

    demangled = demangle_names([s.name for s in symbols], tool_prefix)
    for s in symbols:
        s.display_name = demangled.get(s.name, s.name)

    if verbose:
        print(f"[INFO] Loaded {len(symbols)} functions from ELF")
    return symbols


def assign_stack_usage(symbols, build_dir, verbose=False):
    su_files = list(Path(build_dir).rglob("*.su"))
    if not su_files:
        print(f"[WARNING] No .su files found under {build_dir}")
    else:
        if verbose:
            print(f"[INFO] Found {len(su_files)} .su files")

    for su in su_files:
        try:
            with open(su, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) < 2:
                        if verbose:
                            print(f"[SKIP] Not enough tab-separated parts: {line}")
                        continue

                    meta = parts[0]
                    stack_str = parts[1].strip().split()[0]
                    try:
                        stack = int(stack_str)
                    except ValueError:
                        if verbose:
                            print(f"[SKIP] Could not parse stack size from '{stack_str}' in line: {line}")
                        continue

                    func_name = meta.split(":")[-1].strip()
                    for s in symbols:
                        if s.display_name == func_name or s.name == func_name or func_name.endswith(s.name):
                            if s.stack_size is None or stack > s.stack_size:
                                s.stack_size = stack
                                s.stack_qualifier = parts[1].strip().split()[1] if len(parts[1].strip().split()) > 1 else ""
                            break
        except Exception as e:
            print(f"[ERROR] Failed to read {su}: {e}")


def compute_all_paths(func):
    paths = []

    def dfs(current, path, total, visited):
        if current in visited:
            return
        visited = visited | {current}
        current_stack = current.stack_size or 0
        new_total = total + current_stack
        new_path = path + [current]

        if not current.callees:
            paths.append((new_total, new_path))
        else:
            for callee in current.callees:
                dfs(callee, new_path, new_total, visited)

    dfs(func, [], 0, set())
    return sorted(paths, key=lambda x: x[0], reverse=True)

# ---- CLI ENTRY ----
def main():
    parser = argparse.ArgumentParser(description="Generate worst-case stack usage reports.")
    parser.add_argument("--elf", help="Path to the ELF file.")
    parser.add_argument("--build-dir", help="Directory containing .su files.")
    parser.add_argument(
        "-wcs", "--worst-case-stack",
        metavar="FUNC",
        action="append",
        help=(
            "Literal function name(s) to analyze. Repeat for each, or pass names joined by '&&'."
        )
    )
    parser.add_argument(
        "-wcr", "--worst-case-regex",
        metavar="PATTERN",
        action="append",
        help="Regex pattern(s) to match functions. Repeat for each."
    )
    parser.add_argument(
        "--list-symbols",
        nargs="?",
        const=".*",
        metavar="REGEX",
        help="List all symbols matching optional REGEX and exit."
    )
    parser.add_argument(
        "--dot-output",
        metavar="PREFIX",
        help="Generate Graphviz .dot files for each worst-case path, prefix naming by PREFIX."
    )
    parser.add_argument(
        "--no-dot",
        action="store_true",
        help="Disable generating .dot files even if --dot-output is set."
    )
    parser.add_argument(
        "--graph-format",
        choices=["png", "svg", "pdf"],
        help="Generate rendered graph images in the specified format (requires graphviz)."
    )
    parser.add_argument("--output", default="stack_report.json", help="JSON report output path.")
    parser.add_argument("--gcc-prefix", help="GCC toolchain prefix (e.g. arm-none-eabi-)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    args = parser.parse_args()

            # Infer build-dir and elf if neither provided
    if not args.elf and not args.build_dir:
        cwd = Path(os.getcwd())
        app = cwd.name
        default_build = cwd / "build" / app
        if default_build.is_dir():
            # Check typical Zephyr structure under build/<app>/zephyr
            zephyr_dir = default_build / "zephyr"
            if zephyr_dir.is_dir():
                # Look for common ELF locations
                elf_main = zephyr_dir / f"{app}.elf"
                elf_zephyr = zephyr_dir / "zephyr.elf"
                elf_pre = zephyr_dir / "zephyr_pre0.elf"
                if elf_main.is_file():
                    args.elf = str(elf_main)
                elif elf_zephyr.is_file():
                    args.elf = str(elf_zephyr)
                elif elf_pre.is_file():
                    args.elf = str(elf_pre)
                else:
                    elf_files = list(zephyr_dir.glob("*.elf"))
                    if len(elf_files) == 1:
                        args.elf = str(elf_files[0])
                    else:
                        sys.exit(
                            f"[ERROR] Could not find a single ELF under {zephyr_dir}. "
                            f"Please specify --elf path/to/<app>.elf and --build-dir {default_build}."
                        )
                args.build_dir = str(default_build)
                if args.verbose:
                    print(f"[INFO] Auto-detected build-dir: {args.build_dir}, elf: {args.elf}")
            else:
                # Fallback: look for ELF in default_build
                elf_app = default_build / f"{app}.elf"
                if elf_app.is_file():
                    args.elf = str(elf_app)
                    args.build_dir = str(default_build)
                    if args.verbose:
                        print(f"[INFO] Auto-detected build-dir: {args.build_dir}, elf: {args.elf}")
                else:
                    elf_files = list(default_build.rglob("*.elf"))
                    if len(elf_files) == 1:
                        args.build_dir = str(default_build)
                        args.elf = str(elf_files[0])
                        if args.verbose:
                            print(f"[INFO] Auto-detected build-dir: {args.build_dir}, elf: {args.elf}")
        elif len(elf_files) > 1:
            sys.exit(
                "[ERROR] Multiple .elf files found under {} and its subdirs ({}). "
                "Please specify --elf path/to/{}.elf and --build-dir {}."
                .format(
                    default_build,
                    ', '.join(str(p) for p in elf_files),
                    app,
                    default_build
                )
            )

        else:
            sys.exit(
                f"[ERROR] Default build directory '{default_build}' not found."
                f"Please specify --elf path/to/{app}.elf and --build-dir {cwd}/build/{app}."
            )
    elif (args.elf and not args.build_dir) or (args.build_dir and not args.elf):
        sys.exit(
            "[ERROR] Both --elf and --build-dir must be specified together, or neither to auto-detect."
        )

    # Normalize tool prefix
    tool_prefix = args.gcc_prefix or find_gcc_toolchain_prefix() or ""
    if tool_prefix and not tool_prefix.endswith("-"):
        tool_prefix += "-"

    symbols = build_call_graph(args.elf, tool_prefix, verbose=args.verbose)
    assign_stack_usage(symbols, args.build_dir, verbose=args.verbose)

    # Handle --list-symbols
    if args.list_symbols is not None:
        pat = re.compile(args.list_symbols)
        for s in symbols:
            if pat.search(s.display_name) or pat.search(s.name):
                print(s.display_name)
        sys.exit(0)

    if not args.worst_case_stack and not args.worst_case_regex:
        sys.exit("[ERROR] No targets specified; use -wcs for literal names or -wcr for regex patterns.")

    # Prepare targets
    literal_targets = []
    if args.worst_case_stack:
        for entry in args.worst_case_stack:
            for part in entry.split("&&"):
                p = part.strip()
                if p:
                    literal_targets.append(p)
    regex_targets = args.worst_case_regex or []

    report = {}
    # Process literal names
    for name in literal_targets:
        candidates = [f for f in symbols
                      if f.display_name == name or f.name == name or name.endswith(f.name)]
        if not candidates:
            print(f"[WARN] Function '{name}' not found in symbols")
            continue
        for func in candidates:
            if args.verbose:
                print(f"[INFO] Computing paths for {func.display_name}")
            all_paths = compute_all_paths(func)
            if not all_paths:
                print(f"[WARN] No call paths for '{func.display_name}'")
                continue
            best_total, best_path = all_paths[0]
            report[func.display_name] = {
                "max_static_stack_size": best_total,
                "call_stack": [
                    {"function": f.display_name, "name": f.name,
                     "stack_size": f.stack_size if f.stack_size is not None else "???"}
                    for f in best_path
                ]
            }

            # Graphviz
            if args.dot_output or args.graph_format:
                if graphviz is None:
                    print("[ERROR] graphviz Python package not installed; cannot generate graphs")
                else:
                    dot = graphviz.Digraph(name=func.display_name)
                    for node in best_path:
                        dot.node(node.display_name, label=node.display_name)
                    for a, b in zip(best_path, best_path[1:]):
                        dot.edge(a.display_name, b.display_name)
                    base = f"{args.dot_output}_{func.display_name}" if args.dot_output else func.display_name
                    if args.graph_format:
                        try:
                            out_path = dot.render(filename=base, format=args.graph_format, cleanup=args.no_dot)
                            print(f"[INFO] Wrote graph image to {out_path}")
                        except Exception as e:
                            print(f"[ERROR] Failed to render graph: {e}")
                    elif args.dot_output and not args.no_dot:
                        dot_path = f"{base}.dot"
                        dot.save(filename=dot_path)
                        print(f"[INFO] Wrote Graphviz .dot to {dot_path}")

    # Process regex patterns
    for pattern in regex_targets:
        pat = re.compile(pattern)
        matched = [f for f in symbols if pat.search(f.display_name) or pat.search(f.name)]
        if not matched:
            print(f"[WARN] No functions match regex '{pattern}'")
            continue
        for func in matched:
            if args.verbose:
                print(f"[INFO] Computing paths for {func.display_name}")
            all_paths = compute_all_paths(func)
            if not all_paths:
                print(f"[WARN] No call paths for '{func.display_name}'")
                continue
            best_total, best_path = all_paths[0]
            report[func.display_name] = {
                "max_static_stack_size": best_total,
                "call_stack": [
                    {"function": f.display_name, "name": f.name,
                     "stack_size": f.stack_size if f.stack_size is not None else "???"}
                    for f in best_path
                ]
            }
            if args.dot-output or args.graph_format:
                if graphviz is None:
                    print("[ERROR] graphviz Python package not installed; cannot generate graphs")
                else:
                    dot = graphviz.Digraph(name=func.display_name)
                    for node in best_path:
                        dot.node(node.display_name, label=node.display_name)
                    for a, b in zip(best_path, best_path[1:]):
                        dot.edge(a.display_name, b.display_name)
                    base = f"{args.dot_output}_{func.display_name}" if args.dot_output else func.display_name
                    if args.graph_format:
                        try:
                            out_path = dot.render(filename=base, format=args.graph_format, cleanup=args.no_dot)
                            print(f"[INFO] Wrote graph image to {out_path}")
                        except Exception as e:
                            print(f"[ERROR] Failed to render graph: {e}")
                    elif args.dot_output and not args.no_dot:
                        dot_path = f"{base}.dot"
                        dot.save(filename=dot_path)
                        print(f"[INFO] Wrote Graphviz .dot to {dot_path}")

    # Write JSON report
    with open(args.output, "w") as out_f:
        json.dump(report, out_f, indent=4)
    print(f"[DONE] JSON report: {args.output}")

if __name__ == "__main__":
    main()
