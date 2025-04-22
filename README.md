# custom-worst-stack

A command-line tool to compute worst-case static stack usage for functions generated in ncs connect, with optional call-graph visualization using Graphviz.

---

## Features

* **Exact and Regex Targets**: Analyze specific functions by name (`-wcs/--worst-case-stack`) or by regex patterns (`-wcr/--worst-case-regex`).
* &#x20;

  **Auto-Detection**: Automatically finds the ELF and build directory under `build/<project_name>` or `build/<project_name>/zephyr/`, including common names (`<project>.elf`, `zephyr.elf`, `zephyr_pre0.elf`).
* **Graphviz Output**: Generate DOT files (`--dot-output`) or render graphs to `png`, `svg`, or `pdf` (`--graph-format`), with optional suppression of DOT via `--no-dot`.
* **Symbol Listing**: Print all symbols or those matching a regex (`--list-symbols`).
* **Verbose Logging**: Detailed INFO/WARN messages with `--verbose`.

---

## Prerequisites

* Python 3.6+
* GNU `objdump` and `c++filt` in your PATH (or specify `--gcc-prefix`).
* (Optional) [Graphviz Python package](https://pypi.org/project/graphviz/) for graph output.

```bash
pip install graphviz
```

---

## Installation

Clone or copy `custom-worst-stack.py` into your project’s scripts directory.

Ensure it is executable:

```bash
chmod +x custom-worst-stack.py
```

---

## Usage

First build you project using the following extra flag:
```
-DEXTRA_CFLAGS="-fstack-usage"
```

### Auto-Detect Mode

If you run without `--elf` and `--build-dir`, the script attempts to locate them automatically under:

```
./build/<project>/zephyr/<project>.elf
# or zephyr.elf / zephyr_pre0.elf
```

If exactly one ELF is found, it proceeds. Otherwise you'll see an error with instructions.

### Explicit Mode

Specify both the ELF path and build directory manually:

```bash
./custom-worst-stack.py \
  --elf path/to/project.elf \
  --build-dir path/to/build/project \
  -wcs main -wcs init_function \
  --dot-output stack_graph \
  --graph-format svg
```

### Analyze by Regex

```bash
./custom-worst-stack.py \
  --elf build/myapp/myapp.elf \
  --build-dir build/myapp \
  -wcr "^init_.*" \
  -wcr "handle_.*" \
  --no-dot  # only render images, no .dot files
```

### List Symbols

```bash
./custom-worst-stack.py --list-symbols             # list all symbols
./custom-worst-stack.py --list-symbols "^us.*"   # symbols starting with 'us'
```

---

## Command-Line Options

| Option                       | Description                                                  |        |                                                            |
| ---------------------------- | ------------------------------------------------------------ | ------ | ---------------------------------------------------------- |
| `-wcs`, `--worst-case-stack` | Literal function name(s), repeatable or joined with `&&`.    |        |                                                            |
| `-wcr`, `--worst-case-regex` | Regex pattern(s), repeatable.                                |        |                                                            |
| `--list-symbols [REGEX]`     | List symbols (filtered by REGEX if provided) and exit.       |        |                                                            |
| `--elf <path>`               | Path to the ELF binary.                                      |        |                                                            |
| `--build-dir <dir>`          | Directory containing `.su` files (stack usage data).         |        |                                                            |
| `--dot-output <prefix>`      | Prefix for Graphviz `.dot` files (one per function).         |        |                                                            |
| `--no-dot`                   | Suppress `.dot` file creation even if `--dot-output` is set. |        |                                                            |
| \`--graph-format \<png       | svg                                                          | pdf>\` | Render graph images in given format (requires `graphviz`). |
| `--output <file>`            | JSON report output path (default: `stack_report.json`).      |        |                                                            |
| `--gcc-prefix <prefix>`      | GCC toolchain prefix (e.g. `arm-none-eabi-`).                |        |                                                            |
| `--verbose`                  | Enable verbose INFO/WARN logging.                            |        |                                                            |

---

## Output

* **JSON Report** (`--output`): Contains each function’s maximum static stack size and the call stack leading to that usage.
* **Graph Files**: DOT or rendered images illustrating the worst-case call path.

---

## Examples

1. **Basic**: Analyze `main` with auto-detection:

   ```bash
   ./custom-worst-stack.py -wcs main
   ```
2. **Multiple Functions**:

   ```bash
   ./custom-worst-stack.py --elf app.elf --build-dir build/app \
     -wcs funcA && funcB
   ```
3. **Regex + SVG**:

   ```bash
   ./custom-worst-stack.py -wcr "^task_.*" --graph-format svg
   ```

---

## License

MIT © Dag Erik Refshal Gjørvad
