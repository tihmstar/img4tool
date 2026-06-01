# img4tool Termux helper

This repository adds two minimal Termux-friendly tools in `tools/`:

- `dsbug`: a tiny restore-log analyzer that searches logs for `typereq` / `np explanation` patterns and prints context and suggestions.
- `img4tool-termux`: a minimal helper to inspect binary `.img4`-like files (prints size and first bytes).

Build on Termux:

1. Install toolchain in Termux:

```sh
pkg update
pkg install clang make build-essential
```

2. Build the tools:

```sh
cd /path/to/repo/tools
make CC=clang++
```

3. Package for transfer (optional):

```sh
./package_termux.sh
```

Usage examples:

```sh
# analyze a restore log
cat restore.log | ./dsbug/dsbug

# inspect an img4 blob
./img4tool-termux/img4tool-termux inspect myfile.img4
```

Notes:
- These tools are lightweight and intentionally avoid external dependencies so they can build on Termux. They are a starting point and can be extended with more specific parsers or heuristics.
