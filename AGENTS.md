# HyperPill-smp Agent Instructions

This file is for agentic coding assistants operating in this repository.
Keep changes minimal, simple, and consistent with existing patterns.

## Build

**Compiler**: always use clang.

```bash
# Build the main binary (default target: fuzz)
CC=clang CXX=clang++ make

# Clean rebuild (recommended when vendor/ changes)
make clean && CC=clang CXX=clang++ make

# Debug build (adds -O0 -g)
CC=clang CXX=clang++ make DEBUG=1
```

Notes:
- The default `make` target builds the `fuzz` binary.
- The build invokes Bochs and libFuzzer-ng builds as dependencies.
- `make clean` removes `vendor/bochs-build`, `vendor/lib`, `vendor/include`, and objects.

## Tests

There is no unit-test framework. Testing is mostly “build PoCs + run with a snapshot”.

### Build PoC tests

```bash
# Builds: tests/cve-2021-3947 and tests/cve-2022-0216
CC=clang CXX=clang++ make tests
```

### Run a single PoC test

Pick one PoC name from `tests/` (without `.cc`). Run from a separate working dir
(the scripts copy the binary into the CWD before executing).

```bash
export PROJECT_ROOT=/abs/path/to/HyperPill-smp
export SNAPSHOT_BASE=/abs/path/to/snapshots/<snapshot>

# Required: choose exactly one target mode
export KVM=1   # or HYPERV=1, or MACOS=1

$PROJECT_ROOT/tests/run_hyperpill.sh cve-2021-3947
# or
$PROJECT_ROOT/tests/run_hyperpill.sh cve-2022-0216
```

### Run the main fuzzer (manual)

Do not run fuzzing automatically unless the user asks.

```bash
export PROJECT_ROOT=/abs/path/to/HyperPill-smp
export SNAPSHOT_BASE=/abs/path/to/snapshots/<snapshot>
export KVM=1

mkdir -p CORPUS
export CORPUS_DIR=$PWD/CORPUS
export NSLOTS=$(nproc)

$PROJECT_ROOT/scripts/run_hyperpill.sh
```

Reproduce a single crash file:

```bash
$PROJECT_ROOT/scripts/run_hyperpill.sh crash-<id>
```

Debug via `gdb --args` locally:

```bash
GDB_LOCAL=1 $PROJECT_ROOT/scripts/run_hyperpill.sh crash-<id>
```

### Coverage mode

See `README.md` for the full workflow.

```bash
$PROJECT_ROOT/scripts/run_hyperpill2.sh
```

## Lint / Formatting

There is no repo-provided “lint” target.

### clang-format

Formatting configuration is in `.clang-format`.

Key expectations from config:
- Tabs for indentation (`UseTab: Always`, `TabWidth: 8`, `IndentWidth: 8`)
- 80-column limit (`ColumnLimit: 80`)
- Includes are not auto-sorted (`SortIncludes: false`, preserve blocks)

```bash
# Format specific files (preferred over formatting the whole repo)
clang-format -i main.cc fuzz.cc fuzz.h
```

Only run clang-format on many files if the user asks.

## Code Style (C/C++)

Follow the existing codebase and `.clang-format`.

### Formatting
- Indent with tabs, width 8.
- Keep lines <= 80 chars when reasonable.
- Prefer small, readable functions over clever code.

### Includes
- Do not sort/reorder includes mechanically.
- Keep include groups stable (project headers vs system headers).
- Prefer including what you use; avoid relying on transitive includes.

### Naming
Observed conventions are mixed; default to:
- Functions/variables: `snake_case`
- Types/structs/classes: `UpperCamelCase`
- Constants: `kCamelCase` for local constants; `UPPER_SNAKE_CASE` for macros

### Types
- Prefer fixed-width integers (`uint64_t`, `uint32_t`, etc.) for serialized data
  and external interfaces.
- Use Bochs/VM types (`bx_address`, `bx_phy_address`, `Bit*`) when interacting with
  Bochs APIs.
- Avoid implicit narrowing conversions; use `static_cast<>`.

### Error handling
- Use `assert()` for invariants and “should never happen” conditions.
- For expected failures, return `bool`/`int` status.
- When a syscall/library call fails, print a message (`perror()` or
  `fprintf(stderr, ...)`) and return an error.
- Avoid exceptions and empty `catch` blocks.

### Logging
- Prefer explicit, grep-friendly logs.
- Use `fprintf(stderr, ...)` for errors.

## Project Knowledge / Safety

- CPU 0 is always used as the KVM vCPU.
- Running fuzzing/PoCs requires snapshots and can take a long time. Do not run
  long fuzzing loops without an explicit user request and a timeout.
- Avoid large refactors while fixing bugs; keep diffs tight.

## Editor / Assistant Rules

- Do not run `git commit` unless the user explicitly instructs or approves.
- For each user request, make a detailed plan and TODO list; do not start
  coding until the user says "approve".
- No Cursor rules found (`.cursor/rules/` or `.cursorrules`).
- No Copilot rules found (`.github/copilot-instructions.md`).
