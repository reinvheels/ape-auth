# Coding Conventions

## Zig

- **Prefer inlining over aliasing.** Don't wrap stdlib functions in trivial aliases (e.g. `fn timestamp() { return std.time.timestamp(); }`). Call the stdlib directly — aliases add indirection without value.
