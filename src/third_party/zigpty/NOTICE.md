Vendored from `pithings/zigpty` at commit `54392f8fe9c9028f0f6388513a55323d9da21f2c`.

Included files:
- `lib.zig`
- `pty_linux.zig`
- `pty_darwin.zig`
- `termios.zig`

Repository:
- https://github.com/pithings/zigpty

License:
- MIT, per upstream repository metadata and README as checked on May 4, 2026.

## Local modifications

- `pty_linux.zig`: added a local `rawErrno` helper and used it in place of
  `std.posix.errno` at 10 call sites that decode the return value of a raw
  `std.os.linux.*` syscall. The libc implementation of `std.posix.errno` tests
  `rc == -1`, but `std.os.linux.*` returns `usize` and Zig cannot coerce the
  comptime literal `-1` into `usize`, so that test is constantly false and every
  raw syscall failure was reported as `.SUCCESS`. A failing `faccessat`, for
  example, was therefore reported as "file is executable". These changes are
  local to this repository and are not present upstream.
