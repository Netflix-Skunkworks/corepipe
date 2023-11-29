# corepipe

This is a project to perform a coredump of a running process, and output
the results to a unix pipe. On the other end of the pipe can be any process;
compress the file, send it to a script, store it in the cloud, all without
touching the local disk.

Alternatives:
- Linux provides a capability to output a coredump to pipe, but you have to
  terminate the process to do so.
- `gcore` (part of gdb) provides a script to capture a coredump to file, but
  it requires GDB to be installed, and it writes and seeks the local file as
  it writes.

## Project status

This was developed internally to support live-capture of some applications
to use with the hotspot serviceability agent and debugger. As we are
progressively moving to newer JDKs which support streaming hprof, we have
less of a need for this.  But - it might be useful for you. We have decided
to open source for anyone else to benefit.

We would love for someone to take this over! Open an issue if you are
interested.

## Building

This is a cargo project:

```shell
$ cargo build --release
```

## Usage

Capturing a coredump to file is simple:
```shell
$ sudo ./target/release/corepipe <pid> > core-file-name
```

While the capture is occurring, the target PID will be sent a SIGSTOP, and when
capture is complete a SIGCONT will be sent. This means your process will be
halted and any inflight requests will not be handled. So, please plan for this,
especially if you are outputing the results to a slow network location.

```shell
$ start_long_running_task &
[1] 8733

$ sudo ./target/release/corepipe 8733 > core.8733
dumping core for pid 8733 ..
halted, starting dump.
reading: /proc/8733/smaps
```

Now you can build more complex pipelines:
```shell
$ sudo ./target/release/corepipe 8733 | pzstd > core.8733.zstd
dumping core for pid 8733 ..
halted, starting dump.
reading: /proc/8733/smaps
```

## Tests

Tests have some requirements:
- GDB must be installed
- Integration tests need to be executed as `sudo`, since they will run corepipe.
- Hugepages must be enabled to allow the hugepage test to pass.

```shell
## run all of the ordinary integration tests
$ cargo test

## set up hugepages
$ sudo su
# echo 12 > /proc/sys/vm/nr_hugepages

## run integration tests that require sudo
$ sudo -E cargo test -- --include-ignored

## if we run the integration test, `cargo clean` might fail afterwards
$ sudo -E cargo clean
```

## Limitations and future work

This does not dump page contents that are swapped to disk. It could be made
to do so.

Testing and PRs welcome for other platforms.

### Adding an architecture

This has been built and tested on x86 linux. To extend this to other archs,
at least the following will be required:
- Most of the machine-specific code is in `elfmachine_x86_64.rs` or the
  equivalent. Start by taking a look here, as this defines the notes that
  will be created in the ELF file which represent the specific memory
  regions such as CPU registers for dumping.
- Create a copy of the file, name it appropriately, and reference it from
  main.rs.
- It will likely need to use the ptrace APIs to read register fields. If so
  implement these.
- Search for other locations for cfg `target_arch` flags to ensure, such
  as test cases and other overrides. You might need to provide a custom
  result.

## Contributing

PRs welcome. As per the project status note, this is not a priority project
though.

## Acknowledgments

Several acknowledgments:
- Header files that lay out ELF note struct contents are from the 
  [Google-Coredumper project](https://code.google.com/archive/p/google-coredumper/).
- gabriel AT urdhr POINT fr provided a wonderful article
  [Anatomy of a core file](https://www.gabriel.urdhr.fr/2015/05/29/core-file/)
- The proc/maps parser was heavily based on work by 
