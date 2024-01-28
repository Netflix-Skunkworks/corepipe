// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
use std::{
    io::{self, Write},
    thread,
    time::Duration,
};

use assert_cmd::Command;
use rand::Rng;
use tempfile::NamedTempFile;
use test_binary::build_test_binary;

#[test]
#[ignore]
#[cfg(target_arch = "x86_64")]
fn test_can_read_stack_on_multiple_threads() -> Result<(), io::Error> {
    let test_bin_path =
        build_test_binary("test-workload", "testbins").expect("error building test-workload");

    let mut rng = rand::thread_rng();
    let magic: u32 = rng.gen_range(10001..99999);
    let threads: i32 = 6;

    let mut test_bin_subproc = std::process::Command::new(&test_bin_path)
        .arg("multiple-threads-test")
        .arg("--magic")
        .arg(magic.to_string())
        .arg("--threads")
        .arg(threads.to_string())
        .spawn()
        .expect("error running test binary");

    thread::sleep(Duration::from_millis(300));

    let output = Command::cargo_bin("corepipe")
        .expect("could not find corepipe")
        .arg("--pid")
        .arg(test_bin_subproc.id().to_string())
        .output()
        .expect("failed to execute corepipe");

    test_bin_subproc.kill()?;

    let mut tmpfile: NamedTempFile =
        NamedTempFile::new().expect("could not write coredump to temp file");
    tmpfile.write_all(&output.stdout)?;
    let tmpfile_name = tmpfile.path().as_os_str();

    let gdb_result = Command::new("gdb")
        .arg(test_bin_path)
        .arg(tmpfile_name)
        .arg("--batch")
        .arg("-ex")
        .arg("thread apply all bt")
        .arg("-ex")
        .arg("quit")
        .output()
        .expect("failed to execute gdb");

    eprintln!("gdb stdout == ");
    io::stdout().write_all(&gdb_result.stdout)?;
    eprintln!("gdb stderr == ");
    io::stdout().write_all(&gdb_result.stderr)?;

    let gdb_stdout = std::str::from_utf8(&gdb_result.stdout).unwrap();

    let count_lines_with_magic = gdb_stdout
        .lines()
        .filter(|l| l.contains("test_workload::loop_on_stack"))
        .filter(|l| l.contains(format!("_magic={}", magic.to_string()).as_str()))
        .count();

    assert_eq!(threads as usize, count_lines_with_magic);

    Ok(())
}
