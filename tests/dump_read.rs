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
fn test_can_read_stack() -> Result<(), io::Error> {
    let test_bin_path =
        build_test_binary("test-workload", "testbins").expect("error building test-workload");

    let mut rng = rand::thread_rng();
    let magic: u32 = rng.gen_range(10001..99999);

    let mut test_bin_subproc = std::process::Command::new(&test_bin_path)
        .arg("loop-on-stack")
        .arg("--magic")
        .arg(magic.to_string())
        .spawn()
        .expect("error running test binary");

    thread::sleep(Duration::from_millis(100));

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
        .arg("bt")
        .arg("-ex")
        .arg("quit")
        .output()
        .expect("failed to execute gdb");

    eprintln!("gdb stdout == ");
    io::stdout().write_all(&gdb_result.stdout)?;

    let gdb_stdout = std::str::from_utf8(&gdb_result.stdout).unwrap();
    let count_lines_on_stack = gdb_stdout
        .lines()
        .filter(|l| l.contains("test_workload::"))
        .count();
    assert_eq!(2, count_lines_on_stack);

    let count_lines_with_magic = gdb_stdout
        .lines()
        .filter(|l| l.contains("test_workload::loop_on_stack"))
        .filter(|l| l.contains(format!("_magic={}", magic.to_string()).as_str()))
        .count();

    assert_eq!(1, count_lines_with_magic);

    Ok(())
}

#[test]
#[ignore]
fn test_can_read_heap() -> Result<(), io::Error> {
    let test_bin_path =
        build_test_binary("test-workload", "testbins").expect("error building test-workload");

    let mut rng = rand::thread_rng();
    let magic: u32 = rng.gen_range(10001..99999);

    let mut test_bin_subproc = std::process::Command::new(&test_bin_path)
        .arg("loop-on-heap")
        .arg("--magic")
        .arg(magic.to_string())
        .spawn()
        .expect("error running test binary");

    thread::sleep(Duration::from_millis(100));

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
        .arg("frame 1")
        .arg("-ex")
        .arg("info args")
        .arg("-ex")
        .arg("x/_magic")
        .arg("-ex")
        .arg("quit")
        .output()
        .expect("failed to execute gdb");

    eprintln!("gdb stdout == ");
    io::stdout().write_all(&gdb_result.stdout)?;

    let gdb_stdout = std::str::from_utf8(&gdb_result.stdout).unwrap();
    assert!(gdb_stdout
        .lines()
        .any(|l| l.contains("test_workload::loop_on_heap")));

    let count_lines_with_magic = gdb_stdout
        .lines()
        .filter(|l| l.starts_with("0x"))
        .filter(|l| l.contains(&magic.to_string()))
        .count();

    assert_eq!(1, count_lines_with_magic);

    Ok(())
}
