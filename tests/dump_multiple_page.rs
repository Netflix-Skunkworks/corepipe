// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
use std::{
    io::{self, Read, Write},
    process::Stdio,
    thread,
    time::Duration,
};

use assert_cmd::Command;
use ntest::timeout;
use tempfile::NamedTempFile;
use test_binary::build_test_binary;

#[test]
#[ignore]
#[timeout(10000)]
#[cfg(target_arch = "x86_64")]
fn test_can_read_large_page() -> Result<(), io::Error> {
    let test_bin_path =
        build_test_binary("test-workload", "testbins").expect("error building test-workload");

    let mut test_bin_subproc = std::process::Command::new(&test_bin_path)
        .arg("multiple-page-test")
        .arg("--magic")
        .arg("abcdefghijkl")
        .arg("--nomagic")
        .arg("mnopqrstuvwxyz")
        .stderr(Stdio::piped())
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

    eprintln!("test stderr== ");
    let mut test_stderr = String::new();
    test_bin_subproc
        .stderr
        .as_mut()
        .take()
        .unwrap()
        .read_to_string(&mut test_stderr)?;
    io::stdout().write_all(test_stderr.as_bytes())?;

    let mut stderr_lines = test_stderr.lines();
    stderr_lines.next(); // test header
    stderr_lines.next(); // page sizes
    stderr_lines.next(); // nomagic line

    let mut magic_line = stderr_lines.next().unwrap().split_whitespace();
    magic_line.next(); // magic
    magic_line.next(); // pointer:
    let magic_ptr = magic_line.next().unwrap(); // 0x1234

    let mut tmpfile: NamedTempFile =
        NamedTempFile::new().expect("could not write coredump to temp file");
    tmpfile.write_all(&output.stdout)?;
    let tmpfile_name = tmpfile.path().as_os_str();

    let gdb_result_magic = Command::new("gdb")
        .arg(&test_bin_path)
        .arg(tmpfile_name)
        .arg("--batch")
        .arg("-ex")
        .arg(format!("x/1sb {}", magic_ptr))
        .arg("-ex")
        .arg("quit")
        .output()
        .expect("failed to execute gdb");

    eprintln!("gdb stdout == ");
    io::stdout().write_all(&gdb_result_magic.stdout)?;

    let gdb_magic_stdout = std::str::from_utf8(&gdb_result_magic.stdout).unwrap();
    assert!(gdb_magic_stdout.lines().any(|l| l.contains("abcdefghijkl")));

    Ok(())
}

#[test]
#[ignore]
#[timeout(10000)]
#[cfg(target_arch = "x86_64")]
fn test_cannot_read_dont_dump_page() -> Result<(), io::Error> {
    let test_bin_path =
        build_test_binary("test-workload", "testbins").expect("error building test-workload");

    let mut test_bin_subproc = std::process::Command::new(&test_bin_path)
        .arg("multiple-page-test")
        .arg("--magic")
        .arg("abcdefghijkl")
        .arg("--nomagic")
        .arg("mnopqrstuvwxyz")
        .stderr(Stdio::piped())
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

    eprintln!("test stderr== ");
    let mut test_stderr = String::new();
    test_bin_subproc
        .stderr
        .as_mut()
        .take()
        .unwrap()
        .read_to_string(&mut test_stderr)?;
    io::stdout().write_all(test_stderr.as_bytes())?;

    let mut stderr_lines = test_stderr.lines();
    stderr_lines.next(); // test header
    stderr_lines.next(); // page sizes
    let mut nomagic_line = stderr_lines.next().unwrap().split_whitespace();
    nomagic_line.next(); // nomagic
    nomagic_line.next(); // pointer:
    let nomagic_ptr = nomagic_line.next().unwrap(); // 0x1234

    let mut tmpfile: NamedTempFile =
        NamedTempFile::new().expect("could not write coredump to temp file");
    tmpfile.write_all(&output.stdout)?;
    let tmpfile_name = tmpfile.path().as_os_str();

    let gdb_result_nomagic = Command::new("gdb")
        .arg(&test_bin_path)
        .arg(tmpfile_name)
        .arg("--batch")
        .arg("-ex")
        .arg(format!("x/1sb {}", nomagic_ptr))
        .arg("-ex")
        .arg("quit")
        .output()
        .expect("failed to execute gdb");

    eprintln!("gdb stdout == ");
    io::stdout().write_all(&gdb_result_nomagic.stdout)?;

    // we are looking for NO result for mapping at the start of a page:

    let gdb_nomagic_stdout = std::str::from_utf8(&gdb_result_nomagic.stdout).unwrap();
    assert!(gdb_nomagic_stdout
        .lines()
        .any(|l| l.contains("Cannot access memory at address")));

    Ok(())
}
