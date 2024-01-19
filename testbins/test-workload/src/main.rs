// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.
//! Integration test workloads
//!
//! Some workloads to be executed as part of the project integration tests.
//! They are built during `cargo test` via `testbin`

use clap::{Parser, Subcommand};
use mmap_rs::{MmapFlags, MmapOptions, PageSize};
use std::thread;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    LoopOnHeap {
        /// magic value
        #[arg(long)]
        magic: i32,
    },
    LoopOnStack {
        /// magic value
        #[arg(long)]
        magic: i32,
    },
    MultiplePageTest {
        /// magic value
        #[arg(long)]
        magic: String,
        #[arg(long)]
        nomagic: String,
    },
    MultipleThreadsTest {
        /// magic value
        #[arg(long)]
        magic: i32,
        #[arg(long)]
        threads: i32,
    },
}

fn main() {
    let args = Args::parse();

    match &args.command {
        Some(Commands::LoopOnHeap { magic }) => loop_on_heap(Box::new(*magic)),
        Some(Commands::LoopOnStack { magic }) => loop_on_stack(*magic),
        Some(Commands::MultiplePageTest { magic, nomagic }) => {
            multiple_page_test(magic.to_string(), nomagic.to_string())
        }
        Some(Commands::MultipleThreadsTest { magic, threads }) => {
            multiple_threads_test(*magic, *threads)
        }
        None => {}
    }
}

/// Loop forever, keeping a magic value on the stack for GDB to find it
#[inline(never)]
fn loop_on_stack(_magic: i32) {
    eprintln!("loop_on_stack with magic value: {}", _magic);
    loop {
        thread::yield_now();
    }
}

/// Loop forever, keeping a magic value on the heap for GDB to find it
#[inline(never)]
fn loop_on_heap(_magic: Box<i32>) {
    eprintln!("loop_on_heap with magic value: {}", _magic);
    loop {
        thread::yield_now();
    }
}

#[inline(never)]
fn multiple_page_test(_magic: String, _nomagic: String) {
    eprintln!(
        "large_page_test with magic value: {}, nomagic value: {}",
        _magic, _nomagic
    );
    eprintln!(
        "available page sizes: {:?}",
        MmapOptions::page_sizes().unwrap()
    );

    // page with nodump
    let mut no_dump = MmapOptions::new(2 * 1024 * 1024)
        .unwrap()
        .with_flags(MmapFlags::NO_CORE_DUMP)
        .map_mut()
        .unwrap();

    let nomagic_bytes = _nomagic.as_bytes();
    no_dump[..(nomagic_bytes.len())].copy_from_slice(nomagic_bytes);
    eprintln!("nomagic pointer: {:p}", no_dump.as_ptr());

    // 2MB page
    let mut hugemap = MmapOptions::new(2 * 1024 * 1024)
        .unwrap()
        .with_page_size(PageSize::_2M)
        .with_flags(MmapFlags::HUGE_PAGES)
        .with_flags(MmapFlags::POPULATE)
        .map_mut()
        .unwrap();

    let magic_bytes = _magic.as_bytes();
    hugemap[..(magic_bytes.len())].copy_from_slice(magic_bytes);
    eprintln!("magic pointer: {:p}", hugemap.as_ptr());

    loop {
        thread::yield_now();
    }
}

#[inline(never)]
fn multiple_threads_test(magic: i32, threads: i32) {
    eprintln!("multiple_threads_test with magic value: {} and thread count: {}", magic, threads);

    for t in 0..threads {
        eprintln!("spawning thread {}", t);
        thread::spawn(move || {
            loop_on_stack(magic);
        });
    }
    loop {}
}
