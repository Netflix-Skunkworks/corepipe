// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Netflix, Inc., jkoch@netflix.com.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// use bindings from wrapper.h; this embeds the ELF headers
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
