// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[macro_use]
extern crate lazy_static;
extern crate libc;

use anyhow::{Context, Result};
use byteorder::{NativeEndian, ReadBytesExt};
use goblin::elf::{Elf, Sym};
use libc::pid_t;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{self, BufRead, Cursor, Read};
use std::mem;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str;

lazy_static! {
    #[derive(Debug)]
    pub static ref LD_SO_CACHE: Result<LdSoCache, CacheError> = LdSoCache::load("/etc/ld.so.cache");
}

#[derive(Debug)]
pub enum CacheError {
    IOError(io::Error),
    InvalidHeader,
}

impl From<io::Error> for CacheError {
    fn from(error: io::Error) -> CacheError {
        CacheError::IOError(error)
    }
}

#[derive(Debug, Default)]
pub struct CacheEntry {
    pub key: String,
    pub value: String,
    pub flags: i32,
}

#[derive(Debug, Default)]
pub struct LdSoCache(Vec<CacheEntry>);

const CACHE_HEADER: &str = "glibc-ld.so.cache1.1";

pub struct ElfSymbols<'a>(Elf<'a>);

pub fn find_sym(pid: pid_t, lib: &str, symbol: &str) -> Result<Option<Sym>> {
    let path = resolve_proc_maps_lib(pid, lib).context(format!("lib: {} not found", lib))?;
    let bytes = fs::read(path)?;
    let elf_symbols = ElfSymbols::parse(&bytes)?;
    let sym = elf_symbols.resolve(symbol);
    Ok(sym)
}

impl<'a> ElfSymbols<'a> {
    pub fn resolve(&self, sym_name: &str) -> Option<Sym> {
        self.resolve_dyn_syms(sym_name)
            .or_else(|| self.resolve_syms(sym_name))
    }

    pub fn parse(data: &'a [u8]) -> goblin::error::Result<ElfSymbols<'a>> {
        let elf = Elf::parse(&data)?;
        Ok(ElfSymbols(elf))
    }

    fn resolve_dyn_syms(&self, sym_name: &str) -> Option<Sym> {
        self.0.dynsyms.iter().find(|sym| {
            self.0
                .dynstrtab
                .get(sym.st_name)
                .and_then(|n| n.ok())
                .map(|n| n == sym_name)
                .unwrap_or(false)
        })
    }

    fn resolve_syms(&self, sym_name: &str) -> Option<Sym> {
        self.0.syms.iter().find(|sym| {
            self.0
                .strtab
                .get(sym.st_name)
                .and_then(|n| n.ok())
                .map(|n| n == sym_name)
                .unwrap_or(false)
        })
    }
}

impl LdSoCache {
    pub fn load(path: &str) -> Result<Self, CacheError> {
        let data = fs::read(path).map_err(CacheError::IOError)?;
        Self::parse(&data)
    }

    pub fn resolve(&self, lib: &str) -> Option<&str> {
        let lib = if !lib.contains(".so") {
            lib.to_string() + ".so"
        } else {
            lib.to_string()
        };
        self.0
            .iter()
            .find(|entry| entry.key.starts_with(&lib))
            .map(|entry| entry.value.as_str())
    }

    fn parse(data: &[u8]) -> Result<Self, CacheError> {
        let mut cursor = Cursor::new(data);
        let mut buf = [0u8; CACHE_HEADER.len()];
        cursor.read_exact(&mut buf)?;

        let header = str::from_utf8(&buf).or(Err(CacheError::InvalidHeader))?;
        if header != CACHE_HEADER {
            return Err(CacheError::InvalidHeader);
        }

        let num_entries = cursor.read_u32::<NativeEndian>()?;
        cursor.consume((5 * mem::size_of::<u32>()) + 4);
        let mut ld_cache = LdSoCache::default();
        for _ in 0..num_entries {
            let flags = cursor.read_i32::<NativeEndian>()?;
            let k_pos = cursor.read_u32::<NativeEndian>()?;
            let v_pos = cursor.read_u32::<NativeEndian>()?;
            cursor.consume(12);
            let key = unsafe {
                CStr::from_ptr(cursor.get_ref()[k_pos as usize..].as_ptr() as *const c_char)
            }
            .to_string_lossy()
            .into_owned();

            let value = unsafe {
                CStr::from_ptr(cursor.get_ref()[v_pos as usize..].as_ptr() as *const c_char)
            }
            .to_string_lossy()
            .into_owned();
            ld_cache.0.push(CacheEntry { key, value, flags })
        }
        Ok(ld_cache)
    }
}

pub fn resolve_proc_maps_lib(pid: pid_t, lib: &str) -> Option<String> {
    let libs = proc_map_libs(pid).ok()?;
    let ret = if lib.contains(".so") {
        libs.iter().find(|(k, _)| k.as_str().starts_with(lib))
    } else {
        let lib = lib.to_string();
        let lib1 = lib.clone() + ".so";
        let lib2 = lib + "-";
        libs.iter()
            .find(|(k, _)| k.starts_with(&lib1) || k.starts_with(&lib2))
    }
    .map(|(_, v)| v.clone());
    ret
}

fn proc_map_libs(pid: pid_t) -> io::Result<Vec<(String, String)>> {
    let maps_file = format!("/proc/{}/maps", pid);
    let mut file = File::open(maps_file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents
        .lines()
        .filter_map(|line| {
            let line = line.split_whitespace().last()?;
            if line.starts_with('/') {
                let path = PathBuf::from(line);
                let key = path.file_name().unwrap().to_string_lossy().into_owned();
                let value = path.to_string_lossy().into_owned();
                Some((key, value))
            } else {
                None
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use libc::pid_t;
    use std::process;

    #[test]
    fn find_libcache() {
        let ld_so_cache = (&*crate::LD_SO_CACHE).as_ref();
        assert!(ld_so_cache.unwrap().resolve("libc").is_some());
    }

    #[test]
    fn find_symbol_with_valid_name() {
        let pid = process::id() as pid_t;
        assert!(crate::find_sym(pid, "libc", "gethostbyname").is_ok());
    }

    #[test]
    fn find_symbol_with_invalid_symname() {
        let pid = process::id() as pid_t;
        assert!(crate::find_sym(pid, "libc", "hoge").is_ok());
    }

    #[test]
    fn find_symbol_with_invalid_libname() {
        let pid = process::id() as pid_t;
        assert!(crate::find_sym(pid, "libhoge", "gethoge").is_err());
    }

    #[test]
    fn resolve_proc_maps_lib_with_vaild_name() {
        let pid = process::id() as pid_t;
        assert_eq!(
            crate::resolve_proc_maps_lib(pid, "libc"),
            Some("/usr/lib/x86_64-linux-gnu/libc-2.33.so".to_string())
        );
    }

    #[test]
    fn resolve_proc_maps_lib_with_invalid_name() {
        let pid = process::id() as pid_t;
        assert_eq!(crate::resolve_proc_maps_lib(pid, "libhoge"), None);
    }
}
