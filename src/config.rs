//! Runtime configuration.
//!
//! Sources, in increasing priority:
//!   1. Built-in defaults — see [`AgentConfig::default`].
//!   2. Environment variables (`WAZABI_*`).
//!   3. CLI flags (`--spool-dir`, …).
//!
//! No external dependency: we parse env + argv by hand. That keeps the
//! supply-chain footprint of an EDR agent minimal — fewer crates, fewer
//! review surface, no TOML/JSON parser to audit.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

/// Resolved configuration for the running agent.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub spool_dir: PathBuf,
    pub max_bytes_per_file: u64,
    pub max_age: Duration,
    pub max_total_bytes: u64,
    pub channel_capacity: usize,
    pub zstd_level: i32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            spool_dir: PathBuf::from("spool"),
            max_bytes_per_file: 1 * 1024 * 1024,
            max_age: Duration::from_secs(10),
            max_total_bytes: 256 * 1024 * 1024,
            channel_capacity: 1024,
            zstd_level: 3,
        }
    }
}

impl AgentConfig {
    /// Build the effective config: defaults overridden by env vars,
    /// then by CLI args. Returns `Err` only on outright bad input
    /// (`--spool-dir` with no value, unknown flag, …).
    pub fn from_env_and_args() -> Result<Self, String> {
        let mut cfg = Self::default();
        cfg.apply_env();
        cfg.apply_args(env::args().skip(1))?;
        Ok(cfg)
    }

    /// Pick up overrides from `WAZABI_*` env vars. Silently ignores
    /// malformed values (logs a warning to stderr) — we'd rather start
    /// with defaults than refuse to launch an EDR over a typo.
    fn apply_env(&mut self) {
        if let Ok(v) = env::var("WAZABI_SPOOL_DIR") {
            self.spool_dir = PathBuf::from(v);
        }
        if let Some(v) = parse_env_u64("WAZABI_MAX_BYTES_PER_FILE") {
            self.max_bytes_per_file = v;
        }
        if let Some(v) = parse_env_u64("WAZABI_MAX_AGE_SECS") {
            self.max_age = Duration::from_secs(v);
        }
        if let Some(v) = parse_env_u64("WAZABI_MAX_TOTAL_BYTES") {
            self.max_total_bytes = v;
        }
        if let Some(v) = parse_env_u64("WAZABI_CHANNEL_CAPACITY") {
            self.channel_capacity = v as usize;
        }
        if let Some(v) = parse_env_i32("WAZABI_ZSTD_LEVEL") {
            self.zstd_level = v;
        }
    }

    /// Parse the few CLI flags we care about. `--help` is handled by
    /// printing usage and exiting; other unknown flags are an error so
    /// typos can't silently sit on the command line.
    fn apply_args<I: Iterator<Item = String>>(&mut self, mut args: I) -> Result<(), String> {
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--spool-dir" => {
                    let v = args
                        .next()
                        .ok_or_else(|| "--spool-dir requires a value".to_string())?;
                    self.spool_dir = PathBuf::from(v);
                }
                "--max-bytes-per-file" => {
                    self.max_bytes_per_file = parse_arg_u64(&mut args, "--max-bytes-per-file")?;
                }
                "--max-age-secs" => {
                    self.max_age =
                        Duration::from_secs(parse_arg_u64(&mut args, "--max-age-secs")?);
                }
                "--max-total-bytes" => {
                    self.max_total_bytes = parse_arg_u64(&mut args, "--max-total-bytes")?;
                }
                "--channel-capacity" => {
                    self.channel_capacity =
                        parse_arg_u64(&mut args, "--channel-capacity")? as usize;
                }
                "--zstd-level" => {
                    let raw = args
                        .next()
                        .ok_or_else(|| "--zstd-level requires a value".to_string())?;
                    self.zstd_level = raw
                        .parse()
                        .map_err(|_| format!("invalid --zstd-level: {raw}"))?;
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("unknown flag: {other} (try --help)"));
                }
            }
        }
        Ok(())
    }
}

fn parse_env_u64(name: &str) -> Option<u64> {
    let raw = env::var(name).ok()?;
    match raw.parse::<u64>() {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!("[agent] ignoring {name}={raw:?} — not a u64");
            None
        }
    }
}

fn parse_env_i32(name: &str) -> Option<i32> {
    let raw = env::var(name).ok()?;
    match raw.parse::<i32>() {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!("[agent] ignoring {name}={raw:?} — not an i32");
            None
        }
    }
}

fn parse_arg_u64<I: Iterator<Item = String>>(args: &mut I, flag: &str) -> Result<u64, String> {
    let raw = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    raw.parse()
        .map_err(|_| format!("invalid {flag}: {raw}"))
}

fn print_usage() {
    eprintln!(
        "WazabiEDR agent — connects to \\\\.\\WazabiEDR and spools events.\n\
         \n\
         Usage: WazabiEDR_Agent [FLAGS]\n\
         \n\
         Flags (each also takes a WAZABI_* env var of the same shape):\n\
           --spool-dir <PATH>              spool directory (default: ./spool)\n\
           --max-bytes-per-file <BYTES>    rotate active file at this size\n\
           --max-age-secs <SECS>           rotate active file at this age\n\
           --max-total-bytes <BYTES>       evict oldest batches above this cap\n\
           --channel-capacity <N>          pump→writer queue size\n\
           --zstd-level <1..22>            sealed-batch compression level\n\
           -h, --help                      print this help and exit"
    );
}
