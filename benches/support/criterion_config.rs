#![allow(dead_code)]

//! Criterion configuration helpers for the tiered benchmark suite.
//!
//! Tier 1 and Tier 2 are short, repeatable microbenchmarks.
//! Tier 3 and Tier 4 are longer system and integration benchmarks where
//! the server or storage fixture is part of the steady-state cost.

use criterion::Criterion;
use std::time::Duration;

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    let millis = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_ms);

    Duration::from_millis(millis)
}

fn env_usize(name: &str, default_value: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default_value)
}

fn env_f64(name: &str, default_value: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default_value)
}

pub fn criterion_config_for_tier1() -> Criterion {
    Criterion::default()
        .warm_up_time(env_duration_ms("BENCH_TIER1_WARMUP_MS", 400))
        .measurement_time(env_duration_ms("BENCH_TIER1_MEASUREMENT_MS", 1200))
        .sample_size(env_usize("BENCH_TIER1_SAMPLE_SIZE", 25))
        .noise_threshold(env_f64("BENCH_TIER1_NOISE_THRESHOLD", 0.04))
        .without_plots()
}

pub fn criterion_config_for_tier2() -> Criterion {
    Criterion::default()
        .warm_up_time(env_duration_ms("BENCH_TIER2_WARMUP_MS", 500))
        .measurement_time(env_duration_ms("BENCH_TIER2_MEASUREMENT_MS", 1500))
        .sample_size(env_usize("BENCH_TIER2_SAMPLE_SIZE", 20))
        .noise_threshold(env_f64("BENCH_TIER2_NOISE_THRESHOLD", 0.04))
        .without_plots()
}

pub fn criterion_config_for_tier3() -> Criterion {
    Criterion::default()
        .warm_up_time(env_duration_ms("BENCH_TIER3_WARMUP_MS", 750))
        .measurement_time(env_duration_ms("BENCH_TIER3_MEASUREMENT_MS", 2000))
        .sample_size(env_usize("BENCH_TIER3_SAMPLE_SIZE", 15))
        .noise_threshold(env_f64("BENCH_TIER3_NOISE_THRESHOLD", 0.05))
        .without_plots()
}

pub fn criterion_config_for_tier4() -> Criterion {
    Criterion::default()
        .warm_up_time(env_duration_ms("BENCH_TIER4_WARMUP_MS", 1000))
        .measurement_time(env_duration_ms("BENCH_TIER4_MEASUREMENT_MS", 2500))
        .sample_size(env_usize("BENCH_TIER4_SAMPLE_SIZE", 12))
        .noise_threshold(env_f64("BENCH_TIER4_NOISE_THRESHOLD", 0.06))
        .without_plots()
}
