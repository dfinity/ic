//! Benchmarks for the Wasm SIMD instructions.
//!
//! References:
//! * https://www.w3.org/TR/wasm-core-2/
//! * https://github.com/WebAssembly/simd/blob/main/proposals/simd/SIMD.md

use crate::helper::{benchmark_with_confirmation, first_or_all};
use execution_environment_bench::{common::Benchmark, wat_builder::dst_type};

const SET_X_V128: &str = "global.set $x_v128";
const SET_X_I32: &str = "global.set $x_i32";
const U8X16: &str = "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5";
const X_V128: &str = "(local.get $x_v128)";
const Y_V128: &str = "(local.get $y_v128)";
const Y_I32: &str = "(local.get $y_i32)";
const Z_V128: &str = "(local.get $z_v128)";
const ADDRESS_I32: &str = "(local.get $address_i32)";
const UNALIGNED_ADDRESS_I32: &str = "(local.get $one_i32)";

pub fn benchmarks() -> Vec<Benchmark> {
    // List of benchmarks to run.
    let mut benchmarks = vec![];

    ////////////////////////////////////////////////////////////////////
    // Vector Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#vector-instructions

    // Vector Constants: `$x_v128 = ({op} i64x2 u8 u8)`
    // The throughput for the following benchmarks is ~2.4 Gops/s
    for op in first_or_all(&["v128.const"]) {
        let name = format!("vconst/{op}");
        let code = &format!("({SET_X_V128} ({op} i64x2 7 7))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The following add operation is just an example to show that each
    // constant adds one memory load.
    // The throughput for the following benchmarks is ~2.5 Gops/s
    for op in first_or_all(&["v128.const"]) {
        // This snippet with locals compiles into:
        //   vpaddq xmm4, xmm6, xmm5 ;; the locals are in the registers
        //   vmovdqu xmmword ptr [rdi + 0x70], xmm4
        let name = format!("vconst/{op}_add_locals");
        let code = &format!("({SET_X_V128} (i64x2.add {Y_V128} {Z_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.4 Gops/s
    for op in first_or_all(&["v128.const"]) {
        // This snippet with constants compiles into:
        //   vmovdqu xmm4, xmmword ptr [rip + 0x183] ;; load the first constant
        //   vmovdqu xmm0, xmmword ptr [rip + 0x18b] ;; load the second constant
        //   vpaddq xmm4, xmm4, xmm0
        //   vmovdqu xmmword ptr [rdi + 0x70], xmm4
        let name = format!("vconst/{op}_add_constants");
        let code = &format!("({SET_X_V128} (i64x2.add ({op} i64x2 7 7) ({op} i64x2 1 1)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Bitwise Unary Operators (vvunop): `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.3 Gops/s
    for op in first_or_all(&["v128.not"]) {
        let name = format!("vvunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Bitwise Binary Operators (vvbinop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["v128.and", "v128.andnot", "v128.or", "v128.xor"]) {
        let name = format!("vvbinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Bitwise Ternary Operators (vvternop): `$x_v128 = ({op} $x_v128 $y_v128 $z_v128)`
    // The throughput for the following benchmarks is ~2.0 Gops/s
    for op in first_or_all(&["v128.bitselect"]) {
        let name = format!("vvternop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128} {Z_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Bitwise Test Operators (vvtestop): `$x_i32 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.0 Gops/s
    for op in first_or_all(&["v128.any_true"]) {
        let name = format!("vvtestop/{op}");
        let code = &format!("({SET_X_I32} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Shuffle: `$x_v128 = ({op} u8x16 $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~1.0 Gops/s
    for op in first_or_all(&["i8x16.shuffle"]) {
        let name = format!("vshuffle/{op}");
        let code = &format!("({SET_X_V128} ({op} {U8X16} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Swizzle: `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.1 Gops/s
    for op in first_or_all(&["i8x16.swizzle"]) {
        let name = format!("vswizzle/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Splat: `$x_v128 = ({op} $x_{ty})`
    // The throughput for the following benchmarks is ~2.5 Gops/s
    for op in first_or_all(&[
        "i8x16.splat",
        "i16x8.splat",
        "i32x4.splat",
        "i64x2.splat",
        "f32x4.splat",
        "f64x2.splat",
    ]) {
        let ty = dst_type(op);
        let name = format!("vsplat/{op}");
        let code = &format!("({SET_X_V128} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Extract Lane: `$x_{ty} = ({op} u8 $x_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&[
        "i32x4.extract_lane",
        "i64x2.extract_lane",
        "f32x4.extract_lane",
        "f64x2.extract_lane",
    ]) {
        let ty = dst_type(op);
        let name = format!("vextlane/{op}");
        let code = &format!("(global.set $x_{ty} ({op} 1 (local.get $x_v128)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.1 Gops/s
    for op in first_or_all(&[
        "i8x16.extract_lane_s",
        "i8x16.extract_lane_u",
        "i16x8.extract_lane_s",
        "i16x8.extract_lane_u",
    ]) {
        let ty = dst_type(op);
        let name = format!("vextlane/{op}");
        let code = &format!("(global.set $x_{ty} ({op} 1 (local.get $x_v128)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Replace Lane: `$x_v128 = ({op} u8 $x_v128 $y_{ty})`
    // The throughput for the following benchmarks is ~2.5 Gops/s
    for op in first_or_all(&[
        "i8x16.replace_lane",
        "i16x8.replace_lane",
        "i32x4.replace_lane",
        "i64x2.replace_lane",
        "f32x4.replace_lane",
        "f64x2.replace_lane",
    ]) {
        let ty = dst_type(op);
        let name = format!("vreplane/{op}");
        let code = &format!("({SET_X_V128} ({op} 1 {X_V128} (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Relational Operators (virelop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.5 Gops/s
    for op in first_or_all(&[
        "i8x16.eq",
        "i8x16.ne",
        "i8x16.lt_s",
        "i8x16.gt_s",
        "i8x16.le_s",
        "i8x16.le_u",
        "i8x16.ge_s",
        "i8x16.ge_u",
        "i16x8.eq",
        "i16x8.ne",
        "i16x8.lt_s",
        "i16x8.gt_s",
        "i16x8.le_s",
        "i16x8.le_u",
        "i16x8.ge_s",
        "i16x8.ge_u",
        "i32x4.eq",
        "i32x4.ne",
        "i32x4.lt_s",
        "i32x4.gt_s",
        "i32x4.le_s",
        "i32x4.le_u",
        "i32x4.ge_s",
        "i32x4.ge_u",
        "i64x2.eq",
        "i64x2.ne",
        "i64x2.lt_s",
        "i64x2.gt_s",
        "i64x2.le_s",
        "i64x2.ge_s",
    ]) {
        let name = format!("virelop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&[
        "i8x16.lt_u",
        "i8x16.gt_u",
        "i16x8.lt_u",
        "i16x8.gt_u",
        "i32x4.lt_u",
        "i32x4.gt_u",
    ]) {
        let name = format!("virelop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Floating-Point Relational Operators (vfrelop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&[
        "f32x4.eq", "f32x4.ne", "f32x4.lt", "f32x4.gt", "f32x4.le", "f32x4.ge", "f64x2.eq",
        "f64x2.ne", "f64x2.lt", "f64x2.gt", "f64x2.le", "f64x2.ge",
    ]) {
        let name = format!("vfrelop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Unary Operators (viunop): `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["i8x16.abs", "i16x8.abs", "i32x4.abs"]) {
        let name = format!("viunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["i64x2.abs"]) {
        let name = format!("viunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.4 Gops/s
    for op in first_or_all(&["i8x16.neg", "i16x8.neg", "i32x4.neg", "i64x2.neg"]) {
        let name = format!("viunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.8 Gops/s
    for op in first_or_all(&["i8x16.popcnt"]) {
        let name = format!("viunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Saturating integer Q-format rounding multiplication:
    //   `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~1.8 Gops/s
    for op in first_or_all(&["i16x8.q15mulr_sat_s"]) {
        let name = format!("vq15mulr/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Integer dot product: `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&["i32x4.dot_i16x8_s"]) {
        let name = format!("vdot/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Floating-Point Unary Operators (vfunop): `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&["f32x4.abs", "f32x4.neg", "f64x2.abs", "f64x2.neg"]) {
        let name = format!("vfunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.1 Gops/s
    for op in first_or_all(&[
        "f32x4.ceil",
        "f32x4.floor",
        "f32x4.trunc",
        "f32x4.nearest",
        "f64x2.ceil",
        "f64x2.floor",
        "f64x2.trunc",
        "f64x2.nearest",
    ]) {
        let name = format!("vfunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.5 Gops/s
    for op in first_or_all(&["f32x4.sqrt"]) {
        let name = format!("vfunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.2 Gops/s
    for op in first_or_all(&["f64x2.sqrt"]) {
        let name = format!("vfunop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Test Operators (vitestop): `$x_i32 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~1.6 Gops/s
    for op in first_or_all(&[
        "i8x16.all_true",
        "i16x8.all_true",
        "i32x4.all_true",
        "i64x2.all_true",
    ]) {
        let name = format!("vitestop/{op}");
        let code = &format!("({SET_X_I32} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Bitmask Extraction: `$x_i32 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.4 Gops/s
    for op in first_or_all(&[
        "i8x16.bitmask",
        "i16x8.bitmask",
        "i32x4.bitmask",
        "i64x2.bitmask",
    ]) {
        let name = format!("vbitmask/{op}");
        let code = &format!("({SET_X_I32} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer to Integer Narrowing: `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&[
        "i8x16.narrow_i16x8_s",
        "i8x16.narrow_i16x8_u",
        "i16x8.narrow_i32x4_s",
        "i16x8.narrow_i32x4_u",
    ]) {
        let name = format!("vnarrow/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer to Integer Extension: `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&[
        "i16x8.extend_low_i8x16_s",
        "i16x8.extend_low_i8x16_u",
        "i32x4.extend_low_i16x8_s",
        "i32x4.extend_low_i16x8_u",
        "i64x2.extend_low_i32x4_s",
        "i64x2.extend_low_i32x4_u",
    ]) {
        let name = format!("vextend/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.0 Gops/s
    for op in first_or_all(&[
        "i16x8.extend_high_i8x16_s",
        "i16x8.extend_high_i8x16_u",
        "i32x4.extend_high_i16x8_s",
        "i32x4.extend_high_i16x8_u",
        "i64x2.extend_high_i32x4_s",
        "i64x2.extend_high_i32x4_u",
    ]) {
        let name = format!("vextend/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Shift Operators (vishiftop): `$x_v128 = ({op} $x_v128 $y_i32)`
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&[
        "i16x8.shl",
        "i16x8.shr_s",
        "i16x8.shr_u",
        "i32x4.shl",
        "i32x4.shr_s",
        "i32x4.shr_u",
        "i64x2.shl",
        "i64x2.shr_u",
    ]) {
        let name = format!("vishiftop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.0 Gops/s
    for op in first_or_all(&["i8x16.shl", "i8x16.shr_s", "i8x16.shr_u", "i64x2.shr_s"]) {
        let name = format!("vishiftop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Binary Operators (vibinop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.5 Gops/s
    for op in first_or_all(&[
        "i8x16.add",
        "i8x16.sub",
        "i16x8.add",
        "i16x8.sub",
        "i32x4.add",
        "i32x4.sub",
        "i64x2.add",
        "i64x2.sub",
    ]) {
        let name = format!("vibinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Binary Min/Max Operators (viminmaxop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&[
        "i8x16.min_s",
        "i8x16.min_u",
        "i8x16.max_s",
        "i8x16.max_u",
        "i16x8.min_s",
        "i16x8.min_u",
        "i16x8.max_s",
        "i16x8.max_u",
        "i32x4.min_s",
        "i32x4.min_u",
        "i32x4.max_s",
        "i32x4.max_u",
    ]) {
        let name = format!("viminmaxop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Saturating Binary Operators (visatbinop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&[
        "i8x16.add_sat_s",
        "i8x16.add_sat_u",
        "i8x16.sub_sat_s",
        "i8x16.sub_sat_u",
        "i16x8.add_sat_s",
        "i16x8.add_sat_u",
        "i16x8.sub_sat_s",
        "i16x8.sub_sat_u",
    ]) {
        let name = format!("visatbinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer Multiplication: `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&["i16x8.mul"]) {
        let name = format!("vimul/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&["i32x4.mul"]) {
        let name = format!("vimul/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.7 Gops/s
    for op in first_or_all(&["i64x2.mul"]) {
        let name = format!("vimul/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Lane-wise Integer Rounding Average: `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["i8x16.avgr_u", "i16x8.avgr_u"]) {
        let name = format!("vavgr/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Extended Integer Multiplication: `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~1.8 Gops/s
    for op in first_or_all(&[
        "i16x8.extmul_low_i8x16_s",
        "i64x2.extmul_low_i32x4_s",
        "i64x2.extmul_high_i32x4_s",
        "i64x2.extmul_low_i32x4_u",
        "i64x2.extmul_high_i32x4_u",
    ]) {
        let name = format!("vextmul/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.4 Gops/s
    for op in first_or_all(&[
        "i16x8.extmul_high_i8x16_s",
        "i16x8.extmul_low_i8x16_u",
        "i16x8.extmul_high_i8x16_u",
        "i32x4.extmul_low_i16x8_s",
        "i32x4.extmul_high_i16x8_s",
        "i32x4.extmul_low_i16x8_u",
        "i32x4.extmul_high_i16x8_u",
    ]) {
        let name = format!("vextmul/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Extended Pairwise Integer Addition: `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["i16x8.extadd_pairwise_i8x16_s"]) {
        let name = format!("vextadd/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.4 Gops/s
    for op in first_or_all(&["i16x8.extadd_pairwise_i8x16_u"]) {
        let name = format!("vextadd/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.4 Gops/s
    for op in first_or_all(&["i32x4.extadd_pairwise_i16x8_s"]) {
        let name = format!("vextadd/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.8 Gops/s
    for op in first_or_all(&["i32x4.extadd_pairwise_i16x8_u"]) {
        let name = format!("vextadd/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Floating-Point Binary Operators (vfbinop): `$x_v128 = ({op} $x_v128 $y_v128)`
    // The throughput for the following benchmarks is ~1.2 Gops/s
    for op in first_or_all(&[
        "f32x4.add",
        "f32x4.sub",
        "f32x4.mul",
        "f64x2.add",
        "f64x2.sub",
        "f64x2.mul",
    ]) {
        let name = format!("vfbinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.3 Gops/s
    for op in first_or_all(&["f32x4.div", "f64x2.div"]) {
        let name = format!("vfbinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.6 Gops/s
    for op in first_or_all(&["f32x4.min", "f32x4.max", "f64x2.min", "f64x2.max"]) {
        let name = format!("vfbinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["f32x4.pmin", "f32x4.pmax", "f64x2.pmin", "f64x2.pmax"]) {
        let name = format!("vfbinop/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128} {Y_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Floating Point to Integer With Saturation Conversion: `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~1.3 Gops/s
    for op in first_or_all(&["i32x4.trunc_sat_f32x4_s", "i32x4.trunc_sat_f64x2_s_zero"]) {
        let name = format!("vtrunc/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.8 Gops/s
    for op in first_or_all(&["i32x4.trunc_sat_f32x4_u", "i32x4.trunc_sat_f64x2_u_zero"]) {
        let name = format!("vtrunc/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Integer to Floating Point Conversion: `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["f32x4.convert_i32x4_s", "f64x2.convert_low_i32x4_s"]) {
        let name = format!("vconvert/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.6 Gops/s
    for op in first_or_all(&["f32x4.convert_i32x4_u"]) {
        let name = format!("vconvert/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&["f64x2.convert_low_i32x4_u"]) {
        let name = format!("vconvert/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Double-Precision Floating Point to Single-Precision Conversion:
    //   `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["f32x4.demote_f64x2_zero"]) {
        let name = format!("vdemote/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Single-Precision Floating Point to Double-Precision Conversion:
    //   `$x_v128 = ({op} $x_v128)`
    // The throughput for the following benchmarks is ~2.7 Gops/s
    for op in first_or_all(&["f64x2.promote_low_f32x4"]) {
        let name = format!("vpromote/{op}");
        let code = &format!("({SET_X_V128} ({op} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    ////////////////////////////////////////////////////////////////////
    // Variable Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#variable-instructions

    // Vector Get Variable Instructions: `$x_v128 = ({op} x_v128)`
    // The throughput for the following benchmarks is ~2.7 Gops/s
    for op in first_or_all(&["local.get"]) {
        let name = format!("vvar/{op}");
        let code = &format!("({SET_X_V128} ({op} $x_v128))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.4 Gops/s
    for op in first_or_all(&["global.get"]) {
        let name = format!("vvar/{op}");
        let code = &format!("({SET_X_V128} ({op} $x_v128))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Set Variable Instructions: `({op} x_v128 $x_v128)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["local.set"]) {
        let name = format!("vvar/{op}");
        let code = &format!("({op} $x_v128 (global.get $x_v128))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.6 Gops/s
    for op in first_or_all(&["global.set"]) {
        let name = format!("vvar/{op}");
        let code = &format!("({op} $x_v128 {X_V128})");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Tee Variable Instructions: `$x_v128 = ({op} x_v128 $x_v128)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&["local.tee"]) {
        let name = format!("vvar/{op}");
        let code = &format!("({SET_X_V128} ({op} $x_v128 {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    ////////////////////////////////////////////////////////////////////
    // Memory Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#memory-instructions

    // Vector Load: `$x_v128 = ({op} $address_i32))`
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["v128.load"]) {
        let name = format!("vmem/{op}");
        let code = &format!("({SET_X_V128} ({op} {ADDRESS_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["v128.load"]) {
        let name = format!("vmem/{op}_unaligned");
        let code = &format!("({SET_X_V128} ({op} {UNALIGNED_ADDRESS_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Store: `({op} $address_i32 $x_v128)`
    // The throughput for the following benchmarks is ~2.1 Gops/s
    for op in first_or_all(&["v128.store"]) {
        let name = format!("vmem/{op}");
        let code = &format!("({op} {ADDRESS_I32} {X_V128})");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.1 Gops/s
    for op in first_or_all(&["v128.store"]) {
        let name = format!("vmem/{op}_unaligned");
        let code = &format!("({op} {UNALIGNED_ADDRESS_I32} {X_V128})");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Load and Extend: `$x_v128 = ({op} $address_i32))`
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&[
        "v128.load8x8_s",
        "v128.load8x8_u",
        "v128.load16x4_s",
        "v128.load16x4_u",
        "v128.load32x2_s",
        "v128.load32x2_u",
    ]) {
        let name = format!("vmem/{op}");
        let code = &format!("({SET_X_V128} ({op} {ADDRESS_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Load and Zero-Pad: `$x_v128 = ({op} $address_i32))`
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["v128.load32_zero", "v128.load64_zero"]) {
        let name = format!("vmem/{op}");
        let code = &format!("({SET_X_V128} ({op} {ADDRESS_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Load and Splat: `$x_v128 = ({op} $address_i32))`
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&[
        "v128.load8_splat",
        "v128.load16_splat",
        "v128.load32_splat",
        "v128.load64_splat",
    ]) {
        let name = format!("vmem/{op}");
        let code = &format!("({SET_X_V128} ({op} {ADDRESS_I32}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Load Lane: `$x_v128 = ({op} u8 $address_i32 $x_v128))`
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&["v128.load8_lane", "v128.load16_lane"]) {
        let name = format!("vmem/{op}");
        let code = &format!("({SET_X_V128} ({op} 1 {ADDRESS_I32} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["v128.load32_lane", "v128.load64_lane"]) {
        let name = format!("vmem/{op}");
        let code = &format!("({SET_X_V128} ({op} 1 {ADDRESS_I32} {X_V128}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Vector Store Lane: `({op} u8 $address_i32 $x_v128)`
    // The throughput for the following benchmarks is ~2.3 Gops/s
    for op in first_or_all(&[
        "v128.store8_lane",
        "v128.store16_lane",
        "v128.store32_lane",
        "v128.store64_lane",
    ]) {
        let name = format!("vmem/{op}");
        let code = &format!("({op} 1 {ADDRESS_I32} {X_V128})");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    benchmarks
}
