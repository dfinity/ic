//! Benchmarks for the basic Wasm instructions.
//!
//! References:
//! * https://www.w3.org/TR/wasm-core-2/

use crate::helper::{benchmark_with_confirmation, benchmark_with_loop_confirmation, first_or_all};
use execution_environment_bench::{
    common::Benchmark,
    wat_builder::{dst_type, src_type},
};

pub fn benchmarks() -> Vec<Benchmark> {
    // List of benchmarks to run.
    let mut benchmarks = vec![];

    ////////////////////////////////////////////////////////////////////
    // Overhead Benchmark

    // The bench is an empty loop: `nop`
    // All we need to capture in this benchmark is the call and loop overhead.
    benchmarks.extend(benchmark_with_loop_confirmation("overhead", "(nop)"));

    ////////////////////////////////////////////////////////////////////
    // Numeric Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#numeric-instructions

    // Constants: `$x_{type} = ({op} u8)`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&["i32.const", "i64.const"]) {
        let ty = dst_type(op);
        let name = format!("const/{op}");
        let code = &format!("(global.set $x_{ty} ({op} 7))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.2 Gops/s
    for op in first_or_all(&["f32.const"]) {
        let ty = dst_type(op);
        let name = format!("const/{op}");
        let code = &format!("(global.set $x_{ty} ({op} 7))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&["f64.const"]) {
        let ty = dst_type(op);
        let name = format!("const/{op}");
        let code = &format!("(global.set $x_{ty} ({op} 7))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Integer Unary Operators (iunop): `$x_{type} = ({op} $x_{type})`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&[
        "i32.clz",
        "i32.ctz",
        "i32.popcnt",
        "i64.clz",
        "i64.ctz",
        "i64.popcnt",
    ]) {
        let ty = dst_type(op);
        let name = format!("iunop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Floating-Point Unary Operators (funop): `$x_{type} = ({op} $x_{type})`
    // The throughput for the following benchmarks is ~1.9 Gops/s
    for op in first_or_all(&["f32.abs", "f32.neg"]) {
        let ty = dst_type(op);
        let name = format!("funop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.3 Gops/s
    for op in first_or_all(&["f64.abs", "f64.neg"]) {
        let ty = dst_type(op);
        let name = format!("funop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.07 Gops/s
    for op in first_or_all(&[
        "f32.ceil",
        "f32.floor",
        "f32.trunc",
        "f32.nearest",
        "f64.ceil",
        "f64.floor",
        "f64.trunc",
        "f64.nearest",
    ]) {
        let ty = dst_type(op);
        let name = format!("funop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.05 Gops/s
    for op in first_or_all(&["f32.sqrt", "f64.sqrt"]) {
        let ty = dst_type(op);
        let name = format!("funop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Integer Binary Operators (ibinop): `$x_{type} = ({op} $x_{type} $y_{type})`
    // The throughput for the following benchmarks is ~2.8 Gops/s
    for op in first_or_all(&[
        "i32.add",
        "i32.sub",
        "i32.mul",
        "i32.and",
        "i32.or",
        "i32.xor",
        "i32.shl",
        "i32.shr_s",
        "i32.shr_u",
        "i32.rotl",
        "i32.rotr",
        "i64.add",
        "i64.sub",
        "i64.mul",
        "i64.and",
        "i64.or",
        "i64.xor",
        "i64.shl",
        "i64.shr_s",
        "i64.shr_u",
        "i64.rotl",
        "i64.rotr",
    ]) {
        let ty = dst_type(op);
        let name = format!("ibinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.1 Gops/s
    for op in first_or_all(&[
        "i32.div_s",
        "i32.div_u",
        "i32.rem_s",
        "i32.rem_u",
        "i64.div_s",
        "i64.div_u",
        "i64.rem_s",
        "i64.rem_u",
    ]) {
        let ty = dst_type(op);
        let name = format!("ibinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Floating-Point Binary Operators (fbinop): `$x_{type} = ({op} $x_{type} $y_{type})`
    // The throughput for the following benchmarks is ~0.07 Gops/s
    for op in first_or_all(&[
        "f32.add", "f32.sub", "f32.mul", "f64.add", "f64.sub", "f64.mul",
    ]) {
        let ty = dst_type(op);
        let name = format!("fbinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.06 Gops/s
    for op in first_or_all(&["f32.div", "f64.div"]) {
        let ty = dst_type(op);
        let name = format!("fbinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.04 Gops/s
    for op in first_or_all(&["f32.min", "f32.max", "f64.min", "f64.max"]) {
        let ty = dst_type(op);
        let name = format!("fbinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.5 Gops/s
    for op in first_or_all(&["f32.copysign"]) {
        let ty = dst_type(op);
        let name = format!("fbinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~1.0 Gops/s
    for op in first_or_all(&["f64.copysign"]) {
        let ty = dst_type(op);
        let name = format!("fbinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Integer Test Operators (itestop): `$x_i32 = ({op} $x_{type})`
    // The throughput for the following benchmarks is ~2.5 Gops/s
    for op in first_or_all(&["i32.eqz", "i64.eqz"]) {
        let ty = dst_type(op);
        let name = format!("itestop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Integer Relational Operators (irelop): `$x_i32 = ({op} $x_{type} $y_{type})`
    // The throughput for the following benchmarks is ~2.6 Gops/s
    for op in first_or_all(&[
        "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u", "i32.le_s", "i32.le_u",
        "i32.ge_s", "i32.ge_u", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u", "i64.gt_s", "i64.gt_u",
        "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u",
    ]) {
        let ty = dst_type(op);
        let name = format!("irelop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Floating-Point Relational Operators (frelop): `$x_i32 = ({op} $x_{type} $y_{type})`
    // The throughput for the following benchmarks is ~1.4 Gops/s
    for op in first_or_all(&["f32.eq", "f32.ne", "f64.eq", "f64.ne"]) {
        let ty = dst_type(op);
        let name = format!("frelop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.1 Gops/s
    for op in first_or_all(&[
        "f32.lt", "f32.gt", "f32.le", "f32.ge", "f64.lt", "f64.gt", "f64.le", "f64.ge",
    ]) {
        let ty = dst_type(op);
        let name = format!("frelop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Conversions (cvtop): `$x_{type} = ({op} $x_{src_type})`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&[
        "i32.extend8_s",
        "i32.extend16_s",
        "i64.extend8_s",
        "i64.extend16_s",
        "f32.convert_i32_s",
        "f32.convert_i64_s",
        "f64.convert_i32_s",
        "f64.convert_i64_s",
        "i64.extend32_s",
        "i32.wrap_i64",
        "i64.extend_i32_s",
        "i64.extend_i32_u",
        "f32.demote_f64",
        "f64.promote_f32",
        "f32.reinterpret_i32",
        "f64.reinterpret_i64",
    ]) {
        let ty = dst_type(op);
        let src_type = src_type(op);
        let name = format!("cvtop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{src_type})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~2.2 Gops/s
    for op in first_or_all(&[
        "f32.convert_i32_u",
        "f64.convert_i32_u",
        "i32.reinterpret_f32",
        "i64.reinterpret_f64",
    ]) {
        let ty = dst_type(op);
        let src_type = src_type(op);
        let name = format!("cvtop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{src_type})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.1 Gops/s
    for op in first_or_all(&[
        "i32.trunc_f32_s",
        "i32.trunc_f32_u",
        "i32.trunc_f64_s",
        "i32.trunc_f64_u",
        "i64.trunc_f32_s",
        "i64.trunc_f32_u",
        "i64.trunc_f64_s",
        "i64.trunc_f64_u",
        "i64.trunc_sat_f32_s",
        "i64.trunc_sat_f64_s",
    ]) {
        let ty = dst_type(op);
        let src_type = src_type(op);
        let name = format!("cvtop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{src_type})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.06 Gops/s
    for op in first_or_all(&[
        "i32.trunc_sat_f32_u",
        "i32.trunc_sat_f64_u",
        "i64.trunc_sat_f32_u",
        "i64.trunc_sat_f64_u",
    ]) {
        let ty = dst_type(op);
        let src_type = src_type(op);
        let name = format!("cvtop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{src_type})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }
    // The throughput for the following benchmarks is ~0.2 Gops/s
    for op in first_or_all(&[
        "i32.trunc_sat_f32_s",
        "i32.trunc_sat_f64_s",
        "f32.convert_i64_u",
        "f64.convert_i64_u",
    ]) {
        let ty = dst_type(op);
        let src_type = src_type(op);
        let name = format!("cvtop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{src_type})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    ////////////////////////////////////////////////////////////////////
    // Reference Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#reference-instructions

    // The throughput for the following benchmarks is ~0.02 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "refop/ref.func",
        "(drop (ref.func 0))",
    ));
    // The throughput for the following benchmarks is ~0.02 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "refop/ref.is_null-ref.func",
        "(global.set $x_i32 (ref.is_null (ref.func 0)))",
    ));

    ////////////////////////////////////////////////////////////////////
    // Variable Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#variable-instructions

    // Get Variable Instructions: `$x_i32 = ({op} x_i32)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["local.get", "global.get"]) {
        let name = format!("varop/{op}");
        let code = &format!("(global.set $x_i32 ({op} $x_i32))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Set Variable Instructions: `({op} x_i32 $x_i32)`
    // The throughput for the following benchmarks is ~5.5 Gops/s, as it
    // just stores a register into the memory.
    // The benchmark is commented out, as otherwise it becomes a baseline and
    // skews all the results.
    // for op in first_or_all(&["local.set"]) {
    //     let name = format!("varop/{op}");
    //     let code = &format!("({op} $x_i32 (global.get $x_i32))");
    //     benchmarks.extend(benchmark_with_confirmation(&name, code));
    // }
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["global.set"]) {
        let name = format!("varop/{op}");
        let code = &format!("({op} $x_i32 (local.get $x_i32))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Tee Variable Instructions: `$x_i32 = ({op} x_i32 $x_i32)`
    // The throughput for the following benchmarks is ~2.9 Gops/s
    for op in first_or_all(&["local.tee"]) {
        let name = format!("varop/{op}");
        let code = &format!("(global.set $x_i32 ({op} $x_i32 (local.get $x_i32)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    ////////////////////////////////////////////////////////////////////
    // Table Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#table-instructions

    // The throughput for the following benchmarks is ~0.7 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.get",
        "(drop (table.get $table (local.get $zero_i32)))",
    ));
    // The throughput for the following benchmarks is ~2.8 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.size",
        "(global.set $x_i32 (table.size))",
    ));

    ////////////////////////////////////////////////////////////////////
    // Memory Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#memory-instructions

    // Load: `$x_{type} = ({op} $address_i32))`
    // The throughput for the following benchmarks is ~2.0 Gops/s
    for op in first_or_all(&["i32.load", "i64.load", "f32.load", "f64.load"]) {
        let ty = dst_type(op);
        let name = format!("memop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $address_i32)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Store: `({op} $address_i32 $x_{type})`
    // The throughput for the following benchmarks is ~2.2 Gops/s
    for op in first_or_all(&["i32.store", "i64.store", "f32.store", "f64.store"]) {
        let ty = dst_type(op);
        let name = format!("memop/{op}");
        let code = &format!("({op} (local.get $address_i32) (local.get $x_{ty}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Extending Load: `$x_{type} = ({op} $address_i32))`
    // The throughput for the following benchmarks is ~2.1 Gops/s
    for op in first_or_all(&[
        "i32.load8_s",
        "i32.load8_u",
        "i32.load16_s",
        "i32.load16_u",
        "i64.load8_s",
        "i64.load8_u",
        "i64.load16_s",
        "i64.load16_u",
        "i64.load32_s",
        "i64.load32_u",
    ]) {
        let ty = dst_type(op);
        let name = format!("memop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $address_i32)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Wrapping Store: `({op} $address_i32 $x_{type})`
    // The throughput for the following benchmarks is ~2.2 Gops/s
    for op in first_or_all(&[
        "i32.store8",
        "i32.store16",
        "i64.store8",
        "i64.store16",
        "i64.store32",
    ]) {
        let ty = dst_type(op);
        let name = format!("memop/{op}");
        let code = &format!("({op} (local.get $address_i32) (local.get $x_{ty}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Memory Instructions: Bulk Memory Operations
    // The throughput for the following benchmarks is ~0.2 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.size",
        "(global.set $x_i32 (memory.size))",
    ));
    // The throughput for the following benchmarks is ~0.006 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.grow",
        "(global.set $x_i32 (memory.grow (local.get $zero_i32)))",
    ));
    // The throughput for the following benchmarks is ~0.03 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.fill",
        "(memory.fill (local.get $zero_i32) (local.get $zero_i32) (local.get $zero_i32))",
    ));
    // The throughput for the following benchmarks is ~0.02 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.copy",
        "(memory.copy (local.get $zero_i32) (local.get $zero_i32) (local.get $zero_i32))",
    ));

    ////////////////////////////////////////////////////////////////////
    // Control Instructions
    // See: https://www.w3.org/TR/wasm-core-2/#control-instructions

    // The throughput for the following benchmarks is ~1.4 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "ctrlop/select",
        "(global.set $x_i32 (select (global.get $zero_i32) (global.get $x_i32) (global.get $y_i32)))",
    ));
    // The throughput for the following benchmarks is ~0.2 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "ctrlop/call",
        "(global.set $x_i32 (call $empty))",
    ));
    // The throughput for the following benchmarks is ~0.1 Gops/s
    benchmarks.extend(benchmark_with_confirmation(
        "ctrlop/call_indirect",
        "(global.set $x_i32 (call_indirect (type $result_i32) (i32.const 7)))",
    ));

    benchmarks
}
