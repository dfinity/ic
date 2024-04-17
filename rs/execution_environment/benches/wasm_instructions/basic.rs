//! Benchmarks for the basic WASM instructions.

use crate::helper::{benchmark_with_confirmation, benchmark_with_loop_confirmation};
use execution_environment_bench::{
    common::Benchmark,
    wat_builder::{dst_type, src_type},
};

pub fn benchmarks() -> Vec<Benchmark> {
    // List of benchmarks to run: benchmark id (name), WAT, expected number of instructions.
    let mut benchmarks = vec![];

    ////////////////////////////////////////////////////////////////////
    // Overhead Benchmark

    // The bench is an empty loop: `nop`
    // All we need to capture in this benchmark is the call and loop overhead.
    benchmarks.extend(benchmark_with_loop_confirmation("overhead", "(nop)"));

    ////////////////////////////////////////////////////////////////////
    // Numeric Instructions

    // Numeric Instructions: iunop `$x_{type} = {op}($x_{type})`
    for op in [
        "i32.clz",
        "i32.ctz",
        "i32.popcnt",
        "i64.clz",
        "i64.ctz",
        "i64.popcnt",
    ] {
        let ty = dst_type(op);
        let name = format!("iunop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: funop `$x_{type} = {op}($x_{type})`
    for op in [
        "f32.abs",
        "f32.neg",
        "f32.sqrt",
        "f32.ceil",
        "f32.floor",
        "f32.trunc",
        "f32.nearest",
        "f64.abs",
        "f64.neg",
        "f64.sqrt",
        "f64.ceil",
        "f64.floor",
        "f64.trunc",
        "f64.nearest",
    ] {
        let ty = dst_type(op);
        let name = format!("funop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: ibinop `$x_{type} = {op}($x_{type}, $y_{type})`
    for op in [
        "i32.add",
        "i32.sub",
        "i32.mul",
        "i32.div_s",
        "i32.div_u",
        "i32.rem_s",
        "i32.rem_u",
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
        "i64.div_s",
        "i64.div_u",
        "i64.rem_s",
        "i64.rem_u",
        "i64.and",
        "i64.or",
        "i64.xor",
        "i64.shl",
        "i64.shr_s",
        "i64.shr_u",
        "i64.rotl",
        "i64.rotr",
    ] {
        let ty = dst_type(op);
        let name = format!("ibinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: fbinop `$x_{type} = {op}($x_{type}, $y_{type})`
    for op in [
        "f32.add",
        "f32.sub",
        "f32.mul",
        "f32.div",
        "f32.min",
        "f32.max",
        "f32.copysign",
        "f64.add",
        "f64.sub",
        "f64.mul",
        "f64.div",
        "f64.min",
        "f64.max",
        "f64.copysign",
    ] {
        let ty = dst_type(op);
        let name = format!("fbinop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: itestop `$x_i32 = {op}($x_{type})`
    for op in ["i32.eqz", "i64.eqz"] {
        let ty = dst_type(op);
        let name = format!("itestop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: irelop `$x_i32 = {op}($x_{type}, $y_{type})`
    for op in [
        "i32.eq", "i32.ne", "i32.lt_s", "i32.lt_u", "i32.gt_s", "i32.gt_u", "i32.le_s", "i32.le_u",
        "i32.ge_s", "i32.ge_u", "i64.eq", "i64.ne", "i64.lt_s", "i64.lt_u", "i64.gt_s", "i64.gt_u",
        "i64.le_s", "i64.le_u", "i64.ge_s", "i64.ge_u",
    ] {
        let ty = dst_type(op);
        let name = format!("irelop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: frelop `$x_i32 = {op}($x_{type}, $y_{type})`
    for op in [
        "f32.eq", "f32.ne", "f32.lt", "f32.gt", "f32.le", "f32.ge", "f64.eq", "f64.ne", "f64.lt",
        "f64.gt", "f64.le", "f64.ge",
    ] {
        let ty = dst_type(op);
        let name = format!("frelop/{op}");
        let code = &format!("(global.set $x_i32 ({op} (local.get $x_{ty}) (local.get $y_{ty})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Numeric Instructions: cvtop `$x_{type} = {op}($x_{src_type})`
    for op in [
        "i32.extend8_s",
        "i32.extend16_s",
        "i32.trunc_f32_s",
        "i32.trunc_f32_u",
        "i32.trunc_f64_s",
        "i32.trunc_f64_u",
        "i32.trunc_sat_f32_s",
        "i32.trunc_sat_f32_u",
        "i32.trunc_sat_f64_s",
        "i32.trunc_sat_f64_u",
        "i64.extend8_s",
        "i64.extend16_s",
        "i64.trunc_f32_s",
        "i64.trunc_f32_u",
        "i64.trunc_f64_s",
        "i64.trunc_f64_u",
        "i64.trunc_sat_f32_s",
        "i64.trunc_sat_f32_u",
        "i64.trunc_sat_f64_s",
        "i64.trunc_sat_f64_u",
        "f32.convert_i32_s",
        "f32.convert_i32_u",
        "f32.convert_i64_s",
        "f32.convert_i64_u",
        "f64.convert_i32_s",
        "f64.convert_i32_u",
        "f64.convert_i64_s",
        "f64.convert_i64_u",
        "i64.extend32_s",
        "i32.wrap_i64",
        "i64.extend_i32_s",
        "i64.extend_i32_u",
        "f32.demote_f64",
        "f64.promote_f32",
        "i32.reinterpret_f32",
        "i64.reinterpret_f64",
        "f32.reinterpret_i32",
        "f64.reinterpret_i64",
    ] {
        let ty = dst_type(op);
        let src_type = src_type(op);
        let name = format!("cvtop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $x_{src_type})))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    ////////////////////////////////////////////////////////////////////
    // Reference Instructions

    benchmarks.extend(benchmark_with_confirmation(
        "refop/ref.func",
        "(drop (ref.func 0))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "refop/ref.is_null-ref.func",
        "(global.set $x_i32 (ref.is_null (ref.func 0)))",
    ));

    ////////////////////////////////////////////////////////////////////
    // Variable Instructions

    benchmarks.extend(benchmark_with_confirmation(
        "varop/global.get",
        "(global.set $x_i32 (global.get $y_i32))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "varop/global.set",
        "(global.set $x_i32 (global.get $y_i32 (global.set $y_i32 (local.get $x_i32))))",
    ));

    ////////////////////////////////////////////////////////////////////
    // Table Instructions

    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.get",
        "(drop (table.get $table (local.get $zero_i32)))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.set-ref.func",
        "(table.set $table (local.get $zero_i32) (ref.func 0))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.size",
        "(global.set $x_i32 (table.size))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.copy",
        "(table.copy (local.get $zero_i32) (local.get $zero_i32) (local.get $zero_i32))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.init",
        "(table.init 0 (local.get $zero_i32) (local.get $zero_i32) (local.get $zero_i32))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.grow-ref.func",
        "(global.set $x_i32 (table.grow $table (ref.func 0) (local.get $zero_i32)))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "tabop/table.fill-ref.func",
        "(table.fill $table (local.get $zero_i32) (ref.func 0) (local.get $zero_i32))",
    ));

    ////////////////////////////////////////////////////////////////////
    // Memory Instructions

    // Memory Instructions: Bulk Memory Operations
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.size",
        "(global.set $x_i32 (memory.size))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.grow",
        "(global.set $x_i32 (memory.grow (local.get $zero_i32)))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.fill",
        "(memory.fill (local.get $zero_i32) (local.get $zero_i32) (local.get $zero_i32))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "memop/memory.copy",
        "(memory.copy (local.get $zero_i32) (local.get $zero_i32) (local.get $zero_i32))",
    ));

    // Memory Instructions: load `$x_{type} = {op}($y_i32)`
    for op in [
        "i32.load",
        "i64.load",
        "f32.load",
        "f64.load",
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
    ] {
        let ty = dst_type(op);
        let name = format!("memop/{op}");
        let code = &format!("(global.set $x_{ty} ({op} (local.get $y_i32)))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    // Memory Instructions: store `{op}($zero_i32, $x_{type})`
    for op in [
        "i32.store",
        "i64.store",
        "f32.store",
        "f64.store",
        "i32.store8",
        "i32.store16",
        "i64.store8",
        "i64.store16",
        "i64.store32",
    ] {
        let ty = dst_type(op);
        let name = format!("memop/{op}");
        let code = &format!("({op} (local.get $zero_i32) (local.get $x_{ty}))");
        benchmarks.extend(benchmark_with_confirmation(&name, code));
    }

    ////////////////////////////////////////////////////////////////////
    // Control Instructions

    benchmarks.extend(benchmark_with_confirmation(
        "ctrlop/select",
        "(global.set $x_i32 (select (global.get $zero_i32) (global.get $x_i32) (global.get $y_i32)))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "ctrlop/call",
        "(global.set $x_i32 (call $empty))",
    ));
    benchmarks.extend(benchmark_with_confirmation(
        "ctrlop/call_indirect",
        "(global.set $x_i32 (call_indirect (type $result_i32) (i32.const 7)))",
    ));
    // The `tail_call` feature is available in `wasmtime` version `12.0.1`
    // benchmarks.extend(benchmark_with_confirmation(
    //     "ctrlop/return_call",
    //     "(global.set $x_i32 (call $empty_return_call))",
    // ));

    benchmarks
}
