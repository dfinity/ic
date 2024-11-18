//! This module contains functions to convert between [`wasmparser`] types and
//! [`wasm_encoder`] types. In most cases the types are almost exactly the same
//! for the two crates, but they occasionally vary slightly in terms of
//! structure or ownership of the contained data.
//!
//! In some cases we'll also have internal types which are distinct from both
//! the [`wasmparser`] and [`wasm_encoder`] types, but in most cases the
//! internal type should use [`wasmparser`].

use crate::Error;
type Result<T> = std::result::Result<T, Error>;

/// Conversion from [`wasmparser`] to internal types.
pub(super) mod parser_to_internal {
    use super::*;

    pub(crate) fn const_expr(const_expr: wasmparser::ConstExpr) -> Result<wasmparser::Operator> {
        let mut ops = const_expr.get_operators_reader().into_iter();
        let first = ops.next();
        let end = ops.next();
        let rest = ops.next();
        let (Some(first), Some(Ok(wasmparser::Operator::End)), None) = (first, end, rest) else {
            return Err(Error::ConversionError(format!(
                "Invalid const expression: {:?}",
                const_expr
            )));
        };
        use wasmparser::Operator::*;
        let first = first?;
        // In the MVP Wasm spec, these are the only instructions allowed in const expressions:
        // https://webassembly.github.io/spec/core/valid/instructions.html#constant-expressions
        //
        // More instructions will be supported with the gc and extended const expressions proposals:
        // https://github.com/WebAssembly/gc/blob/main/proposals/gc/Post-MVP.md
        // https://github.com/WebAssembly/extended-const/blob/master/proposals/extended-const/Overview.md
        match first {
            I32Const { .. }
            | I64Const { .. }
            | F32Const { .. }
            | F64Const { .. }
            | V128Const { .. }
            | RefNull { .. }
            | RefFunc { .. }
            | GlobalGet { .. } => Ok(first),
            other => Err(Error::ConversionError(format!(
                "Invalid const expression operator: {:?}",
                other
            ))),
        }
    }

    fn data_kind(kind: wasmparser::DataKind) -> Result<crate::DataSegmentKind> {
        Ok(match kind {
            wasmparser::DataKind::Passive => crate::DataSegmentKind::Passive,
            wasmparser::DataKind::Active {
                memory_index,
                offset_expr,
            } => crate::DataSegmentKind::Active {
                memory_index,
                offset_expr: const_expr(offset_expr)?,
            },
        })
    }

    pub(crate) fn data_segment(data: wasmparser::Data) -> Result<crate::DataSegment> {
        Ok(crate::DataSegment {
            kind: data_kind(data.kind)?,
            data: data.data,
        })
    }

    pub(crate) fn element_kind(kind: wasmparser::ElementKind) -> Result<crate::ElementKind> {
        match kind {
            wasmparser::ElementKind::Passive => Ok(crate::ElementKind::Passive),
            wasmparser::ElementKind::Declared => Ok(crate::ElementKind::Declared),
            wasmparser::ElementKind::Active {
                table_index,
                offset_expr,
            } => Ok(crate::ElementKind::Active {
                table_index,
                offset_expr: const_expr(offset_expr)?,
            }),
        }
    }

    pub(crate) fn element_items(items: wasmparser::ElementItems) -> Result<crate::ElementItems> {
        match items {
            wasmparser::ElementItems::Functions(reader) => {
                let functions = reader
                    .into_iter()
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(crate::ElementItems::Functions(functions))
            }
            wasmparser::ElementItems::Expressions(ref_type, reader) => {
                let exprs = reader
                    .into_iter()
                    .map(|expr| const_expr(expr?))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(crate::ElementItems::ConstExprs {
                    ty: ref_type,
                    exprs,
                })
            }
        }
    }

    pub(crate) fn global(global: wasmparser::Global) -> Result<crate::Global> {
        Ok(crate::Global {
            ty: global.ty,
            init_expr: const_expr(global.init_expr)?,
        })
    }
}

/// Conversion from internal to [`wasm_encoder`] types.
pub(super) mod internal_to_encoder {
    use super::*;

    pub(crate) fn block_type(ty: wasmparser::BlockType) -> Result<wasm_encoder::BlockType> {
        Ok(match ty {
            wasmparser::BlockType::Empty => wasm_encoder::BlockType::Empty,
            wasmparser::BlockType::Type(ty) => {
                wasm_encoder::BlockType::Result(wasm_encoder::ValType::try_from(ty).map_err(
                    |_err| Error::ConversionError(format!("Failed to convert type: {:?}", ty)),
                )?)
            }
            wasmparser::BlockType::FuncType(f) => wasm_encoder::BlockType::FunctionType(f),
        })
    }

    fn memarg(memarg: &wasmparser::MemArg) -> wasm_encoder::MemArg {
        wasm_encoder::MemArg {
            offset: memarg.offset,
            align: memarg.align as u32,
            memory_index: memarg.memory,
        }
    }

    fn ordering(arg: wasmparser::Ordering) -> wasm_encoder::Ordering {
        match arg {
            wasmparser::Ordering::SeqCst => wasm_encoder::Ordering::SeqCst,
            wasmparser::Ordering::AcqRel => wasm_encoder::Ordering::AcqRel,
        }
    }

    pub(crate) fn const_expr(expr: &wasmparser::Operator) -> Result<wasm_encoder::ConstExpr> {
        use wasm_encoder::Encode;

        let mut bytes = vec![];
        op(expr.clone())?.encode(&mut bytes);
        Ok(wasm_encoder::ConstExpr::raw(bytes))
    }

    pub(crate) fn catch(catch: &wasmparser::Catch) -> wasm_encoder::Catch {
        match catch {
            wasmparser::Catch::One { tag, label } => wasm_encoder::Catch::One {
                tag: *tag,
                label: *label,
            },
            wasmparser::Catch::OneRef { tag, label } => wasm_encoder::Catch::OneRef {
                tag: *tag,
                label: *label,
            },
            wasmparser::Catch::All { label } => wasm_encoder::Catch::All { label: *label },
            wasmparser::Catch::AllRef { label } => wasm_encoder::Catch::AllRef { label: *label },
        }
    }

    /// Convert [`wasmparser::Operator`] to [`wasm_encoder::Instruction`]. A
    /// simplified example of the conversion done in wasm-mutate
    /// [here](https://github.com/bytecodealliance/wasm-tools/blob/a8c4fddd239b0cb8978c76e6dfd856d5bd29b860/crates/wasm-mutate/src/mutators/translate.rs#L279).
    #[allow(unused_variables)]
    pub(crate) fn op(op: wasmparser::Operator<'_>) -> Result<wasm_encoder::Instruction<'static>> {
        use wasm_encoder::Instruction as I;

        macro_rules! convert {
            ($( @$proposal:ident $op:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident)*) => {
                match op {
                    $(
                        wasmparser::Operator::$op $({ $($arg),* })? => {
                            $(
                                $(let $arg = convert!(map $arg $arg);)*
                            )?
                            convert!(build $op $($($arg)*)?)
                        }
                    )*
                }
            };

            // Mapping the arguments from wasmparser to wasm-encoder types.

            // Arguments which need to be explicitly converted or ignored.
            (map $arg:ident blockty) => (block_type($arg)?);
            (map $arg:ident try_table) => ((
                block_type($arg.ty)?,
                std::borrow::Cow::from(
                    $arg
                        .catches
                        .iter()
                        .map(|c| catch(c))
                        .collect::<std::vec::Vec<_>>()
                )
            ));
            (map $arg:ident targets) => ((
                $arg
                    .targets()
                    .collect::<std::result::Result<Vec<_>, wasmparser::BinaryReaderError>>()?
                    .into(),
                $arg.default(),
            ));
            (map $arg:ident ty) => (
                wasm_encoder::ValType::try_from($arg)
                    .map_err(|_err| Error::ConversionError(format!("Failed to convert type: {:?}", $arg)))?
            );
            (map $arg:ident hty) => (
                wasm_encoder::HeapType::try_from($arg)
                    .map_err(|_err| Error::ConversionError(format!("Failed to convert type: {:?}", $arg)))?
            );
            (map $arg:ident from_ref_type) => (
                wasm_encoder::RefType::try_from($arg)
                    .map_err(|_err| Error::ConversionError(format!("Failed to convert type: {:?}", $arg)))?
            );
            (map $arg:ident to_ref_type) => (
                wasm_encoder::RefType::try_from($arg)
                    .map_err(|_err| Error::ConversionError(format!("Failed to convert type: {:?}", $arg)))?
            );

            (map $arg:ident memarg) => (memarg(&$arg));
            (map $arg:ident ordering) => (ordering($arg));
            (map $arg:ident table_byte) => (());
            (map $arg:ident mem_byte) => (());
            (map $arg:ident flags) => (());


            // All other arguments are kept the same.
            (map $arg:ident $_:ident) => ($arg);

            // Construct the wasm-encoder Instruction from the arguments of a
            // wasmparser instruction.  There are a few special cases for where the
            // structure of a wasmparser instruction differs from that of
            // wasm-encoder.

            // Single operators are directly converted.
            (build $op:ident) => (Ok(I::$op));

            // Special cases with a single argument.
            (build BrTable $arg:ident) => (Ok(I::BrTable($arg.0, $arg.1)));
            (build TryTable $arg:ident) => (Ok(I::TryTable($arg.0, $arg.1)));
            (build F32Const $arg:ident) => (Ok(I::F32Const(f32::from_bits($arg.bits()))));
            (build F64Const $arg:ident) => (Ok(I::F64Const(f64::from_bits($arg.bits()))));
            (build V128Const $arg:ident) => (Ok(I::V128Const($arg.i128())));

            // Standard case with a single argument.
            (build $op:ident $arg:ident) => (Ok(I::$op($arg)));

            // Special case of multiple arguments.
            (build CallIndirect $ty:ident $table:ident $_:ident) => (Ok(I::CallIndirect {
                type_index: $ty,
                table_index: $table,
            }));
            (build ReturnCallIndirect $ty:ident $table:ident) => (Ok(I::ReturnCallIndirect {
                type_index: $ty,
                table_index: $table,
            }));
            (build MemoryGrow $mem:ident $_:ident) => (Ok(I::MemoryGrow($mem)));
            (build MemorySize $mem:ident $_:ident) => (Ok(I::MemorySize($mem)));

            // Standard case of multiple arguments.
            (build $op:ident $($arg:ident)*) => (Ok(I::$op { $($arg),* }));
        }

        wasmparser::for_each_operator!(convert)
    }
}
