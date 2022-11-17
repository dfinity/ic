//! This module contains functions to convert between [`wasmparser`] types and
//! [`wasm_encoder`] types. In most cases the types are almost exactly the same
//! for the two crates, but they occasionally vary slightly in terms of
//! structure or ownership of the contained data.

use wasm_encoder::{BlockType, DataSegment, DataSegmentMode, EntityType, Instruction};
use wasmparser::{
    BinaryReaderError, ConstExpr, ExternalKind, GlobalType, MemArg, MemoryType, Operator,
    TableType, TagKind, TagType, TypeRef, ValType,
};

use super::ElementItems;

pub(super) fn block_type(ty: &wasmparser::BlockType) -> BlockType {
    match ty {
        wasmparser::BlockType::Empty => BlockType::Empty,
        wasmparser::BlockType::Type(ty) => BlockType::Result(val_type(ty)),
        wasmparser::BlockType::FuncType(f) => BlockType::FunctionType(*f),
    }
}

pub(super) fn val_type(v: &ValType) -> wasm_encoder::ValType {
    match v {
        ValType::I32 => wasm_encoder::ValType::I32,
        ValType::I64 => wasm_encoder::ValType::I64,
        ValType::F32 => wasm_encoder::ValType::F32,
        ValType::F64 => wasm_encoder::ValType::F64,
        ValType::V128 => wasm_encoder::ValType::V128,
        ValType::FuncRef => wasm_encoder::ValType::FuncRef,
        ValType::ExternRef => wasm_encoder::ValType::ExternRef,
    }
}

pub(super) fn table_type(t: TableType) -> wasm_encoder::TableType {
    wasm_encoder::TableType {
        element_type: val_type(&t.element_type),
        minimum: t.initial,
        maximum: t.maximum,
    }
}

pub(super) fn memory_type(m: MemoryType) -> wasm_encoder::MemoryType {
    wasm_encoder::MemoryType {
        memory64: m.memory64,
        shared: m.shared,
        minimum: m.initial,
        maximum: m.maximum,
    }
}

pub(super) fn global_type(g: GlobalType) -> wasm_encoder::GlobalType {
    wasm_encoder::GlobalType {
        val_type: val_type(&g.content_type),
        mutable: g.mutable,
    }
}

fn tag_kind(k: TagKind) -> wasm_encoder::TagKind {
    match k {
        TagKind::Exception => wasm_encoder::TagKind::Exception,
    }
}

fn tag_type(t: TagType) -> wasm_encoder::TagType {
    wasm_encoder::TagType {
        kind: tag_kind(t.kind),
        func_type_idx: t.func_type_idx,
    }
}

pub(super) fn import_type(ty: TypeRef) -> EntityType {
    match ty {
        TypeRef::Func(f) => EntityType::Function(f),
        TypeRef::Table(t) => EntityType::Table(table_type(t)),
        TypeRef::Memory(m) => EntityType::Memory(memory_type(m)),
        TypeRef::Global(g) => EntityType::Global(global_type(g)),
        TypeRef::Tag(t) => EntityType::Tag(tag_type(t)),
    }
}

pub(super) fn op_to_const_expr(
    operator: &Operator,
) -> Result<wasm_encoder::ConstExpr, BinaryReaderError> {
    use wasm_encoder::Encode;
    let mut bytes: Vec<u8> = Vec::new();
    op(operator)?.encode(&mut bytes);
    Ok(wasm_encoder::ConstExpr::raw(bytes))
}

pub(super) fn const_expr(expr: ConstExpr) -> Result<wasm_encoder::ConstExpr, BinaryReaderError> {
    let mut reader = expr.get_binary_reader();
    let size = reader.bytes_remaining();
    // The const expression should end in a `End` instruction, but the encoder
    // doesn't expect that instruction to be part of its input so we drop it.
    let bytes = reader.read_bytes(size - 1)?.to_vec();
    match reader.read_operator().unwrap() {
        Operator::End => {}
        _ => {
            panic!("const expr didn't end with `End` instruction");
        }
    }
    Ok(wasm_encoder::ConstExpr::raw(bytes))
}

pub(super) struct DerefBytesIterator<'a> {
    data: &'a [u8],
    current: usize,
}

impl<'a> DerefBytesIterator<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, current: 0 }
    }
}

impl<'a> Iterator for DerefBytesIterator<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.data.len() {
            let next = self.data[self.current];
            self.current += 1;
            Some(next)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.data.len() - self.current;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for DerefBytesIterator<'a> {}

pub(super) fn data_segment<'a>(
    segment: super::DataSegment<'a>,
    temp_const_expr: &'a mut wasm_encoder::ConstExpr,
) -> Result<DataSegment<'a, DerefBytesIterator<'a>>, BinaryReaderError> {
    let mode = match segment.kind {
        super::DataSegmentKind::Passive => DataSegmentMode::Passive,
        super::DataSegmentKind::Active {
            memory_index,
            offset_expr,
        } => {
            *temp_const_expr = op_to_const_expr(&offset_expr)?;
            DataSegmentMode::Active {
                memory_index,
                offset: temp_const_expr,
            }
        }
    };

    Ok(DataSegment {
        mode,
        data: DerefBytesIterator::new(segment.data),
    })
}

pub(super) fn export_kind(export_kind: ExternalKind) -> wasm_encoder::ExportKind {
    match export_kind {
        ExternalKind::Func => wasm_encoder::ExportKind::Func,
        ExternalKind::Table => wasm_encoder::ExportKind::Table,
        ExternalKind::Memory => wasm_encoder::ExportKind::Memory,
        ExternalKind::Global => wasm_encoder::ExportKind::Global,
        ExternalKind::Tag => wasm_encoder::ExportKind::Tag,
    }
}

fn memarg(memarg: &MemArg) -> wasm_encoder::MemArg {
    wasm_encoder::MemArg {
        offset: memarg.offset,
        align: memarg.align as u32,
        memory_index: memarg.memory,
    }
}

pub(super) fn element_items(element_items: &ElementItems) -> wasm_encoder::Elements<'_> {
    match element_items {
        ElementItems::Functions(funcs) => wasm_encoder::Elements::Functions(funcs),
        ElementItems::ConstExprs(exprs) => wasm_encoder::Elements::Expressions(exprs),
    }
}

/// Convert [`wasmparser::Operator`] to [`wasm_encoder::Instruction`]. A
/// simplified example of the conversion done in wasm-mutate
/// [here](https://github.com/bytecodealliance/wasm-tools/blob/a8c4fddd239b0cb8978c76e6dfd856d5bd29b860/crates/wasm-mutate/src/mutators/translate.rs#L279).
#[allow(unused_variables)]
pub(super) fn op(op: &Operator<'_>) -> Result<Instruction<'static>, BinaryReaderError> {
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
        (map $arg:ident blockty) => (block_type($arg));
        (map $arg:ident targets) => ((
            $arg
                .targets()
                .collect::<Result<Vec<_>, wasmparser::BinaryReaderError>>()?
                .into(),
            $arg.default(),
        ));
        (map $arg:ident ty) => (val_type($arg));
        (map $arg:ident memarg) => (memarg($arg));
        (map $arg:ident table_byte) => (());
        (map $arg:ident mem_byte) => (());
        (map $arg:ident flags) => (());

        // All other arguments are just dereferenced.
        (map $arg:ident $_:ident) => (*$arg);

        // Construct the wasm-encoder Instruction from the arguments of a
        // wasmparser instruction.  There are a few special cases for where the
        // structure of a wasmparser instruction differs from that of
        // wasm-encoder.

        // Single operators are directly converted.
        (build $op:ident) => (Ok(I::$op));

        // Special cases with a single argument.
        (build BrTable $arg:ident) => (Ok(I::BrTable($arg.0, $arg.1)));
        (build F32Const $arg:ident) => (Ok(I::F32Const(f32::from_bits($arg.bits()))));
        (build F64Const $arg:ident) => (Ok(I::F64Const(f64::from_bits($arg.bits()))));
        (build V128Const $arg:ident) => (Ok(I::V128Const($arg.i128())));

        // Standard case with a single argument.
        (build $op:ident $arg:ident) => (Ok(I::$op($arg)));

        // Special case of multiple arguments.
        (build CallIndirect $ty:ident $table:ident $_:ident) => (Ok(I::CallIndirect {
            ty: $ty,
            table: $table,
        }));
        (build ReturnCallIndirect $ty:ident $table:ident) => (Ok(I::ReturnCallIndirect {
            ty: $ty,
            table: $table,
        }));
        (build MemoryGrow $mem:ident $_:ident) => (Ok(I::MemoryGrow($mem)));
        (build MemorySize $mem:ident $_:ident) => (Ok(I::MemorySize($mem)));

        // Standard case of multiple arguments.
        (build $op:ident $($arg:ident)*) => (Ok(I::$op { $($arg),* }));
    }

    wasmparser::for_each_operator!(convert)
}
