//! This module contains functions to convert between [`wasmparser`] types and
//! [`wasm_encoder`] types. In most cases the types are almost exactly the same
//! for the two crates, but they occasionally vary slightly in terms of
//! structure or ownership of the contained data.
//!
//! In some cases we'll also have internal types which are distinct from both
//! the [`wasmparser`] and [`wasm_encoder`] types, but in most cases the
//! internal type should use [`wasmparser`].

/// Conversion from [`wasmparser`] to internal types.
pub(super) mod parser_to_internal {
    pub(crate) fn const_expr(
        const_expr: wasmparser::ConstExpr,
    ) -> Result<Vec<wasmparser::Operator>, wasmparser::BinaryReaderError> {
        const_expr
            .get_operators_reader()
            .into_iter()
            .collect::<Result<_, _>>()
    }

    fn data_kind(kind: wasmparser::DataKind) -> Result<crate::DataSegmentKind, crate::Error> {
        Ok(match kind {
            wasmparser::DataKind::Passive => crate::DataSegmentKind::Passive,
            wasmparser::DataKind::Active {
                memory_index,
                offset_expr,
            } => {
                let ops: Vec<_> = offset_expr
                    .get_operators_reader()
                    .into_iter()
                    .collect::<Result<_, _>>()?;
                match ops.as_slice() {
                    [_, wasmparser::Operator::End] => crate::DataSegmentKind::Active {
                        memory_index,
                        offset_expr: ops[0].clone(),
                    },
                    _ => return Err(crate::Error::InvalidConstExpr),
                }
            }
        })
    }

    pub(crate) fn data_segment(data: wasmparser::Data) -> Result<crate::DataSegment, crate::Error> {
        Ok(crate::DataSegment {
            kind: data_kind(data.kind)?,
            data: data.data,
        })
    }

    pub(crate) fn element_kind(
        kind: wasmparser::ElementKind,
    ) -> Result<crate::ElementKind, wasmparser::BinaryReaderError> {
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

    pub(crate) fn element_items(
        items: wasmparser::ElementItems,
    ) -> Result<crate::ElementItems, wasmparser::BinaryReaderError> {
        match items {
            wasmparser::ElementItems::Functions(reader) => {
                let functions = reader.into_iter().collect::<Result<Vec<_>, _>>()?;
                Ok(crate::ElementItems::Functions(functions))
            }
            wasmparser::ElementItems::Expressions(ref_type, reader) => {
                let exprs = reader
                    .into_iter()
                    .map(|expr| const_expr(expr?))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(crate::ElementItems::ConstExprs {
                    ty: ref_type,
                    exprs,
                })
            }
        }
    }

    pub(crate) fn global(
        global: wasmparser::Global,
    ) -> Result<crate::Global, wasmparser::BinaryReaderError> {
        Ok(crate::Global {
            ty: global.ty,
            init_expr: const_expr(global.init_expr)?,
        })
    }
}

/// Conversion from internal to [`wasm_encoder`] types.
pub(super) mod internal_to_encoder {
    pub(crate) fn block_type(ty: &wasmparser::BlockType) -> wasm_encoder::BlockType {
        match ty {
            wasmparser::BlockType::Empty => wasm_encoder::BlockType::Empty,
            wasmparser::BlockType::Type(ty) => wasm_encoder::BlockType::Result(val_type(ty)),
            wasmparser::BlockType::FuncType(f) => wasm_encoder::BlockType::FunctionType(*f),
        }
    }

    pub(crate) fn val_type(v: &wasmparser::ValType) -> wasm_encoder::ValType {
        match v {
            wasmparser::ValType::I32 => wasm_encoder::ValType::I32,
            wasmparser::ValType::I64 => wasm_encoder::ValType::I64,
            wasmparser::ValType::F32 => wasm_encoder::ValType::F32,
            wasmparser::ValType::F64 => wasm_encoder::ValType::F64,
            wasmparser::ValType::V128 => wasm_encoder::ValType::V128,
            wasmparser::ValType::Ref(r) => wasm_encoder::ValType::Ref(ref_type(r)),
        }
    }

    fn ref_type(v: &wasmparser::RefType) -> wasm_encoder::RefType {
        wasm_encoder::RefType {
            nullable: v.is_nullable(),
            heap_type: heap_type(&v.heap_type()),
        }
    }

    fn heap_type(v: &wasmparser::HeapType) -> wasm_encoder::HeapType {
        match v {
            wasmparser::HeapType::Indexed(i) => wasm_encoder::HeapType::Indexed(*i),
            wasmparser::HeapType::Func => wasm_encoder::HeapType::Func,
            wasmparser::HeapType::Extern => wasm_encoder::HeapType::Extern,
            wasmparser::HeapType::Any => wasm_encoder::HeapType::Any,
            wasmparser::HeapType::None => wasm_encoder::HeapType::None,
            wasmparser::HeapType::NoExtern => wasm_encoder::HeapType::NoExtern,
            wasmparser::HeapType::NoFunc => wasm_encoder::HeapType::NoFunc,
            wasmparser::HeapType::Eq => wasm_encoder::HeapType::Eq,
            wasmparser::HeapType::Struct => wasm_encoder::HeapType::Struct,
            wasmparser::HeapType::Array => wasm_encoder::HeapType::Array,
            wasmparser::HeapType::I31 => wasm_encoder::HeapType::I31,
        }
    }

    fn structural_type(v: &wasmparser::StructuralType) -> wasm_encoder::StructuralType {
        fn field_type(f: &wasmparser::FieldType) -> wasm_encoder::FieldType {
            let element_type = match &f.element_type {
                wasmparser::StorageType::I8 => wasm_encoder::StorageType::I8,
                wasmparser::StorageType::I16 => wasm_encoder::StorageType::I16,
                wasmparser::StorageType::Val(v) => wasm_encoder::StorageType::Val(val_type(v)),
            };
            wasm_encoder::FieldType {
                element_type,
                mutable: f.mutable,
            }
        }

        match v {
            wasmparser::StructuralType::Func(f) => {
                wasm_encoder::StructuralType::Func(wasm_encoder::FuncType::new(
                    f.params().iter().map(val_type),
                    f.results().iter().map(val_type),
                ))
            }
            wasmparser::StructuralType::Array(wasmparser::ArrayType(f)) => {
                wasm_encoder::StructuralType::Array(wasm_encoder::ArrayType(field_type(f)))
            }
            wasmparser::StructuralType::Struct(wasmparser::StructType { fields }) => {
                wasm_encoder::StructuralType::Struct(wasm_encoder::StructType {
                    fields: fields
                        .iter()
                        .map(field_type)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                })
            }
        }
    }

    pub(crate) fn subtype(v: &wasmparser::SubType) -> wasm_encoder::SubType {
        wasm_encoder::SubType {
            is_final: v.is_final,
            supertype_idx: v.supertype_idx,
            structural_type: structural_type(&v.structural_type),
        }
    }

    pub(crate) fn table_type(t: wasmparser::TableType) -> wasm_encoder::TableType {
        wasm_encoder::TableType {
            element_type: ref_type(&t.element_type),
            minimum: t.initial,
            maximum: t.maximum,
        }
    }

    pub(crate) fn memory_type(m: wasmparser::MemoryType) -> wasm_encoder::MemoryType {
        wasm_encoder::MemoryType {
            memory64: m.memory64,
            shared: m.shared,
            minimum: m.initial,
            maximum: m.maximum,
        }
    }

    pub(crate) fn global_type(g: wasmparser::GlobalType) -> wasm_encoder::GlobalType {
        wasm_encoder::GlobalType {
            val_type: val_type(&g.content_type),
            mutable: g.mutable,
        }
    }

    fn tag_kind(k: wasmparser::TagKind) -> wasm_encoder::TagKind {
        match k {
            wasmparser::TagKind::Exception => wasm_encoder::TagKind::Exception,
        }
    }

    fn tag_type(t: wasmparser::TagType) -> wasm_encoder::TagType {
        wasm_encoder::TagType {
            kind: tag_kind(t.kind),
            func_type_idx: t.func_type_idx,
        }
    }

    pub(crate) fn import_type(ty: wasmparser::TypeRef) -> wasm_encoder::EntityType {
        match ty {
            wasmparser::TypeRef::Func(f) => wasm_encoder::EntityType::Function(f),
            wasmparser::TypeRef::Table(t) => wasm_encoder::EntityType::Table(table_type(t)),
            wasmparser::TypeRef::Memory(m) => wasm_encoder::EntityType::Memory(memory_type(m)),
            wasmparser::TypeRef::Global(g) => wasm_encoder::EntityType::Global(global_type(g)),
            wasmparser::TypeRef::Tag(t) => wasm_encoder::EntityType::Tag(tag_type(t)),
        }
    }

    pub(crate) fn const_expr(
        expr: &[wasmparser::Operator],
    ) -> Result<wasm_encoder::ConstExpr, crate::Error> {
        use wasm_encoder::Encode;

        match expr.last() {
            Some(wasmparser::Operator::End) => {
                let mut bytes = vec![];
                for i in &expr[..expr.len() - 1] {
                    op(i)?.encode(&mut bytes);
                }
                Ok(wasm_encoder::ConstExpr::raw(bytes))
            }
            _ => Err(crate::Error::MissingConstEnd),
        }
    }

    pub(crate) struct DerefBytesIterator<'a> {
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

    pub(crate) fn data_segment<'a>(
        segment: crate::DataSegment<'a>,
        temp_const_expr: &'a mut wasm_encoder::ConstExpr,
    ) -> Result<wasm_encoder::DataSegment<'a, DerefBytesIterator<'a>>, crate::Error> {
        let mode = match segment.kind {
            crate::DataSegmentKind::Passive => wasm_encoder::DataSegmentMode::Passive,
            crate::DataSegmentKind::Active {
                memory_index,
                offset_expr,
            } => {
                *temp_const_expr = const_expr(&[offset_expr, wasmparser::Operator::End])?;
                wasm_encoder::DataSegmentMode::Active {
                    memory_index,
                    offset: temp_const_expr,
                }
            }
        };

        Ok(wasm_encoder::DataSegment {
            mode,
            data: DerefBytesIterator::new(segment.data),
        })
    }

    pub(crate) fn export_kind(export_kind: wasmparser::ExternalKind) -> wasm_encoder::ExportKind {
        match export_kind {
            wasmparser::ExternalKind::Func => wasm_encoder::ExportKind::Func,
            wasmparser::ExternalKind::Table => wasm_encoder::ExportKind::Table,
            wasmparser::ExternalKind::Memory => wasm_encoder::ExportKind::Memory,
            wasmparser::ExternalKind::Global => wasm_encoder::ExportKind::Global,
            wasmparser::ExternalKind::Tag => wasm_encoder::ExportKind::Tag,
        }
    }

    fn memarg(memarg: &wasmparser::MemArg) -> wasm_encoder::MemArg {
        wasm_encoder::MemArg {
            offset: memarg.offset,
            align: memarg.align as u32,
            memory_index: memarg.memory,
        }
    }

    pub(crate) fn element_items<'a>(
        element_items: &'a crate::ElementItems<'a>,
        temp_const_exprs: &'a mut Vec<wasm_encoder::ConstExpr>,
    ) -> Result<wasm_encoder::Elements<'a>, crate::Error> {
        match element_items {
            crate::ElementItems::Functions(funcs) => Ok(wasm_encoder::Elements::Functions(funcs)),
            crate::ElementItems::ConstExprs { ty, exprs } => {
                for e in exprs {
                    temp_const_exprs.push(const_expr(e)?);
                }
                Ok(wasm_encoder::Elements::Expressions(
                    ref_type(ty),
                    temp_const_exprs,
                ))
            }
        }
    }

    /// Convert [`wasmparser::Operator`] to [`wasm_encoder::Instruction`]. A
    /// simplified example of the conversion done in wasm-mutate
    /// [here](https://github.com/bytecodealliance/wasm-tools/blob/a8c4fddd239b0cb8978c76e6dfd856d5bd29b860/crates/wasm-mutate/src/mutators/translate.rs#L279).
    #[allow(unused_variables)]
    pub(crate) fn op(
        op: &wasmparser::Operator<'_>,
    ) -> Result<wasm_encoder::Instruction<'static>, wasmparser::BinaryReaderError> {
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
            (map $arg:ident hty) => (heap_type($arg));
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
}
