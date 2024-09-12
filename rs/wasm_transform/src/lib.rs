use std::ops::Range;

use wasmparser::{
    BinaryReaderError, Export, GlobalType, Import, MemoryType, Name, Operator, Parser, Payload,
    RefType, SubType, Subsections, TableType, ValType,
};

mod convert;
use convert::internal_to_encoder;
use convert::parser_to_internal;

pub struct Body<'a> {
    /// Local variables of the function, given as tuples of (# of locals, type).
    /// Note that these do not include the function parameters which are given
    /// indices before the locals. So if a function has 2 parameters and a local
    /// defined here then local indices 0 and 1 will refer to the parameters and
    /// index 2 will refer to the local here.
    pub locals: Vec<(u32, ValType)>,
    pub instructions: Vec<Operator<'a>>,
}

pub enum ElementItems<'a> {
    Functions(Vec<u32>),
    ConstExprs {
        ty: RefType,
        exprs: Vec<Operator<'a>>,
    },
}

pub enum ElementKind<'a> {
    Passive,
    Active {
        table_index: Option<u32>,
        offset_expr: Operator<'a>,
    },
    Declared,
}

pub struct DataSegment<'a> {
    /// The kind of data segment.
    pub kind: DataSegmentKind<'a>,
    /// The data of the data segment.
    pub data: &'a [u8],
}

/// The kind of data segment.
#[derive(Clone, Debug)]
pub enum DataSegmentKind<'a> {
    /// The data segment is passive.
    Passive,
    /// The data segment is active.
    Active {
        /// The memory index for the data segment.
        memory_index: u32,
        /// The initialization operator for the data segment.
        offset_expr: Operator<'a>,
    },
}

pub struct Global<'a> {
    pub ty: GlobalType,
    pub init_expr: Operator<'a>,
}

#[derive(Clone, Debug)]
pub enum Error {
    BinaryReaderError(BinaryReaderError),
    UnknownVersion(u32),
    UnknownSection {
        section_id: u8,
    },
    MissingFunctionEnd {
        func_range: Range<usize>,
    },
    IncorrectDataCount {
        declared_count: usize,
        actual_count: usize,
    },
    ConversionError(String),
    IncorrectCodeCounts {
        function_section_count: usize,
        code_section_declared_count: usize,
        code_section_actual_count: usize,
    },
    MultipleStartSections,
    /// `memory.grow` and `memory.size` operations must have a 0x00 byte
    /// immediately after the instruction (it is not valid to have some other
    /// variable length encoding representation of 0). This is because the
    /// immediate byte will be used to reference other memories in the
    /// multi-memory proposal.
    InvalidMemoryReservedByte {
        func_range: Range<usize>,
    },
}

impl From<BinaryReaderError> for Error {
    fn from(e: BinaryReaderError) -> Self {
        Self::BinaryReaderError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BinaryReaderError(err) => {
                write!(f, "Error from wasmparser: {}", err)
            }
            Error::UnknownVersion(ver) => {
                write!(f, "Unknown version: {}", ver)
            }
            Error::UnknownSection { section_id } => {
                write!(f, "Unknown section: {}", section_id)
            }
            Error::MissingFunctionEnd { func_range } => {
                write!(
                    f,
                    "Missing function End for function in range {} - {}",
                    func_range.start, func_range.end
                )
            }
            Error::IncorrectDataCount {
                declared_count,
                actual_count,
            } => {
                write!(
                    f,
                    "Incorrect data count. Declared: {}, actual: {}",
                    declared_count, actual_count
                )
            }
            Error::ConversionError(s) => {
                write!(
                    f,
                    "Unable to convert wasmparser type to wasm-encoder: {}",
                    s
                )
            }
            Error::IncorrectCodeCounts {
                function_section_count,
                code_section_declared_count,
                code_section_actual_count,
            } => {
                write!(
                    f,
                    "Incorrect code counts. Function section count: {}, code section declared count: {}, code section actual count: {}",
                    function_section_count, code_section_declared_count, code_section_actual_count
                )
            }
            Error::MultipleStartSections => {
                write!(f, "Multiple start sections")
            }
            Error::InvalidMemoryReservedByte { func_range } => {
                write!(f, "Found a `memory.*` instruction with an invalid reserved byte in function at {:?}", func_range)
            }
        }
    }
}

pub struct Module<'a> {
    pub types: Vec<SubType>,
    pub imports: Vec<Import<'a>>,
    /// Mapping from function index to type index.
    pub functions: Vec<u32>,
    /// Each table has a type and optional initialization expression.
    pub tables: Vec<(TableType, Option<Operator<'a>>)>,
    pub memories: Vec<MemoryType>,
    pub globals: Vec<Global<'a>>,
    pub data: Vec<DataSegment<'a>>,
    pub data_count_section_exists: bool,
    pub exports: Vec<Export<'a>>,
    // Index of the start function.
    pub start: Option<u32>,
    pub elements: Vec<(ElementKind<'a>, ElementItems<'a>)>,
    pub code_sections: Vec<Body<'a>>,
    pub custom_sections: Vec<(&'a str, &'a [u8])>,
    pub name_section: Option<NameSection<'a>>,
}

impl<'a> Module<'a> {
    pub fn parse(wasm: &'a [u8], enable_multi_memory: bool) -> Result<Self, Error> {
        let parser = Parser::new(0);
        let mut imports = vec![];
        let mut types = vec![];
        let mut data = vec![];
        let mut tables = vec![];
        let mut memories = vec![];
        let mut functions = vec![];
        let mut elements = vec![];
        let mut code_section_count = 0;
        let mut code_sections = vec![];
        let mut globals = vec![];
        let mut exports = vec![];
        let mut start = None;
        let mut data_section_count = None;
        let mut custom_sections = vec![];
        let mut name_section = None;
        for payload in parser.parse_all(wasm) {
            let payload = payload?;
            match payload {
                Payload::ImportSection(import_section_reader) => {
                    imports = import_section_reader
                        .into_iter()
                        .collect::<Result<_, _>>()?;
                }
                Payload::TypeSection(type_section_reader) => {
                    for rec_group in type_section_reader.into_iter() {
                        types.extend(rec_group?.into_types());
                    }
                }
                Payload::DataSection(data_section_reader) => {
                    data = data_section_reader
                        .into_iter()
                        .map(|sec| {
                            sec.map_err(Error::from)
                                .and_then(parser_to_internal::data_segment)
                        })
                        .collect::<Result<_, _>>()?;
                }
                Payload::TableSection(table_section_reader) => {
                    tables = table_section_reader
                        .into_iter()
                        .map(|t| {
                            t.map_err(Error::from).and_then(|t| match t.init {
                                wasmparser::TableInit::RefNull => Ok((t.ty, None)),
                                wasmparser::TableInit::Expr(e) => {
                                    convert::parser_to_internal::const_expr(e)
                                        .map(|init| (t.ty, Some(init)))
                                }
                            })
                        })
                        .collect::<Result<_, _>>()?;
                }
                Payload::MemorySection(memory_section_reader) => {
                    memories = memory_section_reader
                        .into_iter()
                        .collect::<Result<_, _>>()?;
                }
                Payload::FunctionSection(function_section_reader) => {
                    functions = function_section_reader
                        .into_iter()
                        .collect::<Result<_, _>>()?;
                }
                Payload::GlobalSection(global_section_reader) => {
                    globals = global_section_reader
                        .into_iter()
                        .map(|g| parser_to_internal::global(g?))
                        .collect::<Result<_, _>>()?;
                }
                Payload::ExportSection(export_section_reader) => {
                    exports = export_section_reader
                        .into_iter()
                        .collect::<Result<_, _>>()?;
                }
                Payload::StartSection { func, range: _ } => {
                    if start.is_some() {
                        return Err(Error::MultipleStartSections);
                    }
                    start = Some(func);
                }
                Payload::ElementSection(element_section_reader) => {
                    for element in element_section_reader.into_iter() {
                        let element = element?;
                        let items = parser_to_internal::element_items(element.items.clone())?;
                        elements.push((parser_to_internal::element_kind(element.kind)?, items));
                    }
                }
                Payload::DataCountSection { count, range: _ } => {
                    data_section_count = Some(count);
                }
                Payload::CodeSectionStart {
                    count,
                    range: _,
                    size: _,
                } => {
                    code_section_count = count as usize;
                }
                Payload::CodeSectionEntry(body) => {
                    let locals_reader = body.get_locals_reader()?;
                    let locals = locals_reader.into_iter().collect::<Result<Vec<_>, _>>()?;
                    let instructions = body
                        .get_operators_reader()?
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?;
                    if let Some(last) = instructions.last() {
                        if let Operator::End = last {
                        } else {
                            return Err(Error::MissingFunctionEnd {
                                func_range: body.range(),
                            });
                        }
                    }
                    if !enable_multi_memory
                        && instructions.iter().any(|i| match i {
                            Operator::MemoryGrow { mem } | Operator::MemorySize { mem } => {
                                mem.to_le_bytes()[0] != 0
                            }
                            _ => false,
                        })
                    {
                        return Err(Error::InvalidMemoryReservedByte {
                            func_range: body.range(),
                        });
                    }
                    code_sections.push(Body {
                        locals,
                        instructions,
                    });
                }
                Payload::CustomSection(custom_section_reader) => {
                    if let wasmparser::KnownCustom::Name(subsection) =
                        custom_section_reader.as_known()
                    {
                        name_section = Some(NameSection::parse(subsection)?);
                    } else {
                        custom_sections
                            .push((custom_section_reader.name(), custom_section_reader.data()));
                    }
                }
                Payload::Version {
                    num,
                    encoding: _,
                    range: _,
                } => {
                    if num != 1 {
                        return Err(Error::UnknownVersion(num as u32));
                    }
                }
                Payload::UnknownSection {
                    id,
                    contents: _,
                    range: _,
                } => return Err(Error::UnknownSection { section_id: id }),
                Payload::TagSection(_)
                | Payload::ModuleSection {
                    parser: _,
                    unchecked_range: _,
                }
                | Payload::InstanceSection(_)
                | Payload::CoreTypeSection(_)
                | Payload::ComponentSection {
                    parser: _,
                    unchecked_range: _,
                }
                | Payload::ComponentInstanceSection(_)
                | Payload::ComponentAliasSection(_)
                | Payload::ComponentTypeSection(_)
                | Payload::ComponentCanonicalSection(_)
                | Payload::ComponentStartSection { start: _, range: _ }
                | Payload::ComponentImportSection(_)
                | Payload::ComponentExportSection(_)
                | Payload::End(_) => {}
            }
        }
        if code_section_count != code_sections.len() || code_section_count != functions.len() {
            return Err(Error::IncorrectCodeCounts {
                function_section_count: functions.len(),
                code_section_declared_count: code_section_count,
                code_section_actual_count: code_sections.len(),
            });
        }
        if let Some(data_count) = data_section_count {
            if data_count as usize != data.len() {
                return Err(Error::IncorrectDataCount {
                    declared_count: data_count as usize,
                    actual_count: data.len(),
                });
            }
        }
        Ok(Module {
            types,
            imports,
            functions,
            tables,
            memories,
            globals,
            exports,
            start,
            elements,
            data_count_section_exists: data_section_count.is_some(),
            code_sections,
            data,
            custom_sections,
            name_section,
        })
    }

    pub fn encode(self) -> Result<Vec<u8>, Error> {
        let mut module = wasm_encoder::Module::new();

        if !self.types.is_empty() {
            let mut types = wasm_encoder::TypeSection::new();
            for subtype in self.types {
                types.subtype(&wasm_encoder::SubType::try_from(subtype.clone()).map_err(
                    |_err| Error::ConversionError(format!("Failed to convert type: {:?}", subtype)),
                )?);
            }
            module.section(&types);
        }

        if !self.imports.is_empty() {
            let mut imports = wasm_encoder::ImportSection::new();
            for import in self.imports {
                imports.import(
                    import.module,
                    import.name,
                    wasm_encoder::EntityType::try_from(import.ty).map_err(|_err| {
                        Error::ConversionError(format!("Failed to convert type: {:?}", import.ty))
                    })?,
                );
            }
            module.section(&imports);
        }

        if !self.functions.is_empty() {
            let mut functions = wasm_encoder::FunctionSection::new();
            for type_index in self.functions {
                functions.function(type_index);
            }
            module.section(&functions);
        }

        if !self.tables.is_empty() {
            let mut tables = wasm_encoder::TableSection::new();
            for (table_ty, init) in self.tables {
                let table_ty = wasm_encoder::TableType::try_from(table_ty).map_err(|_err| {
                    Error::ConversionError(format!("Failed to convert type: {:?}", table_ty))
                })?;
                match init {
                    None => tables.table(table_ty),
                    Some(const_expr) => tables
                        .table_with_init(table_ty, &internal_to_encoder::const_expr(&const_expr)?),
                };
            }
            module.section(&tables);
        }

        if !self.memories.is_empty() {
            let mut memories = wasm_encoder::MemorySection::new();
            for memory in self.memories {
                memories.memory(wasm_encoder::MemoryType::from(memory));
            }
            module.section(&memories);
        }

        if !self.globals.is_empty() {
            let mut globals = wasm_encoder::GlobalSection::new();
            for global in self.globals {
                globals.global(
                    wasm_encoder::GlobalType::try_from(global.ty).map_err(|_err| {
                        Error::ConversionError(format!("Failed to convert type: {:?}", global.ty))
                    })?,
                    &internal_to_encoder::const_expr(&global.init_expr)?,
                );
            }
            module.section(&globals);
        }

        if !self.exports.is_empty() {
            let mut exports = wasm_encoder::ExportSection::new();
            for export in self.exports {
                exports.export(
                    export.name,
                    wasm_encoder::ExportKind::from(export.kind),
                    export.index,
                );
            }
            module.section(&exports);
        }

        if let Some(function_index) = self.start {
            module.section(&wasm_encoder::StartSection { function_index });
        }

        if !self.elements.is_empty() {
            let mut elements = wasm_encoder::ElementSection::new();
            let mut temp_const_exprs = vec![];
            for (kind, items) in self.elements {
                temp_const_exprs.clear();
                let element_items = match &items {
                    crate::ElementItems::Functions(funcs) => {
                        wasm_encoder::Elements::Functions(funcs)
                    }
                    crate::ElementItems::ConstExprs { ty, exprs } => {
                        temp_const_exprs.reserve(exprs.len());
                        for e in exprs {
                            temp_const_exprs.push(internal_to_encoder::const_expr(e)?);
                        }
                        wasm_encoder::Elements::Expressions(
                            wasm_encoder::RefType::try_from(*ty).map_err(|_err| {
                                Error::ConversionError(format!("Failed to convert type: {:?}", ty))
                            })?,
                            &temp_const_exprs,
                        )
                    }
                };

                match kind {
                    ElementKind::Passive => {
                        elements.passive(element_items);
                    }
                    ElementKind::Active {
                        table_index,
                        offset_expr,
                    } => {
                        elements.active(
                            table_index,
                            &internal_to_encoder::const_expr(&offset_expr)?,
                            element_items,
                        );
                    }
                    ElementKind::Declared => {
                        elements.declared(element_items);
                    }
                }
            }
            module.section(&elements);
        }

        if self.data_count_section_exists {
            let data_count = wasm_encoder::DataCountSection {
                count: self.data.len() as u32,
            };
            module.section(&data_count);
        }

        if !self.code_sections.is_empty() {
            let mut code = wasm_encoder::CodeSection::new();
            for Body {
                locals,
                instructions,
            } in self.code_sections
            {
                let mut converted_locals = Vec::with_capacity(locals.len());
                for (c, t) in locals {
                    converted_locals.push((
                        c,
                        wasm_encoder::ValType::try_from(t).map_err(|_err| {
                            Error::ConversionError(format!("Falied to convert type: {:?}", t))
                        })?,
                    ));
                }
                let mut function = wasm_encoder::Function::new(converted_locals);
                for op in instructions {
                    function.instruction(&internal_to_encoder::op(op)?);
                }
                code.function(&function);
            }
            module.section(&code);
        }

        if !self.data.is_empty() {
            let mut data = wasm_encoder::DataSection::new();
            for segment in self.data {
                let segment_data = segment.data.iter().copied();
                match segment.kind {
                    crate::DataSegmentKind::Passive => data.segment(wasm_encoder::DataSegment {
                        mode: wasm_encoder::DataSegmentMode::Passive,
                        data: segment_data,
                    }),
                    crate::DataSegmentKind::Active {
                        memory_index,
                        offset_expr,
                    } => {
                        let const_expr = internal_to_encoder::const_expr(&offset_expr)?;
                        data.segment(wasm_encoder::DataSegment {
                            mode: wasm_encoder::DataSegmentMode::Active {
                                memory_index,
                                offset: &const_expr,
                            },
                            data: segment_data,
                        })
                    }
                };
            }
            module.section(&data);
        }

        if let Some(name_section) = self.name_section {
            name_section.encode(&mut module);
        }

        for (name, data) in self.custom_sections {
            module.section(&wasm_encoder::CustomSection {
                name: std::borrow::Cow::Borrowed(name),
                data: std::borrow::Cow::Borrowed(data),
            });
        }

        Ok(module.finish())
    }
}

pub struct NameSection<'a> {
    pub function_names: Vec<(u32, &'a str)>,
    pub type_names: Vec<(u32, &'a str)>,
    pub memory_names: Vec<(u32, &'a str)>,
    pub local_names: Vec<(u32, Vec<(u32, &'a str)>)>,
    pub label_names: Vec<(u32, Vec<(u32, &'a str)>)>,
}

impl<'a> NameSection<'a> {
    fn parse(name_section: Subsections<'a, Name<'a>>) -> Result<Self, Error> {
        fn add_names<'a>(
            name_map: wasmparser::SectionLimited<'a, wasmparser::Naming<'a>>,
            values: &mut Vec<(u32, &'a str)>,
        ) -> Result<(), Error> {
            for naming in name_map.into_iter() {
                let naming = naming?;
                values.push((naming.index, naming.name));
            }
            Ok(())
        }

        fn add_indirect_names<'a>(
            indirect_name_map: wasmparser::SectionLimited<'a, wasmparser::IndirectNaming<'a>>,
            values: &mut Vec<(u32, Vec<(u32, &'a str)>)>,
        ) -> Result<(), Error> {
            for indirect in indirect_name_map.into_iter() {
                let indirect = indirect?;
                let mut names = vec![];
                add_names(indirect.names, &mut names)?;
                values.push((indirect.index, names));
            }
            Ok(())
        }

        let mut function_names = vec![];
        let mut type_names = vec![];
        let mut memory_names = vec![];
        let mut local_names = vec![];
        let mut label_names = vec![];
        for subsection_reader in name_section.into_iter() {
            match subsection_reader? {
                Name::Function(name_map) => add_names(name_map, &mut function_names)?,
                Name::Type(name_map) => add_names(name_map, &mut type_names)?,
                Name::Memory(name_map) => add_names(name_map, &mut memory_names)?,
                Name::Local(indirect_name_map) => {
                    add_indirect_names(indirect_name_map, &mut local_names)?
                }
                Name::Label(indirect_name_map) => {
                    add_indirect_names(indirect_name_map, &mut label_names)?
                }
                _ => {}
            }
        }

        Ok(Self {
            function_names,
            type_names,
            memory_names,
            local_names,
            label_names,
        })
    }

    fn encode(self, module: &mut wasm_encoder::Module) {
        fn make_name_map(values: &[(u32, &str)]) -> wasm_encoder::NameMap {
            let mut result = wasm_encoder::NameMap::new();
            for (index, name) in values {
                result.append(*index, name);
            }
            result
        }

        fn make_indirect_name_map(
            values: &[(u32, Vec<(u32, &str)>)],
        ) -> wasm_encoder::IndirectNameMap {
            let mut result = wasm_encoder::IndirectNameMap::new();
            for (index, names) in values {
                result.append(*index, &make_name_map(&names));
            }
            result
        }

        let mut name_section = wasm_encoder::NameSection::new();

        if !self.function_names.is_empty() {
            name_section.functions(&make_name_map(&self.function_names));
        }

        if !self.type_names.is_empty() {
            name_section.types(&make_name_map(&self.type_names));
        }

        if !self.memory_names.is_empty() {
            name_section.memories(&make_name_map(&self.memory_names));
        }

        if !self.local_names.is_empty() {
            name_section.locals(&make_indirect_name_map(&self.local_names));
        }

        if !self.label_names.is_empty() {
            name_section.labels(&make_indirect_name_map(&self.label_names));
        }

        module.section(&name_section);
    }
}
