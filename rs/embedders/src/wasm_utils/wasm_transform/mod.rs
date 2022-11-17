use std::ops::Range;

use wasmparser::{
    BinaryReaderError, DataKind, Element, ElementItem, ElementKind, Export, Global, Import,
    MemoryType, Operator, Parser, Payload, TableType, Type, ValType,
};

mod convert;

pub enum InstOrBytes<'a> {
    Inst(Operator<'a>),
    Bytes(&'a [u8]),
}

pub struct Body<'a> {
    pub locals: Vec<(u32, ValType)>,
    pub instructions: Vec<Operator<'a>>,
}

pub enum ElementItems {
    Functions(Vec<u32>),
    ConstExprs(Vec<wasm_encoder::ConstExpr>),
}

pub struct DataSegment<'a> {
    /// The kind of data segment.
    pub kind: DataSegmentKind<'a>,
    /// The data of the data segment.
    pub data: &'a [u8],
}

/// The kind of data segment.
#[derive(Debug, Clone)]
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

impl<'a> DataSegmentKind<'a> {
    pub fn from_data_kind(kind: DataKind<'a>) -> Result<Self, Error> {
        Ok(match kind {
            DataKind::Passive => DataSegmentKind::Passive,
            DataKind::Active {
                memory_index,
                offset_expr,
            } => {
                let ops: Vec<_> = offset_expr
                    .get_operators_reader()
                    .into_iter()
                    .collect::<Result<_, _>>()?;
                match ops.as_slice() {
                    [_, Operator::End] => DataSegmentKind::Active {
                        memory_index,
                        offset_expr: ops[0].clone(),
                    },
                    _ => return Err(Error::InvalidConstExpr),
                }
            }
        })
    }
}

#[derive(Debug, Clone)]
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
    InvalidConstExpr,
    IncorrectCodeCounts {
        function_section_count: usize,
        code_section_declared_count: usize,
        code_section_actual_count: usize,
    },
    PassiveElementSectionTypeNotFuncRef {
        ty: ValType,
    },
    MultipleStartSections,
    UnexpectedElementType,
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
            Error::InvalidConstExpr => {
                write!(f, "Invalid ConstExpr")
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
            Error::PassiveElementSectionTypeNotFuncRef { ty } => {
                write!(
                    f,
                    "Passive elements in element section expected to be of type Func, found: {:?}",
                    ty
                )
            }
            Error::MultipleStartSections => {
                write!(f, "Multiple start sections")
            }
            Error::UnexpectedElementType => {
                write!(f, "Unexpected element type")
            }
            Error::InvalidMemoryReservedByte { func_range } => {
                write!(f, "Found a `memory.*` instruction with an invalid reserved byte in function at {:?}", func_range)
            }
        }
    }
}

pub struct Module<'a> {
    pub types: Vec<Type>,
    pub imports: Vec<Import<'a>>,
    /// Mapping from function index to type index.
    pub functions: Vec<u32>,
    pub tables: Vec<TableType>,
    pub memories: Vec<MemoryType>,
    pub globals: Vec<Global<'a>>,
    pub data: Vec<DataSegment<'a>>,
    pub data_count_section_exists: bool,
    pub exports: Vec<Export<'a>>,
    // Index of the start function.
    pub start: Option<u32>,
    pub elements: Vec<(Element<'a>, ElementItems)>,
    pub code_sections: Vec<Body<'a>>,
    pub custom_sections: Vec<(&'a str, &'a [u8])>,
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
        for payload in parser.parse_all(wasm) {
            let payload = payload?;
            match payload {
                Payload::ImportSection(import_section_reader) => {
                    imports = import_section_reader
                        .into_iter()
                        .collect::<Result<_, _>>()?;
                }
                Payload::TypeSection(type_section_reader) => {
                    types = type_section_reader.into_iter().collect::<Result<_, _>>()?;
                }
                Payload::DataSection(data_section_reader) => {
                    data = data_section_reader
                        .into_iter()
                        .map(|sec| {
                            sec.map_err(Error::from).and_then(|sec| {
                                Ok(DataSegment {
                                    kind: DataSegmentKind::from_data_kind(sec.kind)?,
                                    data: sec.data,
                                })
                            })
                        })
                        .collect::<Result<_, _>>()?;
                }
                Payload::TableSection(table_section_reader) => {
                    tables = table_section_reader.into_iter().collect::<Result<_, _>>()?;
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
                        if element.ty != ValType::FuncRef {
                            if let ElementKind::Passive = element.kind {
                                return Err(Error::PassiveElementSectionTypeNotFuncRef {
                                    ty: element.ty,
                                });
                            } else {
                                break;
                            }
                        }
                        let item_reader = element.items.get_items_reader()?;
                        let items = item_reader.into_iter().collect::<Result<Vec<_>, _>>()?;
                        let items = match items.get(0) {
                            Some(ElementItem::Func(_)) => {
                                let mut func_items = vec![];
                                for item in items {
                                    match item {
                                        ElementItem::Func(inx) => func_items.push(inx),
                                        ElementItem::Expr(_) => {
                                            return Err(Error::UnexpectedElementType)
                                        }
                                    }
                                }
                                ElementItems::Functions(func_items)
                            }
                            Some(ElementItem::Expr(_)) => {
                                let mut const_items = vec![];
                                for item in items {
                                    match item {
                                        ElementItem::Expr(expr) => {
                                            const_items.push(convert::const_expr(expr)?);
                                        }
                                        ElementItem::Func(_) => {
                                            return Err(Error::UnexpectedElementType)
                                        }
                                    }
                                }
                                ElementItems::ConstExprs(const_items)
                            }
                            None => ElementItems::Functions(vec![]),
                        };
                        elements.push((element, items));
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
                            Operator::MemoryGrow { mem_byte, .. }
                            | Operator::MemorySize { mem_byte, .. } => *mem_byte != 0x00,
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
                    custom_sections
                        .push((custom_section_reader.name(), custom_section_reader.data()));
                }
                Payload::Version {
                    num,
                    encoding: _,
                    range: _,
                } => {
                    if num != 1 {
                        return Err(Error::UnknownVersion(num));
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
                    range: _,
                }
                | Payload::InstanceSection(_)
                | Payload::CoreTypeSection(_)
                | Payload::ComponentSection {
                    parser: _,
                    range: _,
                }
                | Payload::ComponentInstanceSection(_)
                | Payload::ComponentAliasSection(_)
                | Payload::ComponentTypeSection(_)
                | Payload::ComponentCanonicalSection(_)
                | Payload::ComponentStartSection(_)
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
        })
    }

    pub fn encode(self) -> Result<Vec<u8>, BinaryReaderError> {
        let mut module = wasm_encoder::Module::new();

        if !self.types.is_empty() {
            let mut types = wasm_encoder::TypeSection::new();
            for Type::Func(ty) in self.types {
                let params = ty
                    .params()
                    .iter()
                    .map(convert::val_type)
                    .collect::<Vec<_>>();
                let results = ty
                    .results()
                    .iter()
                    .map(convert::val_type)
                    .collect::<Vec<_>>();
                types.function(params, results);
            }
            module.section(&types);
        }

        if !self.imports.is_empty() {
            let mut imports = wasm_encoder::ImportSection::new();
            for import in self.imports {
                imports.import(import.module, import.name, convert::import_type(import.ty));
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
            for table in self.tables {
                tables.table(convert::table_type(table));
            }
            module.section(&tables);
        }

        if !self.memories.is_empty() {
            let mut memories = wasm_encoder::MemorySection::new();
            for memory in self.memories {
                memories.memory(convert::memory_type(memory));
            }
            module.section(&memories);
        }

        if !self.globals.is_empty() {
            let mut globals = wasm_encoder::GlobalSection::new();
            for global in self.globals {
                globals.global(
                    convert::global_type(global.ty),
                    &convert::const_expr(global.init_expr)?,
                );
            }
            module.section(&globals);
        }

        if !self.exports.is_empty() {
            let mut exports = wasm_encoder::ExportSection::new();
            for export in self.exports {
                exports.export(export.name, convert::export_kind(export.kind), export.index);
            }
            module.section(&exports);
        }

        if let Some(function_index) = self.start {
            module.section(&wasm_encoder::StartSection { function_index });
        }

        if !self.elements.is_empty() {
            let mut elements = wasm_encoder::ElementSection::new();
            for (element, items) in self.elements {
                let element_items = convert::element_items(&items);
                match element.kind {
                    ElementKind::Passive => {
                        elements.passive(convert::val_type(&element.ty), element_items);
                    }
                    ElementKind::Active {
                        table_index,
                        offset_expr,
                    } => {
                        // Setting the table_index to `None` is semantically
                        // equivalent to `Some(0)` with the type being FuncRef.
                        // But `None` will use the `0x00` element section tag
                        // and `Some(0) will use the `0x02` element tag. We
                        // didn't track which tag was actually used in the
                        // original file, but it's safer to assume `0x00` was
                        // used if possible.
                        let table_index = if table_index == 0 && element.ty == ValType::FuncRef {
                            None
                        } else {
                            Some(table_index)
                        };
                        elements.active(
                            table_index,
                            &convert::const_expr(offset_expr)?,
                            convert::val_type(&element.ty),
                            element_items,
                        );
                    }
                    ElementKind::Declared => {
                        elements.declared(convert::val_type(&element.ty), element_items);
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
                let mut function = wasm_encoder::Function::new(
                    locals.into_iter().map(|(c, t)| (c, convert::val_type(&t))),
                );
                for op in instructions {
                    function.instruction(&convert::op(&op)?);
                }
                code.function(&function);
            }
            module.section(&code);
        }

        if !self.data.is_empty() {
            let mut data = wasm_encoder::DataSection::new();
            let mut temp_const_exprs = vec![];
            for segment in self.data {
                temp_const_exprs.push(wasm_encoder::ConstExpr::empty());
                let len = temp_const_exprs.len();
                data.segment(convert::data_segment(
                    segment,
                    temp_const_exprs.get_mut(len - 1).unwrap(),
                )?);
            }
            module.section(&data);
        }

        for (name, data) in self.custom_sections {
            module.section(&wasm_encoder::CustomSection { name, data });
        }

        Ok(module.finish())
    }
}
