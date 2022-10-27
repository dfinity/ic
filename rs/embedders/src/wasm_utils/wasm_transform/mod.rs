use wasm_encoder::Function;
use wasmparser::{
    BinaryReaderError, Data, Element, ElementItem, ElementKind, Export, Global, Import, MemoryType,
    Operator, Parser, Payload, TableType, Type, ValType,
};

mod convert;

pub enum InstOrBytes<'a> {
    Inst(Operator<'a>),
    Bytes(&'a [u8]),
}
pub struct Body<'a> {
    locals: Vec<(u32, ValType)>,
    instructions: Vec<Operator<'a>>,
}

pub struct Module<'a> {
    pub types: Vec<Type>,
    pub imports: Vec<Import<'a>>,
    /// Mapping from function index to type index.
    pub functions: Vec<u32>,
    pub tables: Vec<TableType>,
    pub memories: Vec<MemoryType>,
    pub globals: Vec<Global<'a>>,
    pub data: Vec<Data<'a>>,
    pub exports: Vec<Export<'a>>,
    // Index of the start function.
    pub start: Option<u32>,
    //Vector of function indices. For now ignore other element types.
    pub elements: Vec<(Element<'a>, Vec<u32>)>,
    pub code_sections: Vec<Body<'a>>,
    pub custom_sections: Vec<(&'a str, &'a [u8])>,
}

impl<'a> Module<'a> {
    pub fn parse(wasm: &'a [u8]) -> Result<Self, BinaryReaderError> {
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
                    data = data_section_reader.into_iter().collect::<Result<_, _>>()?;
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
                    start = Some(func);
                }
                Payload::ElementSection(element_section_reader) => {
                    for element in element_section_reader.into_iter() {
                        let element = element?;
                        if element.ty != ValType::FuncRef {
                            break;
                        }
                        let item_reader = element.items.get_items_reader()?;
                        let mut items = vec![];
                        for item in item_reader {
                            match item? {
                                ElementItem::Func(inx) => items.push(inx),
                                ElementItem::Expr(_) => break,
                            }
                        }
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
                    code_section_count = count;
                }
                Payload::CodeSectionEntry(body) => {
                    let locals_reader = body.get_locals_reader()?;
                    let locals = locals_reader.into_iter().collect::<Result<Vec<_>, _>>()?;
                    let instructions = body
                        .get_operators_reader()?
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?;
                    code_sections.push(Body {
                        locals,
                        instructions,
                    });
                }
                Payload::CustomSection(custom_section_reader) => {
                    custom_sections
                        .push((custom_section_reader.name(), custom_section_reader.data()));
                }
                Payload::Version { .. }
                | Payload::TagSection(_)
                | Payload::ModuleSection { .. }
                | Payload::InstanceSection(_)
                | Payload::CoreTypeSection(_)
                | Payload::ComponentSection { .. }
                | Payload::ComponentInstanceSection(_)
                | Payload::ComponentAliasSection(_)
                | Payload::ComponentTypeSection(_)
                | Payload::ComponentCanonicalSection(_)
                | Payload::ComponentStartSection(_)
                | Payload::ComponentImportSection(_)
                | Payload::ComponentExportSection(_)
                | Payload::UnknownSection { .. }
                | Payload::End(_) => {}
            }
        }
        assert_eq!(code_section_count as usize, code_sections.len());
        if let Some(data_count) = data_section_count {
            assert_eq!(data_count as usize, data.len());
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
                match element.kind {
                    ElementKind::Passive => {
                        elements.passive(
                            convert::val_type(&element.ty),
                            wasm_encoder::Elements::Functions(&items),
                        );
                    }
                    ElementKind::Active {
                        table_index,
                        offset_expr,
                    } => {
                        elements.active(
                            Some(table_index),
                            &convert::const_expr(offset_expr)?,
                            convert::val_type(&element.ty),
                            wasm_encoder::Elements::Functions(&items),
                        );
                    }
                    ElementKind::Declared => {
                        elements.declared(
                            convert::val_type(&element.ty),
                            wasm_encoder::Elements::Functions(&items),
                        );
                    }
                }
            }
            module.section(&elements);
        }

        if !self.code_sections.is_empty() {
            let mut code = wasm_encoder::CodeSection::new();
            for Body {
                locals,
                instructions,
            } in self.code_sections
            {
                let mut function =
                    Function::new(locals.into_iter().map(|(c, t)| (c, convert::val_type(&t))));
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
