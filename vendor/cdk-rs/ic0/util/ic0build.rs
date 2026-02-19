use quote::quote;
use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;
use syn::{Error, parenthesized};
use syn::{FnArg, Ident, Token, TypePath};

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Debug)]
pub struct SystemAPI {
    pub name: Ident,
    pub args: Vec<FnArg>,
    pub output: Option<TypePath>,
}

impl Parse for SystemAPI {
    fn parse(input: ParseStream) -> Result<Self> {
        let ic0_token: Ident = input.parse()?;
        if ic0_token != "ic0" {
            return Err(Error::new(ic0_token.span(), "expected `ic0`"));
        }
        input.parse::<Token![.]>()?;
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;

        // args
        let content;
        parenthesized!(content in input);
        let args = Punctuated::<FnArg, Comma>::parse_terminated(&content)?;
        let args: Vec<FnArg> = args.iter().cloned().collect();
        for arg in &args {
            match arg {
                FnArg::Receiver(r) => return Err(Error::new(r.span(), "arguments can't be self")),
                FnArg::Typed(pat_type) => match &*pat_type.ty {
                    syn::Type::Path(ty) => {
                        type_supported(ty)?;
                    }
                    _ => {
                        return Err(Error::new(
                            pat_type.span(),
                            "argument types can only be i32, i64 or isize",
                        ));
                    }
                },
            }
        }

        input.parse::<Token![->]>()?;

        // output
        let output = if input.peek(syn::token::Paren) {
            let content;
            parenthesized!(content in input);
            if content.is_empty() {
                None
            } else {
                let _output_name: Ident = content.parse()?;
                content.parse::<Token![:]>()?;
                let ty: TypePath = content.parse()?;
                if !content.is_empty() {
                    return Err(Error::new(ty.span(), "expected only one return type"));
                }
                type_supported(&ty)?;
                Some(ty)
            }
        } else {
            let ty: TypePath = input.parse()?;
            type_supported(&ty)?;
            Some(ty)
        };

        input.parse::<Token![;]>()?;

        Ok(Self { name, args, output })
    }
}

fn type_supported(ty: &TypePath) -> Result<()> {
    let ty = ty
        .path
        .get_ident()
        .ok_or(Error::new(ty.span(), "cannot get ident from: {ty:?}"))?;
    if ty == "u32" || ty == "u64" || ty == "usize" {
        Ok(())
    } else {
        Err(Error::new(
            ty.span(),
            "ic0.txt should only contain i32, i64 or I",
        ))
    }
}

#[derive(Clone, Debug)]
pub struct IC0 {
    pub apis: Vec<SystemAPI>,
}

impl Parse for IC0 {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            apis: {
                let mut apis = vec![];
                while !input.is_empty() {
                    apis.push(input.parse()?);
                }
                apis
            },
        })
    }
}

fn parse_safety_comments(file: &str) -> HashMap<String, String> {
    let mut comments = HashMap::new();
    let lines = file.lines().collect::<Vec<_>>();
    let mut cursor = 0;
    while cursor < lines.len() {
        if lines[cursor].is_empty() || lines[cursor].trim().starts_with("//") {
            cursor += 1;
            continue;
        }
        let fn_name = lines[cursor]
            .split_whitespace()
            .next()
            .unwrap()
            .strip_prefix("ic0.")
            .unwrap();
        while !lines[cursor].contains(";") {
            cursor += 1;
            if cursor >= lines.len() {
                panic!("unexpected eof, no semicolon found for function: {fn_name}");
            }
        }
        cursor += 1;
        let mut comment = String::new();
        loop {
            if let Some(comment_line) = lines[cursor].strip_prefix("    ") {
                comment.push_str(comment_line.trim());
                comment.push('\n');
                cursor += 1;
                if cursor >= lines.len() {
                    break;
                }
            } else if lines[cursor].trim().is_empty() {
                comment.push('\n');
                cursor += 1;
                if cursor >= lines.len() {
                    break;
                }
            } else {
                break;
            }
        }
        comments.insert(
            fn_name.to_string(),
            format!("# Safety\n\n{}", comment.trim()),
        );
    }
    comments
}

fn main() {
    let s = include_str!("../ic0.txt");
    let s = s.replace('I', "usize");
    let s = s.replace("i32", "u32");
    let s = s.replace("i64", "u64");
    let ic0: IC0 = syn::parse_str(&s).unwrap();
    let safety_comments = parse_safety_comments(include_str!("../manual_safety_comments.txt"));
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("src/sys.rs");

    let mut f = fs::File::create(d).unwrap();

    writeln!(
        f,
        r#"// This file is generated from ic0.txt.
// Don't manually modify it.
#[cfg(target_family = "wasm")]
#[link(wasm_import_module = "ic0")]
unsafe extern "C" {{"#,
    )
    .unwrap();

    for api in &ic0.apis {
        let fn_name = &api.name;
        let args = &api.args;

        let mut r = quote! {
            pub fn #fn_name(#(#args),*)
        };

        if let Some(output) = &api.output {
            r = quote! {
                #r -> #output
            }
        }

        let Some(comment) = safety_comments.get(&fn_name.to_string()) else {
            panic!("missing safety comment for {fn_name}")
        };

        r = quote! {
            #[doc = #comment]
            #r;
        };
        writeln!(f, "{r}").unwrap();
    }

    writeln!(f, "}}").unwrap();

    writeln!(
        f,
        r#"
#[cfg(not(target_family = "wasm"))]
#[allow(unused_variables)]
#[allow(clippy::missing_safety_doc)]
#[allow(clippy::too_many_arguments)]
mod non_wasm{{"#,
    )
    .unwrap();

    for api in &ic0.apis {
        let fn_name = &api.name;
        let args = &api.args;

        let mut r = quote! {
            pub unsafe fn #fn_name(#(#args),*)
        };

        if let Some(output) = &api.output {
            r = quote! {
                #r -> #output
            }
        }

        let panic_str = format!("{fn_name} should only be called inside canisters.");
        let Some(comment) = safety_comments.get(&fn_name.to_string()) else {
            panic!("missing safety comment for {fn_name}")
        };

        r = quote! {
            #[doc = #comment]
            #r {
                panic!(#panic_str);
            }
        };
        writeln!(f, "{r}").unwrap();
    }

    writeln!(
        f,
        r#"}}

#[cfg(not(target_family = "wasm"))]
pub use non_wasm::*;
"#
    )
    .unwrap();

    Command::new("cargo")
        .args(["fmt"])
        .output()
        .expect("`cargo fmt` failed");
}
