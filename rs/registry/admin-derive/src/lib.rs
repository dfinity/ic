//! Simple derive macros used in `ic-admin` to reduce repetition.
extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;

/// Macro to allow proposal command structs to implement the ProposalMetadata
/// trait.
#[proc_macro_derive(ProposalMetadata)]
pub fn proposal_metadata_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_proposal_metadata(&ast)
}

fn impl_proposal_metadata(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl ProposalMetadata for #name {
            fn summary(&self) -> String {
                summary_from_string_or_file(&self.summary, &self.summary_file)
            }

            fn url(&self) -> String {
                parse_proposal_url(self.proposal_url.clone())
            }

            fn proposer_and_sender(&self, sender: Sender) -> (NeuronId, Sender) {
                let use_test_neuron = self.test_neuron_proposer || (self.dry_run && matches!(sender, Sender::Anonymous));
                get_proposer_and_sender(self.proposer.clone(), sender, use_test_neuron)
            }

            fn is_dry_run(&self) -> bool {
                self.dry_run
            }

            fn is_verbose(&self) -> bool {
                self.verbose
            }
        }
    };
    gen.into()
}

/// Macro to add common fields to proposals command structs.
#[proc_macro_attribute]
pub fn derive_common_proposal_fields(_: TokenStream, item: TokenStream) -> TokenStream {
    let mut found_struct = false;
    item.into_iter()
        .map(|r| {
            match r {
                proc_macro::TokenTree::Ident(ref ident) if ident.to_string() == "struct" => {
                    found_struct = true;
                    r
                }
                proc_macro::TokenTree::Group(ref group)
                    if group.delimiter() == proc_macro::Delimiter::Brace && found_struct =>
                {
                    let mut stream = proc_macro::TokenStream::new();
                    let gen = TokenStream::from(quote! {
                            #[clap(long)]
                            /// The id of the neuron on behalf of which the proposal will be submitted.
                            pub proposer: Option<NeuronId>,

                            /// If set, the proposal will use a test proposer neuron, which must exist
                            /// in the governance canister. Ignored if 'proposer' is set.
                            #[clap(long)]
                            pub test_neuron_proposer: bool,

                            /// A url pointing to additional content required to evaluate the
                            /// proposal, specified using HTTPS.
                            #[clap(long)]
                            pub proposal_url: Option<Url>,

                            /// The title of the proposal.
                            #[clap(long)]
                            pub proposal_title: Option<String>,

                            /// A human-readable, markdown, summary of the proposal content.
                            #[clap(long)]
                            summary: Option<String>,

                            /// A file containing a human readable summary of the proposal content.
                            /// If this is provided "summary" will be ignored.
                            #[clap(long)]
                            summary_file: Option<PathBuf>,

                            /// If set, the fully formed proposal payload will be printed but not
                            /// submitted.
                            #[clap(long)]
                            pub dry_run: bool,

                            /// If set, verbose output will be printed.
                            #[clap(long)]
                            pub verbose: bool,
                    });
                    stream.extend(gen);
                    stream.extend(group.stream());
                    proc_macro::TokenTree::Group(proc_macro::Group::new(
                        proc_macro::Delimiter::Brace,
                        stream,
                    ))
                }
                _ => r,
            }
        })
        .collect()
}
