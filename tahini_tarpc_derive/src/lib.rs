extern crate proc_macro;
extern crate syn;


mod tahini_type;
mod tahini_service;

use proc_macro::TokenStream;
use quote::quote_spanned;
use syn::{parse_macro_input, DeriveInput};


#[proc_macro_derive(TahiniType)]
pub fn derive_tahini_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match tahini_type::derive_tahini_type_impl(input) {
        Ok(tokens) => tokens.into(),
        Err((span, err)) => quote_spanned!(span => compile_error!(#err)).into(),
    }
}


#[proc_macro_attribute]
pub fn tahini_service(args: TokenStream, input: TokenStream) -> TokenStream {
    tahini_service::service(args, input)
}

#[proc_macro_attribute]
pub fn allow_client_transform(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}
