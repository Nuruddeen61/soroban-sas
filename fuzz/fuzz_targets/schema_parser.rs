#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::errors::SASError;
use soroban_sas_common::validation::{validate_schema_syntax, MAX_SCHEMA_FIELDS};
use soroban_sdk::{Env, String as SorobanString};

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\n' | '\r' | '\t' | '\x0b' | '\x0c')
}

fuzz_target!(|data: &[u8]| {
    let env = Env::default();
    let schema = SorobanString::from_bytes(&env, data);
    let result = validate_schema_syntax(&env, &schema); // kada ya yi panic

    if data.is_empty() {
        assert!(matches!(result, Err(SASError::EmptySchema)));
    }
    if data.len() > 1024 {
        assert!(matches!(result, Err(SASError::InvalidSchema)));
    }

    if result.is_ok() {
        assert!(data.is_ascii());
        let text = core::str::from_utf8(data).unwrap();
        let fields: Vec<&str> = text.split(',').collect();
        assert!(fields.len() as u32 <= MAX_SCHEMA_FIELDS);
        for f in fields {
            let f = f.trim_matches(is_ws);
            assert!(!f.is_empty() && f.len() <= 64);
            let mut it = f.splitn(2, is_ws);
            let ident = it.next().unwrap();
            let ty = it.next().unwrap().trim_matches(is_ws);
            assert!(!ident.is_empty() && ident.len() <= 32);
            assert!(!ty.is_empty() && ty.len() <= 32);
        }
    }
});
