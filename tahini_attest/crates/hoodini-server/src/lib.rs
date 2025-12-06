use fizz_rs::DelegatedCredentialData;

pub fn fetch_credentials() -> Option<fizz_rs::DelegatedCredentialData> {
    std::env::var("TAHINI_CREDENTIAL")
        .ok()
        .and_then(|c| DelegatedCredentialData::from_pem(c.as_str()).ok())
}
