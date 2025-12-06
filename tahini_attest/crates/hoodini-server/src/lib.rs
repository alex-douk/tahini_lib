use fizz_rs::DelegatedCredentialData;

pub fn fetch_credentials() -> Option<fizz_rs::DelegatedCredentialData> {
    std::env::var("TAHINI_CREDENTIAL")
        .ok()
        .and_then(|c| serde_json::from_str::<DelegatedCredentialData>(&c).ok())
}
