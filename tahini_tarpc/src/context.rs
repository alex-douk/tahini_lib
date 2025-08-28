use std::{collections::HashMap, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::enums::TahiniEnum;
use super::traits::TahiniType;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TahiniContext {
    pub service: String,
    pub rpc: String,
    priv_marker: PhantomData<()>,
}

impl TahiniContext {
    pub(crate) fn new<'a>(service: &'a str, rpc: &'a str) -> Self {
        TahiniContext {
            service: service.to_string(),
            rpc: rpc.to_string(),
            priv_marker: PhantomData,
        }
    }
}

impl TahiniType for TahiniContext {
    fn to_tahini_enum(self) -> TahiniEnum {
        let mut hash_map = HashMap::new();
        hash_map.insert("service", TahiniEnum::Value(Box::new(self.service)));
        hash_map.insert("rpc", TahiniEnum::Value(Box::new(self.rpc)));
        TahiniEnum::Struct("TahiniContext", hash_map)
    }
}
