pub mod client;
pub mod context;
pub mod enums;
pub mod server;
pub mod traits;
pub mod transport;
pub mod tls_transport;

pub use enums::{TahiniEnum, TahiniVariantsEnum};
pub use traits::{TahiniTransformFrom, TahiniTransformInto, TahiniType};
// pub use serde::{Serialize as TahiniSerialize, Deserialize as };
pub use serde::{
    Deserialize as TahiniDeserialize, Deserializer, Serialize as TahiniSerialize, Serializer,
};

#[cfg(feature = "derive")]
pub use tahini_tarpc_derive::*;
