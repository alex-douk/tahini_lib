use pin_project_lite::pin_project;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::convert::TryInto;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tarpc::serde_transport::Transport;
use tarpc::tokio_serde::{Deserializer, Serializer};
use tarpc::tokio_util::{
    bytes::BytesMut,
    codec::{Framed, LengthDelimitedCodec},
};
use tarpc::Transport as TransportTrait;
use tokio_util::bytes::Bytes;
