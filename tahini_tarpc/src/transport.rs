// TODO(babman): we can probably do some work with this to ensure transport/codec are safe, maybe
//               using scrutinizer.
pub use aws_lc_rs::aead::RandomizedNonceKey as TahiniChannelKey;
use aws_lc_rs::aead::{Aad, Nonce, NONCE_LEN};
use hoodini_core::types::ClientId;
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

use crate::server::ClientMap;

#[derive(Clone)]
pub struct ClientEngine {
    pub key: Arc<OnceLock<TahiniChannelKey>>,
}

#[derive(Clone)]
pub struct ServerEngine {
    pub key: Arc<OnceLock<TahiniChannelKey>>,
    pub passthrough: Arc<OnceLock<bool>>,
    pub client_map: ClientMap,
}

impl ServerEngine {
    pub fn set_session_key(&self, client_id: usize) -> Result<(), String> {
        let mut map_lock = self
            .client_map
            .try_write()
            .map_err(|_| "Couldn't get a lock on the session map".to_string())?;
        match map_lock.remove(&ClientId::from(client_id)) {
            None => Err("Client ID not found in map".to_string()),
            Some(key) => self
                .key
                .set(key)
                .map_err(|_| "Key was already set for this session".to_string()),
        }
    }
}

#[derive(Clone)]
pub enum KeyEngine {
    Client(ClientEngine),
    Server(ServerEngine),
}

impl KeyEngine {
    pub(crate) fn new_client() -> Self {
        KeyEngine::Client(ClientEngine {
            key: Arc::new(OnceLock::new()),
        })
    }

    pub(crate) fn new_server(client_map: ClientMap) -> Self {
        KeyEngine::Server(ServerEngine {
            key: Arc::new(OnceLock::new()),
            passthrough: Arc::new(OnceLock::new()),
            client_map,
        })
    }

    ///Gets the current session key if it exists
    pub(crate) fn get_key(&self) -> Option<&TahiniChannelKey> {
        match self {
            Self::Client(ref client) => client.key.get(),
            Self::Server(ref server) => server.key.get(),
        }
    }

    ///Sets the key for the current underlying channel
    pub fn set_key(&self, key: TahiniChannelKey) -> Result<(), TahiniChannelKey> {
        match self {
            Self::Client(ref client) => client.key.set(key),
            Self::Server(ref server) => server.key.set(key),
        }
    }

    ///Handles skipping encryption under the following logic:
    ///- Clients always encrypt if the key is set
    ///- Servers only encrypt with a set key after the return path of the attestation handshake.
    ///
    ///This means that for the server variant, we can immediately set the flag as the first time it
    ///is read is during the attestation handshake.
    ///For the client, we can always return a set flag as the key is only set after the handshake
    ///completes.
    ///
    ///To avoid acquiring an additional lock, we do not check if the key is set here.
    ///The invokation sites of this method apply the above key context.
    pub(crate) fn passthrough(&self) -> Option<bool> {
        match self {
            Self::Server(ref server) => match server.passthrough.get() {
                //Flag unset, we set before returning
                None => {
                    let _ = server.passthrough.set(true);
                    None
                }
                //Flag already set, we just propagate it
                Some(_) => Some(true),
            },
            //Client
            Self::Client(_) => Some(true),
        }
    }
}

pin_project! {
pub struct TahiniTransport<S, Item, SinkItem, Codec> {
        #[pin]
        pub(crate) transport:
            Transport<S, Item, SinkItem, TahiniEncryptionLayer<Item, SinkItem, Codec>>,
        pub key_engine: KeyEngine,
    }
}

pub trait TahiniTransportTrait<SinkItem, Item> {
    type InnerChannelType: TransportTrait<SinkItem, Item>;

    fn get_engine(&self) -> KeyEngine;

    fn get_inner(self) -> Self::InnerChannelType;
}

impl<S, Item, SinkItem, Codec> TahiniTransportTrait<SinkItem, Item>
    for TahiniTransport<S, Item, SinkItem, Codec>
where
    S: tokio::io::AsyncWrite + tokio::io::AsyncRead,
    Codec: Serializer<SinkItem> + Deserializer<Item>,
    Item: for<'de> Deserialize<'de> + Debug,
    SinkItem: Serialize,
{
    type InnerChannelType =
        Transport<S, Item, SinkItem, TahiniEncryptionLayer<Item, SinkItem, Codec>>;

    fn get_engine(&self) -> KeyEngine {
        self.key_engine.clone()
    }

    fn get_inner(self) -> Self::InnerChannelType {
        self.transport
    }
}

//FIXME: Encryption should only exist if attestation is required.
fn new_tahini_transport<'a, S, Item, SinkItem, Codec>(
    framed_io: Framed<S, LengthDelimitedCodec>,
    codec: Codec,
    engine: KeyEngine,
) -> TahiniTransport<S, Item, SinkItem, Codec>
where
    S: tokio::io::AsyncWrite + tokio::io::AsyncRead,
    Item: for<'de> Deserialize<'de> + Debug,
    SinkItem: Serialize,
    Codec: Serializer<SinkItem> + Deserializer<Item>,
{
    let encryption_layer: TahiniEncryptionLayer<Item, SinkItem, Codec> =
        TahiniEncryptionLayer::new(codec, engine.clone());

    TahiniTransport {
        transport: tarpc::serde_transport::new(framed_io, encryption_layer),
        key_engine: engine,
    }
}

pub fn new_tahini_client_transport<'a, S, Item, SinkItem, Codec>(
    framed_io: Framed<S, LengthDelimitedCodec>,
    codec: Codec,
) -> TahiniTransport<S, Item, SinkItem, Codec>
where
    S: tokio::io::AsyncWrite + tokio::io::AsyncRead,
    Item: for<'de> Deserialize<'de> + Debug,
    SinkItem: Serialize,
    Codec: Serializer<SinkItem> + Deserializer<Item>,
{
    let engine = KeyEngine::new_client();
    new_tahini_transport(framed_io, codec, engine)
}

pub fn new_tahini_server_transport<'a, S, Item, SinkItem, Codec>(
    framed_io: Framed<S, LengthDelimitedCodec>,
    codec: Codec,
    client_map: ClientMap,
) -> TahiniTransport<S, Item, SinkItem, Codec>
where
    S: tokio::io::AsyncWrite + tokio::io::AsyncRead,
    Item: for<'de> Deserialize<'de> + Debug,
    SinkItem: Serialize,
    Codec: Serializer<SinkItem> + Deserializer<Item>,
{
    let engine = KeyEngine::new_server(client_map);
    new_tahini_transport(framed_io, codec, engine)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializedCipher {
    bytes: Vec<u8>,
    nonce: [u8; 12],
}

//FIXME: Encryption should only exist if attestation is required.
pin_project! {
    pub struct TahiniEncryptionLayer<Item, SinkItem, C>
    {
        #[pin]
        inner_channel: C,
        item: PhantomData<Item>,
        sink: PhantomData<SinkItem>,
        key_state: KeyEngine,
    }
}

impl<C, Item, SinkItem> TahiniEncryptionLayer<Item, SinkItem, C>
where
    C: Serializer<SinkItem> + Deserializer<Item>,
{
    pub(crate) fn new(codec: C, engine: KeyEngine) -> Self {
        Self {
            inner_channel: codec,
            item: PhantomData,
            sink: PhantomData,
            key_state: engine,
        }
    }
}

pub enum TahiniChannelLayerError {
    InnerError(std::io::Error),
    WrapperError(std::io::Error),
}

impl TahiniChannelLayerError {
    pub fn wrapper_err(s: &str) -> Self {
        TahiniChannelLayerError::WrapperError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            s.to_string(),
        ))
    }
}

impl From<TahiniChannelLayerError> for std::io::Error {
    fn from(value: TahiniChannelLayerError) -> Self {
        match value {
            TahiniChannelLayerError::InnerError(inner) => inner,
            TahiniChannelLayerError::WrapperError(wrapper) => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, wrapper)
            }
        }
    }
}

impl<C, Item, SinkItem> Serializer<SinkItem> for TahiniEncryptionLayer<Item, SinkItem, C>
where
    C: Serializer<SinkItem>,
    SinkItem: Serialize,
{
    type Error = TahiniChannelLayerError;

    fn serialize(
        self: std::pin::Pin<&mut Self>,
        item: &SinkItem,
    ) -> Result<tokio_util::bytes::Bytes, Self::Error> {
        let start_k = Instant::now();
        let key_engine = self.key_state.clone();
        let key_opt = key_engine.get_key();
        let elapsed_k = start_k.elapsed();


        match key_opt {
            None => C::serialize(self.project().inner_channel, item)
                .map_err(|_| TahiniChannelLayerError::wrapper_err("Keyshare ser error")),
            Some(key) => match key_engine.passthrough() {
                None => {
                    return C::serialize(self.project().inner_channel, item)
                        .map_err(|_| TahiniChannelLayerError::wrapper_err("Keyshare ser error"));
                }
                Some(_) => {
                    let mut inner_codec = self.project().inner_channel;
                    let res = C::serialize(inner_codec.as_mut(), item).map_err(|_| {
                        TahiniChannelLayerError::wrapper_err("Payload serialization error")
                    })?;

                    let enc_start = Instant::now();

                    let mut cipher_buf = Vec::from(res);
                    println!("cipher buf is {:?}", cipher_buf);
                    let nonce = key
                        .seal_in_place_append_tag(Aad::empty(), &mut cipher_buf)
                        .map_err(|_| TahiniChannelLayerError::wrapper_err("Encryption error"))?;
                    let nonce = nonce.as_ref();
                    cipher_buf.extend_from_slice(nonce);
                    let end_end = enc_start.elapsed();
                    let res = Bytes::from(cipher_buf);
                    let total_enc_time = end_end + elapsed_k;
                    println!("Encryption time: {:?}", total_enc_time);

                    // let encrypted_struct = SerializedCipher {
                    //     bytes: cipher_buf,
                    //     nonce: *nonce,
                    // };
                    // let encrypted_serialized =
                    //     serde_json::to_vec(&encrypted_struct).map_err(|_| {
                    //         TahiniChannelLayerError::wrapper_err("Ciphertext serialization error")
                    //     })?;
                    Ok(res)
                }
            },
        }
    }
}

impl<'de, C, Item, SinkItem> Deserializer<Item> for TahiniEncryptionLayer<Item, SinkItem, C>
where
    C: Deserializer<Item>,
    Item: Deserialize<'de> + Debug,
{
    type Error = TahiniChannelLayerError;
    fn deserialize(
        self: std::pin::Pin<&mut Self>,
        src: &tokio_util::bytes::BytesMut,
    ) -> Result<Item, Self::Error> {
        let start_k = Instant::now();
        let arc_cloned = self.key_state.clone();
        let key_opt = arc_cloned.get_key();
        let elapsed_k = start_k.elapsed();

        // match self.encrypt {
        //     false => key_opt = None,
        //     true => ()
        // }
        match key_opt {
            None => {
                let a = C::deserialize(self.project().inner_channel, src).map_err(|_| {
                    TahiniChannelLayerError::wrapper_err("Remote Keyshare deserialization error");
                });
                a.map_err(|_| {
                    TahiniChannelLayerError::wrapper_err(
                        "Failed at deserializing the remote key share",
                    )
                })
            }
            Some(key) => {
                // let ciphertext: SerializedCipher = serde_json::from_slice(src).map_err(|_| {
                //     TahiniChannelLayerError::wrapper_err("Ciphertext deserialization error")
                // })?;

                let dec_start = Instant::now();
                let (cipher, nonce) = src.split_at(src.len()-NONCE_LEN);

                // let mut cipher = BytesMut::from(cipher);

                let nonce = Nonce::from(&<&[u8] as TryInto<[u8;12]>>::try_into(nonce).expect("Malformed nonce"));


                let mut cipher : BytesMut = cipher[..].into();
                let plaintext : &[u8] = key
                    .open_in_place(nonce, Aad::empty(), &mut cipher)
                    .map_err(|_| TahiniChannelLayerError::wrapper_err("Decryption error"))?;

                let end_end = dec_start.elapsed();

                let plaintext_length = plaintext.len();
                unsafe {
                    cipher.set_len(plaintext_length);
                }
                let total_dec_time = end_end + elapsed_k;
                println!("Decryption time: {:?}", total_dec_time);
                let res = C::deserialize(self.project().inner_channel, &cipher).map_err(
                    |_| {
                        TahiniChannelLayerError::wrapper_err(
                            "Plaintext payload deserialization error",
                        )
                    },
                )?;
                Ok(res)
            }
        }
    }
}
