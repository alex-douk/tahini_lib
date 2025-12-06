use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::Poll;

use aws_lc_rs::aead::RandomizedNonceKey;

use hoodini_core::types::ClientId;
//FIXME: Hide this behind an attestation flag
use hoodini_server::get_key_for_client;

use crate::{enums::TahiniSafeWrapper, traits::TahiniType};
use futures::{FutureExt, Sink, Stream};
use pin_project_lite::pin_project;
use tarpc::context::Context;
use tarpc::server::BaseChannel as TarpcBaseChannel;
use tarpc::server::Channel as TarpcChannel;
use tarpc::server::Serve as TarpcServe;
use tarpc::server::{Config, TrackedRequest};
use tarpc::{ChannelError, ClientMessage, Response, ServerError, Transport};

///Async-safe mapping between sidecar-provided ClientIds and their associated AES session keys.
pub type ClientMap = Arc<RwLock<HashMap<ClientId, RandomizedNonceKey>>>;

pub trait TahiniChannel
where
    Self: Sized,
{
    type Req: TahiniType;
    type Resp: TahiniType;
    type Transport: Transport<Response<TahiniSafeWrapper<Self::Resp>>, ClientMessage<Self::Req>>;

    fn config(&self) -> &Config;
    fn in_flight_requests(&self) -> usize;

    fn transport(&self) -> &Self::Transport;

    fn execute<S>(self, serve: S) -> impl Stream<Item = impl Future<Output = ()>>
    where
        S: TahiniServe<Req = Self::Req, Resp = Self::Resp> + Clone;
}

pin_project! {
    pub struct TahiniBaseChannel<Req, Resp, Trans>
    where
        Req: TahiniType,
        Resp: TahiniType,
        Trans: tarpc::Transport<Response<TahiniSafeWrapper<Resp>>, ClientMessage<Req>>
    {
        #[pin]
        channel: TarpcBaseChannel<Req, TahiniSafeWrapper<Resp>, Trans>,
    }
}

impl<Req, Resp, Trans> TahiniBaseChannel<Req, Resp, Trans>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: tarpc::Transport<Response<TahiniSafeWrapper<Resp>>, ClientMessage<Req>>,
{
    pub fn new(config: Config, transport: Trans) -> Self {
        Self {
            channel: TarpcBaseChannel::new(config, transport),
        }
    }
    pub fn with_defaults(transport: Trans) -> Self {
        Self {
            channel: TarpcBaseChannel::with_defaults(transport),
        }
    }
}

impl<Req, Resp, Trans> TahiniChannel for TahiniBaseChannel<Req, Resp, Trans>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: Transport<Response<TahiniSafeWrapper<Resp>>, ClientMessage<Req>>,
{
    type Req = Req;
    type Resp = Resp;
    type Transport = Trans;

    fn config(&self) -> &Config {
        self.channel.config()
    }

    fn in_flight_requests(&self) -> usize {
        self.channel.in_flight_requests()
    }

    fn transport(&self) -> &Self::Transport {
        self.channel.transport()
    }

    fn execute<S>(self, serve: S) -> impl Stream<Item = impl Future<Output = ()>>
    where
        Self: Sized,
        S: TahiniServe<Req = Self::Req, Resp = Self::Resp> + Clone,
    {
        self.channel
            .execute(ServeAdapter::new(serve))
    }
}

impl<Req, Resp, Trans> Sink<Response<TahiniSafeWrapper<Resp>>>
    for TahiniBaseChannel<Req, Resp, Trans>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: Transport<
        Response<TahiniSafeWrapper<Resp>>,
        ClientMessage<Req>,
    >,
    // ChannelType: Transport<Response<TahiniSafeWrapper<Resp>>, ClientMessage<Req>>,
    // ChannelType::Error: Error,
{
    type Error = ChannelError<Trans::TransportError>;
    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        TarpcBaseChannel::poll_ready(self.project().channel, cx)
    }
    fn start_send(
        self: Pin<&mut Self>,
        item: Response<TahiniSafeWrapper<Resp>>,
    ) -> Result<(), Self::Error> {
        TarpcBaseChannel::start_send(self.project().channel, item)
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        TarpcBaseChannel::poll_flush(self.project().channel, cx)
    }
    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        TarpcBaseChannel::poll_close(self.project().channel, cx)
    }
}

//
impl<Req, Resp, Trans> Stream for TahiniBaseChannel<Req, Resp, Trans>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: tarpc::Transport<
        Response<TahiniSafeWrapper<Resp>>,
        ClientMessage<Req>,
    >,
    // ChannelType: Transport<Response<TahiniSafeWrapper<Resp>>, ClientMessage<Req>>,
    // ChannelType::Error: Error,
{
    type Item = Result<TrackedRequest<Req>, ChannelError<Trans::TransportError>>;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        TarpcBaseChannel::poll_next(self.project().channel, cx)
    }
}
// // mimics `tarpc::server::Serve`
#[allow(async_fn_in_trait)]
pub trait TahiniServe {
    /// Type of request.
    type Req: TahiniType;

    /// Type of response.
    type Resp: TahiniType + Send;

    /// Extracts a method name from the request.
    fn method(&self, _request: &Self::Req) -> Option<&'static str> {
        None
    }

    /// Responds to a single request.
    async fn serve(self, ctx: Context, req: Self::Req) -> Result<Self::Resp, ServerError>;
}

//FIXME: Encryption should only exist if attestation is required.
#[derive(Clone)]
struct ServeAdapter<T: TahiniServe> {
    tahini_serve: T,
}
impl<T: TahiniServe> ServeAdapter<T> {
    fn new(tahini_serve: T) -> Self {
        Self {
            tahini_serve,
        }
    }
}

pub fn get_session_key_for_client(client_id: usize) -> RandomizedNonceKey {
    let client_id = ClientId::from(client_id);
    get_key_for_client(&client_id)
}

impl<T: TahiniServe> TarpcServe for ServeAdapter<T> {
    type Req = T::Req;
    type Resp = TahiniSafeWrapper<T::Resp>;

    async fn serve(self, ctx: Context, req: Self::Req) -> Result<Self::Resp, ServerError> {
        self.tahini_serve
            .serve(ctx, req)
            .map(|res| res.map(TahiniSafeWrapper::new))
            .await
    }
    // fn method(&self, request: &Self::Req) -> Option<&'static str> {
    //     Some(T::Req::enum_name(request))
    // }
}
