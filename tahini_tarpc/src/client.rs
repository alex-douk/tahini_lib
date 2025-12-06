use crate::context::TahiniContext;
use crate::enums::TahiniSafeWrapper;
use crate::traits::{Fromable, TahiniTransformInto, TahiniType};
use pin_project_lite::pin_project;
use std::future::Future;
use tarpc::client::Channel as TarpcChannel;
use tarpc::client::NewClient as TarpcNewClient;
use tarpc::client::RequestDispatch as TarpcRequestDispatch;
use tarpc::client::{Config, RpcError};
use tarpc::{context, ChannelError, ClientMessage, Response, Transport};


#[derive(Clone)]
pub struct TahiniChannel<Req: TahiniType, Resp: TahiniType> {
    channel: TarpcChannel<TahiniSafeWrapper<Req>, Resp>,
}

impl<'a, Req: TahiniType, Resp: TahiniType> TahiniChannel<Req, Resp> {
    pub(crate) fn new(
        channel: TarpcChannel<TahiniSafeWrapper<Req>, Resp>,
    ) -> Self {
        Self { channel }
    }
}

pub trait TahiniStubWrapper {}

// mimics `tarpc::client::Stub`.
#[allow(async_fn_in_trait)]
pub trait TahiniStub {
    type Req: TahiniType;

    /// The service response type.
    type Resp: TahiniType;

    /// Calls a remote service.
    async fn call(
        &self,
        ctx: context::Context,
        request_name: &'static str,
        request: Self::Req,
    ) -> Result<Self::Resp, RpcError>;

    async fn transform_with_fromable<
        'a,
        InputRemoteType: TahiniType,
        InputLocalType: TahiniTransformInto<InputRemoteType> + 'static,
        EgressTransform: FnOnce(InputRemoteType) -> Self::Req,
        OutputRemoteType: TahiniType,
        IngressTransform: FnOnce(Self::Resp) -> Fromable<OutputRemoteType>,
    >(
        &'a self,
        ctx: context::Context,
        request_name: &'static str,
        tahini_context_builder: &'static str,
        local_input: InputLocalType,
        input_transform: EgressTransform,
        output_transform: IngressTransform,
    ) -> Result<Fromable<OutputRemoteType>, RpcError>;

    async fn transform_only_egress<
        'a,
        InputRemoteType: TahiniType,
        InputLocalType: TahiniTransformInto<InputRemoteType> + 'static,
        EgressTransform: FnOnce(InputRemoteType) -> Self::Req,
    >(
        &'a self,
        ctx: context::Context,
        request_name: &'static str,
        tahini_context_builder: &'static str,
        local_input: InputLocalType,
        input_transform: EgressTransform,
    ) -> Result<Self::Resp, RpcError>;

}

impl<Req: TahiniType, Resp: TahiniType> TahiniStub for TahiniChannel<Req, Resp> {
    type Req = Req;
    type Resp = Resp;

    async fn call(
        &self,
        ctx: context::Context,
        request_name: &'static str,
        request: Req,
    ) -> Result<Self::Resp, RpcError> {
        let request = TahiniSafeWrapper::new(request);
        let response = self.channel.call(ctx, request_name, request).await?;
        Ok(response)
    }
    async fn transform_with_fromable<
        'a,
        InputRemoteType: TahiniType,
        InputLocalType: TahiniTransformInto<InputRemoteType> + 'static,
        EgressTransform: FnOnce(InputRemoteType) -> Self::Req,
        OutputRemoteType: TahiniType,
        IngressTransform: FnOnce(Self::Resp) -> Fromable<OutputRemoteType>,
    >(
        &'a self,
        ctx: context::Context,
        request_name: &'static str,
        tahini_context_builder: &'static str,
        local_input: InputLocalType,
        input_transform: EgressTransform,
        output_transform: IngressTransform,
    ) -> Result<Fromable<OutputRemoteType>, RpcError> {
        let splitted: Vec<_> = tahini_context_builder.split(".").collect();
        assert_eq!(splitted.len(), 2, "Checking if request_name is of length 2");
        let (service, rpc) = (splitted[0], splitted[1]);
        let tahini_context = TahiniContext::new(service, rpc);
        let remote_input: InputRemoteType = local_input
            .transform_into(&tahini_context)
            .expect("Policy didn't allow to transform the input for this RPC");
        let wrapped = input_transform(remote_input);
        let resp = self.call(ctx, request_name, wrapped).await?;
        let mut unwrapped: Fromable<OutputRemoteType> = output_transform(resp);
        unwrapped.add_context(tahini_context);
        Ok(unwrapped)
    }
    async fn transform_only_egress<
        'a,
        InputRemoteType: TahiniType,
        InputLocalType: TahiniTransformInto<InputRemoteType> + 'static,
        EgressTransform: FnOnce(InputRemoteType) -> Self::Req,
    >(
        &'a self,
        ctx: context::Context,
        request_name: &'static str,
        tahini_context_builder: &'static str,
        local_input: InputLocalType,
        input_transform: EgressTransform,
    ) -> Result<Self::Resp, RpcError> {
        let splitted: Vec<_> = tahini_context_builder.split(".").collect();
        assert_eq!(splitted.len(), 2, "Checking if request_name is of length 2");
        let (service, rpc) = (splitted[0], splitted[1]);
        let tahini_context = TahiniContext::new(service, rpc);
        let remote_input: InputRemoteType = local_input
            .transform_into(&tahini_context)
            .expect("Policy didn't allow to transform the input for this RPC");
        let wrapped = input_transform(remote_input);
        self.call(ctx, request_name, wrapped).await
    }

}

pin_project! {
    pub struct TahiniRequestDispatch<Req: TahiniType, Resp: TahiniType, Trans>
        where
            Trans: tarpc::Transport<ClientMessage<TahiniSafeWrapper<Req>>, Response<Resp>>
    {
        #[pin]
        pub(super) dispatch: TarpcRequestDispatch<TahiniSafeWrapper<Req>, Resp, Trans>,
    }

}
//What is the current issue? The dispatch leaks the types.

impl<Req: TahiniType, Resp: TahiniType, Trans> TahiniRequestDispatch<Req, Resp, Trans>
where
    Trans: tarpc::Transport<ClientMessage<TahiniSafeWrapper<Req>>, Response<Resp>>,
{
    pub(crate) fn new(dispatch: TarpcRequestDispatch<TahiniSafeWrapper<Req>, Resp, Trans>) -> Self {
        Self { dispatch }
    }
}

impl<Req, Resp, Trans> Future for TahiniRequestDispatch<Req, Resp, Trans>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: Transport<ClientMessage<TahiniSafeWrapper<Req>>, Response<Resp>> + Send,
{
    type Output = Result<(), ChannelError<Trans::TransportError>>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        this.dispatch.poll(cx)
    }
}

pub struct TahiniNewClient<C, D> {
    pub client: C,
    pub dispatch: D,
}
impl<E, C, Req, Resp, Trans> TahiniNewClient<C, TahiniRequestDispatch<Req, Resp, Trans>>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: Transport<ClientMessage<TahiniSafeWrapper<Req>>, Response<Resp>> + Send + 'static,
    // Trans: TahiniTransport<Req, Resp> + 'static,
    TahiniRequestDispatch<Req, Resp, Trans>: Future<Output = Result<(), E>> + Send + 'static,
    E: std::error::Error + Send + Sync + 'static,
    C: TahiniStub,
{
    pub fn spawn(self) -> C {
        let client = TarpcNewClient {
            client: self.client,
            dispatch: self.dispatch,
        };
        let client = client.spawn();
        client
    }
}

//TODO(douk): Generated client-side code basically extracts the channel from within
//this new client, and then recomponses itself into a TahiniNewClient.
//Might be a more elegant way to do that with a nice API with generics over a trait.
pub fn new<Req, Resp, Trans>(
    config: Config,
    transport: Trans,
) -> TahiniNewClient<
    TahiniChannel<Req, Resp>,
    TahiniRequestDispatch<Req, Resp, Trans>,
>
where
    Req: TahiniType,
    Resp: TahiniType,
    Trans: tarpc::Transport<ClientMessage<TahiniSafeWrapper<Req>>, Response<Resp>>,
{
    // let engine = transport.get_engine();
    let client = tarpc::client::new(config, transport);
    TahiniNewClient {
        client: TahiniChannel::new(client.client),
        dispatch: TahiniRequestDispatch::new(client.dispatch),
    }
}
