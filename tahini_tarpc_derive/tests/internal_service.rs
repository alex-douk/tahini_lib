use alohomora::bbox::BBox;
use alohomora::context::UnprotectedContext;
use alohomora::policy::{Reason, SimplePolicy};
use alohomora::pure::PrivacyPureRegion;
use alohomora::testing::TestPolicy;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tahini_tarpc::server::{TahiniBaseChannel, TahiniChannel};
use tahini_tarpc::transport::new_tahini_server_transport;
use tahini_tarpc_derive::tahini_service;
use tarpc::context::Context;
use tarpc::tokio_serde::formats::Json;
use tarpc::tokio_util::codec::LengthDelimitedCodec;
use tokio::net::TcpListener;

use futures::future::Future;
use futures::StreamExt;

use tahini_tarpc::transport::new_tahini_client_transport;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MyPolicy {
    pub x: u32,
    pub y: String,
}
impl SimplePolicy for MyPolicy {
    fn simple_name(&self) -> String {
        todo!()
    }
    fn simple_check(&self, _context: &UnprotectedContext, _reason: Reason<'_>) -> bool {
        todo!()
    }
    fn simple_join_direct(&mut self, other: &mut Self) {
        todo!()
    }
}

mod service {
    // Define your tarpc service: this definition is shared between client and server, including
    // definition of MyPolicy.
    #[tahini_tarpc_derive::tahini_service(domain=internal)]
    pub trait MyService {
        async fn lenny(
            name: ::alohomora::bbox::BBox<String, super::TestPolicy<super::MyPolicy>>,
        ) -> ::alohomora::bbox::BBox<usize, super::TestPolicy<super::MyPolicy>>;
    }
}

mod server {
    use super::*;
    use service::MyService;

    // Server that implements the service: this can be only server side.
    #[derive(Clone)]
    pub struct MyServer;
    impl MyService for MyServer {
        async fn lenny(
            self,
            _context: Context,
            name: BBox<String, TestPolicy<MyPolicy>>,
        ) -> BBox<usize, TestPolicy<MyPolicy>> {
            assert_eq!(name.policy().policy().x, 5);
            assert_eq!(name.policy().policy().y, "MyString");

            // Compute len.
            let len = name.discard_box().len();
            println!("LEN {}", len);
            BBox::new(
                len,
                TestPolicy::new(MyPolicy {
                    x: 102,
                    y: String::from("Returned policy"),
                }),
            )
        }
    }

    async fn wait_upon(fut: impl Future<Output = ()> + Send + 'static) {
        fut.await
    }

    pub async fn server() -> Result<String, ()> {
        // Setup for connection
        let listener = TcpListener::bind(&("127.0.0.1", 15003)).await.unwrap();

        loop {
            let (stream, _peer_addr) = listener.accept().await.unwrap();
            println!("Accepted a connection");

            // Building the transport channel
            let codec_builder = LengthDelimitedCodec::builder();
            let framed = codec_builder.new_framed(stream);

            let transport =
                new_tahini_server_transport(framed, Json::default(), Arc::new(RwLock::default()));
            let server = TahiniBaseChannel::with_defaults(transport);

            tokio::spawn(server.execute(MyServer.serve()).for_each(wait_upon));
        }
    }
}

mod client {
    use super::*;

    pub async fn client() -> Result<String, ()> {
        // Establish connection to server.
        let stream = TcpStream::connect("127.0.0.1:15003").await.unwrap();

        let codec_builder = LengthDelimitedCodec::builder();
        let transport =
            new_tahini_client_transport(codec_builder.new_framed(stream), Json::default());

        let active_client = service::TahiniMyServiceClient::new(Default::default(), transport)
            .spawn()
            .await;
        println!("Established a connection");

        // Call service.
        let bbox = BBox::new(
            String::from("My Message"),
            TestPolicy::new(MyPolicy {
                x: 5,
                y: String::from("MyString"),
            }),
        );

        let response = active_client.lenny(tarpc::context::current(), bbox).await;

        // Check output.
        assert!(matches!(response, Ok(_)));
        if let Ok(bbox) = response {
            assert_eq!(bbox.policy().policy().x, 192);
            assert_eq!(bbox.policy().policy().y, "Returned policy");
            assert_eq!(bbox.discard_box(), "My Message".len());
        }

        Ok(String::from("Client successful"))
    }
}

#[tokio::test]
async fn test_internal_rpc() {
    let future1 = server::server();
    let future2 = client::client();
    let mut set = JoinSet::new();
    set.spawn(future1);
    set.spawn(future2);

    while let Some(res) = set.join_next().await {
        // assert_eq!(res.unwrap().unwrap(), "Client successful");
        return set.abort_all();
    }
}
