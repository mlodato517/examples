use std::net::ToSocketAddrs;

use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use clap::{value_t, Arg};
use futures::stream::StreamExt;
use reqwest::Client;
use tokio::sync::mpsc;
use url::Url;

async fn forward(
    req: HttpRequest,
    mut payload: web::Payload,
    url: web::Data<Url>,
    client: web::Data<Client>,
) -> Result<HttpResponse, Error> {
    let mut new_url = url.get_ref().clone();
    new_url.set_path(req.uri().path());
    new_url.set_query(req.uri().query());

    // TODO: This forwarded implementation is incomplete as it only handles the inofficial
    // X-Forwarded-For header but not the official Forwarded one.
    let forwarded_req = client.request(req.method().clone(), new_url);

    let forwarded_req = if let Some(addr) = req.head().peer_addr {
        forwarded_req.header("x-forwarded-for", format!("{}", addr.ip()))
    } else {
        forwarded_req
    };

    let (tx, rx) = mpsc::unbounded_channel();
    let reqwest_stream = rx.map(|(msg_count, msg)| {
        log::info!("Received message {}", msg_count);
        msg
    });

    let mut msg_count = 0;
    loop {
        log::info!("Waiting for next message");
        if let Some(msg) = payload.next().await {
            log::info!("Sending msg {}", msg_count);
            let _ = tx.send((msg_count, msg));
        } else {
            break;
        }
        msg_count += 1;
    }
    log::info!("Done sending message");

    let stream = reqwest::Body::wrap_stream(reqwest_stream);
    let res = client
        .execute(forwarded_req.body(stream).build().unwrap())
        .await;
    match res {
        Ok(_) => Ok(HttpResponse::Ok().body("Proxied")),
        Err(_) => Ok(HttpResponse::InternalServerError().body("Not proxied")),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let matches = clap::App::new("HTTP Proxy")
        .arg(
            Arg::with_name("listen_addr")
                .takes_value(true)
                .value_name("LISTEN ADDR")
                .index(1)
                .required(true),
        )
        .arg(
            Arg::with_name("listen_port")
                .takes_value(true)
                .value_name("LISTEN PORT")
                .index(2)
                .required(true),
        )
        .arg(
            Arg::with_name("forward_addr")
                .takes_value(true)
                .value_name("FWD ADDR")
                .index(3)
                .required(true),
        )
        .arg(
            Arg::with_name("forward_port")
                .takes_value(true)
                .value_name("FWD PORT")
                .index(4)
                .required(true),
        )
        .get_matches();

    let listen_addr = matches.value_of("listen_addr").unwrap();
    let listen_port = value_t!(matches, "listen_port", u16).unwrap_or_else(|e| e.exit());

    let forwarded_addr = matches.value_of("forward_addr").unwrap();
    let forwarded_port =
        value_t!(matches, "forward_port", u16).unwrap_or_else(|e| e.exit());

    let forward_url = Url::parse(&format!(
        "http://{}",
        (forwarded_addr, forwarded_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap()
    ))
    .unwrap();

    HttpServer::new(move || {
        App::new()
            .data(
                Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap(),
            )
            .data(forward_url.clone())
            .wrap(middleware::Logger::default())
            .default_service(web::route().to(forward))
    })
    .bind((listen_addr, listen_port))?
    .system_exit()
    .run()
    .await
}
