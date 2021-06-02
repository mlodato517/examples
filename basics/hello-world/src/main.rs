use actix_web::{middleware, web, App, HttpRequest, HttpServer};
use futures::stream::StreamExt;

async fn index(_req: HttpRequest, mut payload: web::Payload) -> String {
    // Commenting out this loop results in the proxy succeeding
    let mut msg_count = 0;
    loop {
        log::info!("Waiting for next message");
        if payload.next().await.is_some() {
            log::info!("Received message");
            msg_count += 1;
        } else {
            break;
        }
    }

    log::info!("Received entire payload");
    msg_count.to_string()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "INFO");
    env_logger::init();

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .default_service(web::route().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::dev::Service;
    use actix_web::{http, test, web, App, Error};

    #[actix_rt::test]
    async fn test_index() -> Result<(), Error> {
        let app = App::new().route("/", web::get().to(index));
        let mut app = test::init_service(app).await;

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = app.call(req).await.unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response_body = match resp.response().body().as_ref() {
            Some(actix_web::body::Body::Bytes(bytes)) => bytes,
            _ => panic!("Response error"),
        };

        assert_eq!(response_body, r##"Hello world!"##);

        Ok(())
    }
}
