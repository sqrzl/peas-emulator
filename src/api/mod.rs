pub mod buckets;
pub mod server;

use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .configure(buckets::configure),
    );
}
