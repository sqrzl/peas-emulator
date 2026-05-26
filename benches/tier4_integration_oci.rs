use bytes::Bytes;
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, SamplingMode,
    Throughput,
};
use hyper::{Body, Request, StatusCode};
use tokio::runtime::{Builder, Runtime};

#[path = "support/criterion_config.rs"]
mod criterion_config;

#[path = "support/mod.rs"]
mod support;

use support::live_server::{auth_disabled, LiveServer};

const TENANT: &str = "tenant";

fn build_runtime() -> Runtime {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime should build")
}

async fn create_bucket(server: &LiveServer, bucket: &str) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("{}/n/{}/b", server.base_url, TENANT))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": bucket,
                "compartmentId": "ignored"
            })
            .to_string(),
        ))
        .expect("bucket create request should build");
    let response = server.request(request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

fn bench_put_object(c: &mut Criterion) {
    let runtime = build_runtime();
    let server = runtime.block_on(LiveServer::start_api(auth_disabled()));
    let bucket = "tier4-oci-put";
    runtime.block_on(create_bucket(&server, bucket));
    let payload = Bytes::from_static(b"tier4 oci payload");
    let object_url = format!("{}/n/{}/b/{}/o/hello.txt", server.base_url, TENANT, bucket);

    let mut group = c.benchmark_group("tier4_integration_oci_put_object");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function(BenchmarkId::new("put_object", payload.len()), |b| {
        b.iter(|| {
            let request = Request::builder()
                .method("PUT")
                .uri(&object_url)
                .header("content-type", "text/plain")
                .body(Body::from(payload.clone()))
                .expect("object put request should build");
            let response = runtime.block_on(server.request(request));
            assert_eq!(response.status(), StatusCode::OK);
            black_box(response.headers().get("etag").cloned());
        })
    });
    group.finish();
}

fn bench_get_object(c: &mut Criterion) {
    let runtime = build_runtime();
    let server = runtime.block_on(LiveServer::start_api(auth_disabled()));
    let bucket = "tier4-oci-get";
    runtime.block_on(create_bucket(&server, bucket));
    let payload = Bytes::from(vec![b'o'; 64 * 1024]);
    let object_url = format!("{}/n/{}/b/{}/o/hello.txt", server.base_url, TENANT, bucket);

    runtime.block_on(async {
        let request = Request::builder()
            .method("PUT")
            .uri(&object_url)
            .header("content-type", "text/plain")
            .body(Body::from(payload.clone()))
            .expect("seed put request should build");
        let response = server.request(request).await;
        assert_eq!(response.status(), StatusCode::OK);
    });

    let mut group = c.benchmark_group("tier4_integration_oci_get_object");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function(BenchmarkId::new("get_object", payload.len()), |b| {
        b.iter_batched(
            || {
                Request::builder()
                    .method("GET")
                    .uri(&object_url)
                    .body(Body::empty())
                    .expect("object get request should build")
            },
            |request| {
                let body = runtime.block_on(server.response_bytes(request));
                assert_eq!(body.as_slice(), payload.as_ref());
                black_box(body);
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_multipart_upload(c: &mut Criterion) {
    let runtime = build_runtime();
    let server = runtime.block_on(LiveServer::start_api(auth_disabled()));
    let bucket = "tier4-oci-multipart";
    runtime.block_on(create_bucket(&server, bucket));
    let object = "multi.txt";
    let init_url = format!("{}/n/{}/b/{}/u", server.base_url, TENANT, bucket);
    let multipart_url = format!("{}/n/{}/b/{}/u/{}", server.base_url, TENANT, bucket, object);
    let part_one = Bytes::from(vec![b'a'; 4096]);
    let part_two = Bytes::from(vec![b'b'; 4096]);

    let mut group = c.benchmark_group("tier4_integration_oci_multipart_upload");
    group.sampling_mode(SamplingMode::Flat);
    group.throughput(Throughput::Bytes((part_one.len() + part_two.len()) as u64));
    group.bench_function(
        BenchmarkId::new("multipart_upload", part_one.len() + part_two.len()),
        |b| {
            b.iter(|| {
                let init_request = Request::builder()
                    .method("POST")
                    .uri(&init_url)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "object": object,
                            "contentType": "text/plain",
                            "metadata": { "owner": "bench" },
                            "storageTier": "InfrequentAccess"
                        })
                        .to_string(),
                    ))
                    .expect("multipart init request should build");
                let init_body = runtime.block_on(server.response_bytes(init_request));
                let init_json: serde_json::Value =
                    serde_json::from_slice(&init_body).expect("multipart init body should parse");
                let upload_id = init_json
                    .get("uploadId")
                    .and_then(|value| value.as_str())
                    .expect("multipart upload id should exist")
                    .to_string();

                let part_one_request = Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "{multipart_url}?uploadId={upload_id}&uploadPartNum=1"
                    ))
                    .body(Body::from(part_one.clone()))
                    .expect("multipart part one request should build");
                let part_one_response = runtime.block_on(server.request(part_one_request));
                assert_eq!(part_one_response.status(), StatusCode::OK);
                let etag_one = part_one_response
                    .headers()
                    .get("etag")
                    .and_then(|value| value.to_str().ok())
                    .expect("multipart part one etag should exist")
                    .to_string();

                let part_two_request = Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "{multipart_url}?uploadId={upload_id}&uploadPartNum=2"
                    ))
                    .body(Body::from(part_two.clone()))
                    .expect("multipart part two request should build");
                let part_two_response = runtime.block_on(server.request(part_two_request));
                assert_eq!(part_two_response.status(), StatusCode::OK);
                let etag_two = part_two_response
                    .headers()
                    .get("etag")
                    .and_then(|value| value.to_str().ok())
                    .expect("multipart part two etag should exist")
                    .to_string();

                let commit_request = Request::builder()
                    .method("POST")
                    .uri(format!("{multipart_url}?uploadId={upload_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "partsToCommit": [
                                { "partNum": 1, "etag": etag_one },
                                { "partNum": 2, "etag": etag_two }
                            ]
                        })
                        .to_string(),
                    ))
                    .expect("multipart commit request should build");
                let commit_response = runtime.block_on(server.request(commit_request));
                assert_eq!(commit_response.status(), StatusCode::OK);
                black_box(commit_response.headers().get("etag").cloned());
            })
        },
    );
    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config::criterion_config_for_tier4();
    targets = bench_put_object, bench_get_object, bench_multipart_upload
}
criterion_main!(benches);
