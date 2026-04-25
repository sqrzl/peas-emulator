mod common;

use common::interop::{
    auth_disabled, body_bytes, body_text, call, request, temp_storage, AZURE_VERSION,
};
use hyper::StatusCode;

#[tokio::test(flavor = "multi_thread")]
async fn should_round_trip_block_blob_given_container_exists_when_using_basic_blob_operations() {
    let storage = temp_storage();
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure?restype=container",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    let response = call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure/hello.txt",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-blob-type", "BlockBlob"),
                ("content-type", "text/plain"),
            ],
            b"azure smoke",
        )
        .await,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = body_bytes(
        call(
            storage,
            auth_disabled(),
            request(
                "GET",
                "http://localhost/devstoreaccount1/interop-azure/hello.txt",
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert_eq!(body, b"azure smoke");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_custom_metadata_given_blob_metadata_headers_when_requesting_blob_head() {
    let storage = temp_storage();
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure?restype=container",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure/hello.txt",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-blob-type", "BlockBlob"),
                ("x-ms-meta-owner", "sdk"),
            ],
            b"azure smoke",
        )
        .await,
    )
    .await;
    let response = call(
        storage,
        auth_disabled(),
        request(
            "HEAD",
            "http://localhost/devstoreaccount1/interop-azure/hello.txt",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    assert_eq!(
        response
            .headers()
            .get("x-ms-meta-owner")
            .and_then(|value| value.to_str().ok()),
        Some("sdk")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_requested_slice_given_range_header_when_reading_blob_content() {
    let storage = temp_storage();
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure?restype=container",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure/hello.txt",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-blob-type", "BlockBlob"),
            ],
            b"azure smoke",
        )
        .await,
    )
    .await;
    let body = body_bytes(
        call(
            storage,
            auth_disabled(),
            request(
                "GET",
                "http://localhost/devstoreaccount1/interop-azure/hello.txt",
                &[("x-ms-version", AZURE_VERSION), ("x-ms-range", "bytes=0-4")],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert_eq!(body, b"azure");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_list_containers_and_blobs_given_stored_objects_when_querying_azure_lists() {
    let storage = temp_storage();
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure?restype=container",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/interop-azure/hello.txt",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-blob-type", "BlockBlob"),
            ],
            b"azure smoke",
        )
        .await,
    )
    .await;
    let containers = body_text(
        call(
            storage.clone(),
            auth_disabled(),
            request(
                "GET",
                "http://localhost/devstoreaccount1?comp=list",
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert!(containers.contains("interop-azure"));

    let blobs = body_text(
        call(
            storage,
            auth_disabled(),
            request(
                "GET",
                "http://localhost/devstoreaccount1/interop-azure?restype=container&comp=list&prefix=hell",
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert!(blobs.contains("hello.txt"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_persist_append_and_page_blob_writes_given_specialized_blob_types_when_uploading_content(
) {
    let storage = temp_storage();
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state?restype=container",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/events.log",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-blob-type", "AppendBlob"),
            ],
            b"hello",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/events.log?comp=appendblock",
            &[("x-ms-version", AZURE_VERSION)],
            b" azure",
        )
        .await,
    )
    .await;
    let append = body_bytes(
        call(
            storage.clone(),
            auth_disabled(),
            request(
                "GET",
                "http://localhost/devstoreaccount1/state/events.log",
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert_eq!(append, b"hello azure");

    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/page.bin",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-blob-type", "PageBlob"),
                ("x-ms-blob-content-length", "512"),
            ],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/page.bin?comp=page",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-range", "bytes=0-511"),
            ],
            &vec![b'b'; 512],
        )
        .await,
    )
    .await;
    let page = body_bytes(
        call(
            storage,
            auth_disabled(),
            request(
                "GET",
                "http://localhost/devstoreaccount1/state/page.bin",
                &[("x-ms-version", AZURE_VERSION), ("x-ms-range", "bytes=0-7")],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert_eq!(page, b"bbbbbbbb");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_enforce_leases_and_retention_given_snapshot_and_immutability_operations_when_deleting_blob(
) {
    let storage = temp_storage();
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state?restype=container",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/lease.txt",
            &[("x-ms-version", AZURE_VERSION)],
            b"initial",
        )
        .await,
    )
    .await;

    let lease = call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/lease.txt?comp=lease",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
            ],
            b"",
        )
        .await,
    )
    .await;
    let lease_id = lease
        .headers()
        .get("x-ms-lease-id")
        .and_then(|value| value.to_str().ok())
        .expect("lease id should exist")
        .to_string();

    assert_eq!(
        call(
            storage.clone(),
            auth_disabled(),
            request(
                "DELETE",
                "http://localhost/devstoreaccount1/state/lease.txt",
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await
        .status(),
        StatusCode::PRECONDITION_FAILED
    );

    let release = call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/lease.txt?comp=lease",
            &[
                ("x-ms-version", AZURE_VERSION),
                ("x-ms-lease-action", "release"),
                ("x-ms-lease-id", &lease_id),
            ],
            b"",
        )
        .await,
    )
    .await;
    assert_eq!(release.status(), StatusCode::OK);

    let snapshot = call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/lease.txt?comp=snapshot",
            &[("x-ms-version", AZURE_VERSION)],
            b"",
        )
        .await,
    )
    .await;
    let snapshot_time = snapshot
        .headers()
        .get("x-ms-snapshot")
        .and_then(|value| value.to_str().ok())
        .expect("snapshot should exist")
        .to_string();

    let snap_body = body_bytes(
        call(
            storage.clone(),
            auth_disabled(),
            request(
                "GET",
                &format!(
                    "http://localhost/devstoreaccount1/state/lease.txt?snapshot={snapshot_time}"
                ),
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await,
    )
    .await;
    assert_eq!(snap_body, b"initial");

    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/lease.txt?comp=immutabilitypolicy",
            &[
                ("x-ms-version", AZURE_VERSION),
                (
                    "x-ms-immutability-policy-until-date",
                    "2099-01-01T00:00:00Z",
                ),
                ("x-ms-immutability-policy-mode", "Unlocked"),
            ],
            b"",
        )
        .await,
    )
    .await;
    call(
        storage.clone(),
        auth_disabled(),
        request(
            "PUT",
            "http://localhost/devstoreaccount1/state/lease.txt?comp=legalhold",
            &[("x-ms-version", AZURE_VERSION), ("x-ms-legal-hold", "true")],
            b"",
        )
        .await,
    )
    .await;
    assert_eq!(
        call(
            storage,
            auth_disabled(),
            request(
                "DELETE",
                "http://localhost/devstoreaccount1/state/lease.txt",
                &[("x-ms-version", AZURE_VERSION)],
                b"",
            )
            .await,
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
}
