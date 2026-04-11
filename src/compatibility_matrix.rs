#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    fn known_verifiers() -> HashSet<&'static str> {
        HashSet::from([
            "api::server::tests::bucket_crud_json",
            "api::server::tests::object_upload_download",
            "auth::sigv4::tests::should_verify_valid_sigv4_signature",
            "interop::sdk_smoke::azure_basic",
            "interop::sdk_smoke::azure_list",
            "interop::sdk_smoke::azure_metadata",
            "interop::sdk_smoke::azure_range",
            "interop::sdk_smoke::gcs_basic",
            "interop::sdk_smoke::gcs_json_api",
            "interop::sdk_smoke::gcs_list",
            "interop::sdk_smoke::gcs_metadata",
            "interop::sdk_smoke::gcs_range",
            "interop::sdk_smoke::oci_basic",
            "interop::sdk_smoke::oci_list",
            "interop::sdk_smoke::oci_metadata",
            "interop::sdk_smoke::oci_multipart",
            "interop::sdk_smoke::s3_basic",
            "interop::sdk_smoke::s3_multipart",
            "interop::sdk_smoke::s3_versioning",
            "providers::azure::tests::should_commit_block_blob_from_put_block_list",
            "providers::azure::tests::should_create_list_and_fetch_azure_blobs",
            "providers::azure::tests::should_update_metadata_return_block_list_and_support_ranges",
            "providers::azure::tests::should_validate_azure_shared_key_and_sas_authorization",
            "providers::gcs::tests::should_handle_gcs_bucket_and_object_crud",
            "providers::gcs::tests::should_increment_generation_on_overwrite_and_patch_metageneration",
            "providers::gcs::tests::should_enforce_gcs_generation_and_metageneration_preconditions",
            "providers::gcs::tests::should_return_generation_headers_and_support_ranges",
            "providers::gcs::tests::should_support_gcs_resumable_uploads_and_signed_access",
            "providers::gcs::tests::should_support_gcs_json_api_bucket_and_media_flows",
            "providers::oci::tests::should_round_trip_oci_metadata_and_prefix_listing",
            "providers::oci::tests::should_support_oci_multipart_upload_lifecycle",
            "providers::oci::tests::should_support_oci_namespace_bucket_and_object_flows",
            "providers::oci::tests::should_validate_oci_signature_authorization",
            "server::handlers::auth::tests::should_build_standard_sigv4_canonical_request_with_sorted_query",
            "server::handlers::bucket::tests::should_list_version_history_when_versions_query_is_requested",
            "server::handlers::bucket::tests::should_round_trip_request_payment_website_and_cors_bucket_configs",
            "server::http::tests::should_route_virtual_hosted_style_bucket_requests",
            "services::object::tests::should_list_object_versions_through_service",
            "services::object::tests::should_roundtrip_object_through_service",
        ])
    }

    #[test]
    fn compatibility_matrix_should_use_checked_schema_and_known_verifiers() {
        let matrix: serde_json::Value =
            serde_json::from_str(include_str!("../compatibility-matrix.json"))
                .expect("compatibility matrix should parse");
        let providers = matrix
            .get("providers")
            .and_then(|providers| providers.as_object())
            .expect("providers should be an object");
        let known_verifiers = known_verifiers();

        for (provider_name, operations) in providers {
            let operations = operations
                .as_object()
                .expect("provider operations should be an object");
            for (operation_name, operation) in operations {
                let operation = operation
                    .as_object()
                    .expect("operation entry should be an object");
                let status = operation
                    .get("status")
                    .and_then(|status| status.as_str())
                    .expect("status should be a string");
                assert!(
                    matches!(status, "pass" | "partial" | "missing" | "deferred"),
                    "unexpected compatibility status '{}' for {}.{}",
                    status,
                    provider_name,
                    operation_name
                );

                let verifiers = operation
                    .get("verified_by")
                    .and_then(|value| value.as_array())
                    .expect("verified_by should be an array");
                if status == "pass" {
                    assert!(
                        !verifiers.is_empty(),
                        "pass status for {}.{} must name at least one verifier",
                        provider_name,
                        operation_name
                    );
                    let auth_only_operation = matches!(
                        operation_name.as_str(),
                        "sigv4" | "shared_key_auth" | "sas_auth" | "signed_url_v2" | "request_signing"
                    );
                    if !auth_only_operation {
                        assert!(
                            verifiers.iter().filter_map(|value| value.as_str()).any(|verifier| {
                                verifier.starts_with("interop::") || verifier.starts_with("server::")
                            }),
                            "pass status for {}.{} must include an interop or black-box verifier",
                            provider_name,
                            operation_name
                        );
                    }
                }

                for verifier in verifiers {
                    let verifier = verifier
                        .as_str()
                        .expect("verifier entries should be strings");
                    assert!(
                        known_verifiers.contains(verifier),
                        "unknown verifier '{}' declared for {}.{}",
                        verifier,
                        provider_name,
                        operation_name
                    );
                }
            }
        }
    }
}
