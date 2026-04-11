#[cfg(test)]
mod tests {
    #[test]
    fn compatibility_matrix_should_only_use_known_status_values() {
        let matrix: serde_json::Value =
            serde_json::from_str(include_str!("../compatibility-matrix.json"))
                .expect("compatibility matrix should parse");
        let providers = matrix
            .get("providers")
            .and_then(|providers| providers.as_object())
            .expect("providers should be an object");

        for operations in providers.values() {
            let operations = operations
                .as_object()
                .expect("provider operations should be an object");
            for status in operations.values() {
                let status = status.as_str().expect("status should be a string");
                assert!(
                    matches!(status, "pass" | "partial" | "missing" | "deferred"),
                    "unexpected compatibility status: {}",
                    status
                );
            }
        }
    }
}
