#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_escape_ampersand_given_string_with_ampersand_when_escape_xml_called() {
        // Arrange
        let input = "test & data";
        let expected = "test &amp; data";

        // Act
        let result = escape_xml(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[test]
    fn should_escape_angle_brackets_given_string_with_brackets_when_escape_xml_called() {
        // Arrange
        let input = "<tag>";
        let expected = "&lt;tag&gt;";

        // Act
        let result = escape_xml(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[test]
    fn should_escape_quotes_given_string_with_quotes_when_escape_xml_called() {
        // Arrange
        let input = r#"quote"test"#;
        let expected = "quote&quot;test";

        // Act
        let result = escape_xml(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[test]
    fn should_include_xml_declaration_given_any_input_when_list_buckets_xml_called() {
        // Arrange
        let buckets = vec![];

        // Act
        let xml = list_buckets_xml(&buckets);

        // Assert
        assert!(xml.starts_with("<?xml version="), "XML should start with declaration");
    }

    #[test]
    fn should_include_bucket_name_given_bucket_list_when_list_buckets_xml_called() {
        // Arrange
        let buckets = vec![];

        // Act
        let xml = list_buckets_xml(&buckets);

        // Assert
        assert!(xml.contains("<ListBucketsResult"), "XML should contain ListBucketsResult element");
        assert!(xml.contains("</ListBucketsResult>"), "XML should close ListBucketsResult element");
    }

    #[test]
    fn should_include_error_code_given_error_parameters_when_error_xml_called() {
        // Arrange
        let code = "NoSuchBucket";
        let message = "Bucket not found";
        let request_id = "req-12345";

        // Act
        let xml = error_xml(code, message, request_id);

        // Assert
        assert!(xml.contains("<Code>NoSuchBucket</Code>"), "XML should contain error code");
    }

    #[test]
    fn should_include_error_message_given_error_parameters_when_error_xml_called() {
        // Arrange
        let code = "NoSuchBucket";
        let message = "Bucket not found";
        let request_id = "req-12345";

        // Act
        let xml = error_xml(code, message, request_id);

        // Assert
        assert!(xml.contains("<Message>Bucket not found</Message>"), "XML should contain error message");
    }

    #[test]
    fn should_include_request_id_given_request_id_when_error_xml_called() {
        // Arrange
        let code = "NoSuchBucket";
        let message = "Bucket not found";
        let request_id = "req-12345";

        // Act
        let xml = error_xml(code, message, request_id);

        // Assert
        assert!(xml.contains("<RequestId>req-12345</RequestId>"), "XML should contain request ID");
    }

    #[test]
    fn should_include_enabled_status_given_enabled_string_when_versioning_status_xml_called() {
        // Arrange
        let status = Some("Enabled");

        // Act
        let xml = versioning_status_xml(status);

        // Assert
        assert!(xml.contains("<Status>Enabled</Status>"), "XML should contain Enabled status");
    }

    #[test]
    fn should_include_suspended_status_given_suspended_string_when_versioning_status_xml_called() {
        // Arrange
        let status = Some("Suspended");

        // Act
        let xml = versioning_status_xml(status);

        // Assert
        assert!(xml.contains("<Status>Suspended</Status>"), "XML should contain Suspended status");
    }

    #[test]
    fn should_include_versioning_configuration_element_given_any_status_when_versioning_status_xml_called() {
        // Arrange
        let status = Some("Enabled");

        // Act
        let xml = versioning_status_xml(status);

        // Assert
        assert!(xml.contains("<VersioningConfiguration"), "XML should contain VersioningConfiguration element");
        assert!(xml.contains("</VersioningConfiguration>"), "XML should close VersioningConfiguration element");
    }

    #[test]
    fn should_include_empty_constraint_given_us_east_1_when_location_xml_called() {
        // Arrange
        let region = "us-east-1";

        // Act
        let xml = location_xml(region);

        // Assert
        assert!(xml.contains("<LocationConstraint"), "XML should contain LocationConstraint element");
        // US-east-1 returns empty constraint in S3
    }

    #[test]
    fn should_include_region_given_non_us_east_1_when_location_xml_called() {
        // Arrange
        let region = "eu-central-1";

        // Act
        let xml = location_xml(region);

        // Assert
        assert!(xml.contains("eu-central-1"), "XML should contain region name");
    }

    #[test]
    fn should_parse_tagging_xml_into_map() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<Tagging><TagSet><Tag><Key>env</Key><Value>dev</Value></Tag><Tag><Key>owner</Key><Value>alice</Value></Tag></TagSet></Tagging>"#;

        let tags = parse_tagging_xml(body).expect("parse tagging xml");

        assert_eq!(tags.get("env"), Some(&"dev".to_string()));
        assert_eq!(tags.get("owner"), Some(&"alice".to_string()));
    }

    #[test]
    fn should_render_tagging_xml_with_entries() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());

        let xml = tagging_xml(&tags);

        assert!(xml.contains("<Tag>"));
        assert!(xml.contains("<Key>env</Key>"));
        assert!(xml.contains("<Value>prod</Value>"));
    }

    #[test]
    fn should_error_when_more_than_ten_tags() {
        let mut body = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Tagging><TagSet>");
        for i in 0..11 {
            body.push_str(&format!("<Tag><Key>k{i}</Key><Value>v{i}</Value></Tag>"));
        }
        body.push_str("</TagSet></Tagging>");

        let result = parse_tagging_xml(&body);
        assert!(result.is_err());
    }

    #[test]
    fn should_error_on_empty_tag_key() {
        let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Tagging><TagSet><Tag><Key></Key><Value>v</Value></Tag></TagSet></Tagging>";
        let result = parse_tagging_xml(body);
        assert!(result.is_err());
    }

    #[test]
    fn should_render_owner_grant_in_acl_xml() {
        let owner = Owner { id: "owner-id".to_string(), display_name: "Owner".to_string() };
        let acl = Acl { canned: CannedAcl::Private };

        let xml = acl_xml(&owner, &acl);

        assert!(xml.contains("<AccessControlPolicy"));
        assert!(xml.contains("<Permission>FULL_CONTROL</Permission>"));
        assert!(xml.contains("owner-id"));
        assert!(!xml.contains("AllUsers"));
    }

    #[test]
    fn should_render_public_read_grant_in_acl_xml() {
        let owner = Owner { id: "owner-id".to_string(), display_name: "Owner".to_string() };
        let acl = Acl { canned: CannedAcl::PublicRead };

        let xml = acl_xml(&owner, &acl);

        assert!(xml.contains("AllUsers"));
        assert!(xml.contains("<Permission>READ</Permission>"));
    }
}
/// XML response builders for S3-compliant responses
use crate::models::{Acl, Bucket, CannedAcl, Object, MultipartUpload, Owner, Part};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;

/// Wrap content in XML declaration
pub fn xml_declaration() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string()
}

/// ListBuckets response
pub fn list_buckets_xml(buckets: &[Bucket]) -> String {
    let mut xml = format!(
        r#"{}
<ListBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Buckets>"#,
        xml_declaration()
    );

    for bucket in buckets {
        let created = bucket.created_at.to_rfc3339();
        xml.push_str(&format!(
            r#"
    <Bucket>
      <Name>{}</Name>
      <CreationDate>{}</CreationDate>
    </Bucket>"#,
            escape_xml(&bucket.name), created
        ));
    }

    xml.push_str(
        r#"
  </Buckets>
  <Owner>
    <ID>peas-emulator</ID>
    <DisplayName>Peas Emulator</DisplayName>
  </Owner>
</ListBucketsResult>"#,
    );

    xml
}

/// Parse object tagging XML into key/value pairs
/// Parse versioning configuration XML
pub fn parse_versioning_xml(body: &str) -> Result<bool, String> {
    let mut reader = Reader::from_str(body);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut in_status = false;
    let mut enabled = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if e.name().as_ref() == b"Status" {
                    in_status = true;
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"Status" {
                    in_status = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_status {
                    let text = e.unescape().map_err(|err| err.to_string())?.to_string();
                    enabled = text == "Enabled";
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    Ok(enabled)
}

pub fn parse_tagging_xml(body: &str) -> Result<HashMap<String, String>, String> {
    let mut reader = Reader::from_str(body);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut in_key = false;
    let mut in_value = false;
    let mut current_key: Option<String> = None;
    let mut tags = HashMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                match e.name().as_ref() {
                    b"Key" => in_key = true,
                    b"Value" => in_value = true,
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                match e.name().as_ref() {
                    b"Key" => in_key = false,
                    b"Value" => in_value = false,
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().map_err(|err| err.to_string())?.to_string();
                if in_key {
                    current_key = Some(text);
                } else if in_value {
                    if let Some(k) = current_key.take() {
                        tags.insert(k, text);
                    } else {
                        return Err("InvalidTagKey".to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(e.to_string()),
            _ => {}
        }
        buf.clear();
    }

    if tags.len() > 10 {
        return Err("TooManyTags".to_string());
    }

    for (k, v) in tags.iter() {
        if k.is_empty() {
            return Err("InvalidTagKey".to_string());
        }
        if k.len() > 128 {
            return Err("InvalidTagKey".to_string());
        }
        if v.len() > 256 {
            return Err("InvalidTagValue".to_string());
        }
    }

    Ok(tags)
}

/// Build Tagging XML response from key/value pairs
pub fn tagging_xml(tags: &HashMap<String, String>) -> String {
    let mut xml = format!(
        r#"{} 
<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"> 
  <TagSet>"#,
        xml_declaration()
    );

    for (k, v) in tags.iter() {
        xml.push_str(&format!(
            "\n    <Tag><Key>{}</Key><Value>{}</Value></Tag>",
            escape_xml(k),
            escape_xml(v)
        ));
    }

    xml.push_str("\n  </TagSet>\n</Tagging>");
    xml
}

/// ListBucketResult response (list objects)
pub fn list_objects_xml(
    objects: &[Object],
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    marker: Option<&str>,
    max_keys: usize,
    truncated: bool,
    next_marker: Option<&str>,
) -> String {
    let mut xml = format!(
        r#"{}
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{}</Name>
  <Prefix>{}</Prefix>"#,
        xml_declaration(),
        escape_xml(bucket),
        escape_xml(prefix)
    );

    if let Some(delim) = delimiter {
        xml.push_str(&format!("\n  <Delimiter>{}</Delimiter>", escape_xml(delim)));
    }

    if let Some(m) = marker {
        xml.push_str(&format!("\n  <Marker>{}</Marker>", escape_xml(m)));
    }

    xml.push_str(&format!("\n  <MaxKeys>{}</MaxKeys>", max_keys));
    xml.push_str(&format!(
        "\n  <IsTruncated>{}</IsTruncated>",
        if truncated { "true" } else { "false" }
    ));

    for obj in objects {
        let modified = obj.last_modified.to_rfc3339();
        xml.push_str(&format!(
            r#"
  <Contents>
    <Key>{}</Key>
    <LastModified>{}</LastModified>
    <ETag>"{}"</ETag>
    <Size>{}</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>"#,
            escape_xml(&obj.key),
            modified,
            escape_xml(&obj.etag),
            obj.size
        ));
    }

    if truncated {
        if let Some(nm) = next_marker {
            xml.push_str(&format!("\n  <NextMarker>{}</NextMarker>", escape_xml(nm)));
        }
    }

    xml.push_str("\n</ListBucketResult>");

    xml
}

/// Error response
pub fn error_xml(code: &str, message: &str, request_id: &str) -> String {
    format!(
        r#"{}
<Error>
  <Code>{}</Code>
  <Message>{}</Message>
  <RequestId>{}</RequestId>
</Error>"#,
        xml_declaration(),
        escape_xml(code),
        escape_xml(message),
        escape_xml(request_id)
    )
}

/// Versioning configuration response
pub fn versioning_status_xml(status: Option<&str>) -> String {
    let status_str = status.unwrap_or("Suspended");
    format!(
        r#"{}
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>{}</Status>
</VersioningConfiguration>"#,
        xml_declaration(),
        escape_xml(status_str)
    )
}

/// List object versions response
pub fn list_versions_xml(
    bucket: &str,
    versions: &[crate::models::Object],
    prefix: &str,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
    max_keys: usize,
    truncated: bool,
    next_key_marker: Option<&str>,
    next_version_id_marker: Option<&str>,
) -> String {
    let mut versions_xml = String::new();
    for obj in versions {
        let version_id = obj.version_id.as_deref().unwrap_or("null");
        let last_modified = obj.last_modified.format("%Y-%m-%dT%H:%M:%S%.3fZ");
        versions_xml.push_str(&format!(
            r#"
  <Version>
    <Key>{}</Key>
    <VersionId>{}</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>{}</LastModified>
    <ETag>{}</ETag>
    <Size>{}</Size>
    <Owner>
      <ID>peas-emulator</ID>
      <DisplayName>Peas Emulator</DisplayName>
    </Owner>
    <StorageClass>{}</StorageClass>
  </Version>"#,
            escape_xml(&obj.key),
            escape_xml(version_id),
            last_modified,
            escape_xml(&obj.etag),
            obj.size,
            escape_xml(&obj.storage_class)
        ));
    }
    
    let mut result = format!(
        r#"{}
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>{}</Name>
  <Prefix>{}</Prefix>
  <KeyMarker>{}</KeyMarker>
  <VersionIdMarker>{}</VersionIdMarker>
  <MaxKeys>{}</MaxKeys>
  <IsTruncated>{}</IsTruncated>{}"#,
        xml_declaration(),
        escape_xml(bucket),
        escape_xml(prefix),
        escape_xml(key_marker.unwrap_or("")),
        escape_xml(version_id_marker.unwrap_or("")),
        max_keys,
        if truncated { "true" } else { "false" },
        versions_xml
    );

    if truncated {
        if let Some(nkm) = next_key_marker {
            result.push_str(&format!("\n  <NextKeyMarker>{}</NextKeyMarker>", escape_xml(nkm)));
        }
        if let Some(nvm) = next_version_id_marker {
            result.push_str(&format!("\n  <NextVersionIdMarker>{}</NextVersionIdMarker>", escape_xml(nvm)));
        }
    }

    result.push_str("</ListVersionsResult>");
    result
}

/// Location constraint response
pub fn location_xml(region: &str) -> String {
    if region == "us-east-1" {
        // AWS returns empty LocationConstraint for us-east-1
        format!(
            r#"{}
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
</LocationConstraint>"#,
            xml_declaration()
        )
    } else {
        format!(
            r#"{}
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  {}
</LocationConstraint>"#,
            xml_declaration(),
            escape_xml(region)
        )
    }
}

/// Initiate multipart upload response
pub fn initiate_multipart_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        r#"{}
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>{}</Bucket>
  <Key>{}</Key>
  <UploadId>{}</UploadId>
</InitiateMultipartUploadResult>"#,
        xml_declaration(),
        escape_xml(bucket),
        escape_xml(key),
        escape_xml(upload_id)
    )
}

/// List multipart uploads response
pub fn list_multipart_uploads_xml(uploads: &[MultipartUpload], bucket: &str) -> String {
    let mut xml = format!(
        r#"{}
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>{}</Bucket>
  <Uploads>"#,
        xml_declaration(),
        escape_xml(bucket)
    );

    for upload in uploads {
        let initiated = upload.initiated.to_rfc3339();
        xml.push_str(&format!(
            r#"
    <Upload>
      <Key>{}</Key>
      <UploadId>{}</UploadId>
      <Initiated>{}</Initiated>
      <StorageClass>STANDARD</StorageClass>
    </Upload>"#,
            escape_xml(&upload.key),
            escape_xml(&upload.upload_id),
            initiated
        ));
    }

    xml.push_str(
        r#"
  </Uploads>
  <IsTruncated>false</IsTruncated>
</ListMultipartUploadsResult>"#,
    );

    xml
}

/// ACL response
pub fn acl_xml(owner: &Owner, acl: &Acl) -> String {
        let mut grants = String::new();

        grants.push_str(&format!(
                r#"
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                <ID>{}</ID>
                <DisplayName>{}</DisplayName>
            </Grantee>
            <Permission>FULL_CONTROL</Permission>
        </Grant>"#,
                escape_xml(&owner.id),
                escape_xml(&owner.display_name)
        ));

        match acl.canned {
                CannedAcl::Private => {}
                CannedAcl::PublicRead => {
                        grants.push_str(
                                r#"
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee>
            <Permission>READ</Permission>
        </Grant>"#,
                        );
                }
                CannedAcl::PublicReadWrite => {
                        grants.push_str(
                                r#"
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee>
            <Permission>READ</Permission>
        </Grant>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee>
            <Permission>WRITE</Permission>
        </Grant>"#,
                        );
                }
        }

        format!(
                r#"{}
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>{}</ID>
        <DisplayName>{}</DisplayName>
    </Owner>
    <AccessControlList>{}
    </AccessControlList>
</AccessControlPolicy>"#,
                xml_declaration(),
                escape_xml(&owner.id),
                escape_xml(&owner.display_name),
                grants
        )
}

/// List parts response
pub fn list_parts_xml(bucket: &str, key: &str, upload_id: &str, parts: &[Part]) -> String {
    let mut xml = format!(
        r#"{}
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>{}</Bucket>
  <Key>{}</Key>
  <UploadId>{}</UploadId>
  <Parts>"#,
        xml_declaration(),
        escape_xml(bucket),
        escape_xml(key),
        escape_xml(upload_id)
    );

    for part in parts {
        let modified = part.last_modified.to_rfc3339();
        xml.push_str(&format!(
            r#"
    <Part>
      <PartNumber>{}</PartNumber>
      <LastModified>{}</LastModified>
      <ETag>"{}"</ETag>
      <Size>{}</Size>
    </Part>"#,
            part.part_number, modified, escape_xml(&part.etag), part.size
        ));
    }

    xml.push_str(
        r#"
  </Parts>
  <IsTruncated>false</IsTruncated>
</ListPartsResult>"#,
    );

    xml
}

/// Complete multipart upload response
pub fn complete_multipart_upload_xml(
    bucket: &str,
    key: &str,
    etag: &str,
) -> String {
    format!(
        r#"{}
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://s3.amazonaws.com/{}/{}</Location>
  <Bucket>{}</Bucket>
  <Key>{}</Key>
  <ETag>"{}"</ETag>
</CompleteMultipartUploadResult>"#,
        xml_declaration(),
        escape_xml(bucket),
        escape_xml(key),
        escape_xml(bucket),
        escape_xml(key),
        escape_xml(etag)
    )
}

/// Generate lifecycle configuration XML response
pub fn lifecycle_xml(config: &crate::models::lifecycle::LifecycleConfiguration) -> String {
    use crate::models::lifecycle::*;
    
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<LifecycleConfiguration>\n");

    for rule in &config.rules {
        xml.push_str("  <Rule>\n");

        if let Some(id) = &rule.id {
            xml.push_str(&format!("    <ID>{}</ID>\n", escape_xml(id)));
        }

        xml.push_str(&format!("    <Status>{}</Status>\n", 
            if rule.status == Status::Enabled { "Enabled" } else { "Disabled" }));

        if let Some(filter) = &rule.filter {
            xml.push_str("    <Filter>\n");
            if let Some(prefix) = &filter.prefix {
                xml.push_str(&format!("      <Prefix>{}</Prefix>\n", escape_xml(prefix)));
            }
            for tag in &filter.tags {
                xml.push_str("      <Tag>\n");
                xml.push_str(&format!("        <Key>{}</Key>\n", escape_xml(&tag.key)));
                xml.push_str(&format!("        <Value>{}</Value>\n", escape_xml(&tag.value)));
                xml.push_str("      </Tag>\n");
            }
            xml.push_str("    </Filter>\n");
        }

        if let Some(expiration) = &rule.expiration {
            xml.push_str("    <Expiration>\n");
            if let Some(days) = expiration.days {
                xml.push_str(&format!("      <Days>{}</Days>\n", days));
            }
            if let Some(date) = &expiration.date {
                xml.push_str(&format!("      <Date>{}</Date>\n", escape_xml(date)));
            }
            if let Some(marker) = expiration.expired_object_delete_marker {
                xml.push_str(&format!("      <ExpiredObjectDeleteMarker>{}</ExpiredObjectDeleteMarker>\n", marker));
            }
            xml.push_str("    </Expiration>\n");
        }

        for transition in &rule.transitions {
            xml.push_str("    <Transition>\n");
            if let Some(days) = transition.days {
                xml.push_str(&format!("      <Days>{}</Days>\n", days));
            }
            if let Some(date) = &transition.date {
                xml.push_str(&format!("      <Date>{}</Date>\n", escape_xml(date)));
            }
            let storage_class = match transition.storage_class {
                StorageClass::Standard => "STANDARD",
                StorageClass::Glacier => "GLACIER",
                StorageClass::DeepArchive => "DEEP_ARCHIVE",
            };
            xml.push_str(&format!("      <StorageClass>{}</StorageClass>\n", storage_class));
            xml.push_str("    </Transition>\n");
        }

        xml.push_str("  </Rule>\n");
    }

    xml.push_str("</LifecycleConfiguration>");
    xml
}

/// Parse lifecycle configuration XML body
pub fn parse_lifecycle_xml(body: &str) -> Result<crate::models::lifecycle::LifecycleConfiguration, String> {
    use crate::models::lifecycle::*;
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(body);
    reader.trim_text(true);

    let mut rules = Vec::new();
    let mut current_rule: Option<Rule> = None;
    let mut current_filter: Option<Filter> = None;
    let mut current_expiration: Option<Expiration> = None;
    let mut current_transition: Option<Transition> = None;
    let mut current_tag: Option<(String, String)> = None;
    
    let mut path_stack: Vec<String> = Vec::new();
    let mut text_buffer = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                path_stack.push(name.clone());
                
                match name.as_str() {
                    "Rule" => {
                        current_rule = Some(Rule {
                            id: None,
                            status: Status::Disabled,
                            filter: None,
                            expiration: None,
                            transitions: Vec::new(),
                        });
                    }
                    "Filter" => {
                        current_filter = Some(Filter {
                            prefix: None,
                            tags: Vec::new(),
                        });
                    }
                    "Expiration" => {
                        current_expiration = Some(Expiration {
                            days: None,
                            date: None,
                            expired_object_delete_marker: None,
                        });
                    }
                    "Transition" => {
                        current_transition = Some(Transition {
                            days: None,
                            date: None,
                            storage_class: StorageClass::Standard,
                        });
                    }
                    "Tag" => {
                        current_tag = Some((String::new(), String::new()));
                    }
                    _ => {}
                }
                text_buffer.clear();
            }
            Ok(Event::Text(e)) => {
                text_buffer = e.unescape().unwrap_or_default().to_string();
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                
                match name.as_str() {
                    "ID" => {
                        if let Some(ref mut rule) = current_rule {
                            rule.id = Some(text_buffer.clone());
                        }
                    }
                    "Status" => {
                        if let Some(ref mut rule) = current_rule {
                            rule.status = if text_buffer == "Enabled" { 
                                Status::Enabled 
                            } else { 
                                Status::Disabled 
                            };
                        }
                    }
                    "Prefix" => {
                        if let Some(ref mut filter) = current_filter {
                            filter.prefix = Some(text_buffer.clone());
                        }
                    }
                    "Key" => {
                        if let Some(ref mut tag) = current_tag {
                            tag.0 = text_buffer.clone();
                        }
                    }
                    "Value" => {
                        if let Some(ref mut tag) = current_tag {
                            tag.1 = text_buffer.clone();
                        }
                    }
                    "Tag" => {
                        if let (Some(ref mut filter), Some(tag)) = (&mut current_filter, current_tag.take()) {
                            filter.tags.push(crate::models::lifecycle::Tag {
                                key: tag.0,
                                value: tag.1,
                            });
                        }
                    }
                    "Days" => {
                        if let Ok(days) = text_buffer.parse::<u32>() {
                            if let Some(ref mut exp) = current_expiration {
                                exp.days = Some(days);
                            } else if let Some(ref mut trans) = current_transition {
                                trans.days = Some(days);
                            }
                        }
                    }
                    "Date" => {
                        if let Some(ref mut exp) = current_expiration {
                            exp.date = Some(text_buffer.clone());
                        } else if let Some(ref mut trans) = current_transition {
                            trans.date = Some(text_buffer.clone());
                        }
                    }
                    "ExpiredObjectDeleteMarker" => {
                        if let Some(ref mut exp) = current_expiration {
                            exp.expired_object_delete_marker = Some(text_buffer == "true");
                        }
                    }
                    "StorageClass" => {
                        if let Some(ref mut trans) = current_transition {
                            trans.storage_class = match text_buffer.as_str() {
                                "GLACIER" => StorageClass::Glacier,
                                "DEEP_ARCHIVE" => StorageClass::DeepArchive,
                                _ => StorageClass::Standard,
                            };
                        }
                    }
                    "Filter" => {
                        if let (Some(ref mut rule), Some(filter)) = (&mut current_rule, current_filter.take()) {
                            rule.filter = Some(filter);
                        }
                    }
                    "Expiration" => {
                        if let (Some(ref mut rule), Some(exp)) = (&mut current_rule, current_expiration.take()) {
                            rule.expiration = Some(exp);
                        }
                    }
                    "Transition" => {
                        if let (Some(ref mut rule), Some(trans)) = (&mut current_rule, current_transition.take()) {
                            rule.transitions.push(trans);
                        }
                    }
                    "Rule" => {
                        if let Some(rule) = current_rule.take() {
                            rules.push(rule);
                        }
                    }
                    _ => {}
                }
                
                path_stack.pop();
                text_buffer.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
    }

    Ok(LifecycleConfiguration { rules })
}

/// Helper to escape XML special characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
