use serde::{Deserialize, Serialize};

pub use super::bucket::{Bucket, BucketPolicy, PolicyStatement, LifecycleRule, LifecycleExpiration};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[derive(Default)]
pub enum CannedAcl {
	#[serde(rename = "private")]
	#[default]
 Private,
	#[serde(rename = "public-read")]
	PublicRead,
	#[serde(rename = "public-read-write")]
	PublicReadWrite,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Acl {
	pub canned: CannedAcl,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Owner {
	pub id: String,
	pub display_name: String,
}

/// Bucket policy document (JSON format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BucketPolicyDocument {
	pub version: String,
	pub statement: Vec<PolicyStatementDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyStatementDocument {
	pub sid: Option<String>,
	pub effect: String, // "Allow" or "Deny"
	pub principal: Principal,
	pub action: ActionList,
	pub resource: ResourceList,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub condition: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Principal {
	All(String), // "*"
	AWS(StringOrArray),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrArray {
	Single(String),
	Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionList {
	Single(String),
	Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceList {
	Single(String),
	Multiple(Vec<String>),
}
