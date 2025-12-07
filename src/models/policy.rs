use serde::{Deserialize, Serialize};

pub use super::bucket::{
    Bucket, BucketPolicy, LifecycleExpiration, LifecycleRule, PolicyStatement,
};

// ============================================================================
// ACL (Access Control List) Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum CannedAcl {
    #[serde(rename = "private")]
    #[default]
    Private,
    #[serde(rename = "public-read")]
    PublicRead,
    #[serde(rename = "public-read-write")]
    PublicReadWrite,
    #[serde(rename = "authenticated-read")]
    AuthenticatedRead,
    #[serde(rename = "bucket-owner-read")]
    BucketOwnerRead,
    #[serde(rename = "bucket-owner-full-control")]
    BucketOwnerFullControl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    #[serde(rename = "READ")]
    Read,
    #[serde(rename = "WRITE")]
    Write,
    #[serde(rename = "READ_ACP")]
    ReadAcp,
    #[serde(rename = "WRITE_ACP")]
    WriteAcp,
    #[serde(rename = "FULL_CONTROL")]
    FullControl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "Type")]
pub enum Grantee {
    #[serde(rename = "CanonicalUser")]
    CanonicalUser {
        #[serde(rename = "ID")]
        id: String,
        #[serde(rename = "DisplayName", skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
    },
    #[serde(rename = "Group")]
    Group {
        #[serde(rename = "URI")]
        uri: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub grantee: Grantee,
    pub permission: Permission,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Acl {
    pub canned: CannedAcl,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

impl Acl {
    /// Convert a canned ACL to explicit grants
    pub fn to_grants(&self, owner_id: &str) -> Vec<Grant> {
        if !self.grants.is_empty() {
            return self.grants.clone();
        }

        match self.canned {
            CannedAcl::Private => vec![Grant {
                grantee: Grantee::CanonicalUser {
                    id: owner_id.to_string(),
                    display_name: None,
                },
                permission: Permission::FullControl,
            }],
            CannedAcl::PublicRead => vec![
                Grant {
                    grantee: Grantee::CanonicalUser {
                        id: owner_id.to_string(),
                        display_name: None,
                    },
                    permission: Permission::FullControl,
                },
                Grant {
                    grantee: Grantee::Group {
                        uri: "http://acs.amazonaws.com/groups/global/AllUsers".to_string(),
                    },
                    permission: Permission::Read,
                },
            ],
            CannedAcl::PublicReadWrite => vec![
                Grant {
                    grantee: Grantee::CanonicalUser {
                        id: owner_id.to_string(),
                        display_name: None,
                    },
                    permission: Permission::FullControl,
                },
                Grant {
                    grantee: Grantee::Group {
                        uri: "http://acs.amazonaws.com/groups/global/AllUsers".to_string(),
                    },
                    permission: Permission::Read,
                },
                Grant {
                    grantee: Grantee::Group {
                        uri: "http://acs.amazonaws.com/groups/global/AllUsers".to_string(),
                    },
                    permission: Permission::Write,
                },
            ],
            CannedAcl::AuthenticatedRead => vec![
                Grant {
                    grantee: Grantee::CanonicalUser {
                        id: owner_id.to_string(),
                        display_name: None,
                    },
                    permission: Permission::FullControl,
                },
                Grant {
                    grantee: Grantee::Group {
                        uri: "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                            .to_string(),
                    },
                    permission: Permission::Read,
                },
            ],
            CannedAcl::BucketOwnerRead | CannedAcl::BucketOwnerFullControl => vec![Grant {
                grantee: Grantee::CanonicalUser {
                    id: owner_id.to_string(),
                    display_name: None,
                },
                permission: Permission::FullControl,
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Owner {
    pub id: String,
    pub display_name: String,
}

// ============================================================================
// Authorization Context
// ============================================================================

#[derive(Debug, Clone)]
pub struct AuthContext {
    /// User/principal making the request
    pub principal: String,
    /// Whether the user is authenticated
    pub is_authenticated: bool,
    /// The action being performed (e.g., "s3:GetObject", "s3:PutObject")
    pub action: String,
    /// The resource being accessed (e.g., "arn:aws:s3:::bucket/key")
    pub resource: String,
    /// Bucket owner ID
    pub bucket_owner: Option<String>,
    /// Object owner ID
    pub object_owner: Option<String>,
}

impl AuthContext {
    pub fn anonymous(action: &str, resource: &str) -> Self {
        Self {
            principal: "*".to_string(),
            is_authenticated: false,
            action: action.to_string(),
            resource: resource.to_string(),
            bucket_owner: None,
            object_owner: None,
        }
    }

    pub fn authenticated(principal: &str, action: &str, resource: &str) -> Self {
        Self {
            principal: principal.to_string(),
            is_authenticated: true,
            action: action.to_string(),
            resource: resource.to_string(),
            bucket_owner: None,
            object_owner: None,
        }
    }
}

// ============================================================================
// Authorization Engine
// ============================================================================

pub struct Authorizer;

impl Authorizer {
    /// Check if an ACL permits the given action
    pub fn check_acl_permission(acl: &Acl, owner_id: &str, context: &AuthContext) -> bool {
        let grants = acl.to_grants(owner_id);

        for grant in grants {
            if Self::grant_matches(grant, context) {
                return true;
            }
        }

        false
    }

    fn grant_matches(grant: Grant, context: &AuthContext) -> bool {
        // Check if grantee matches
        let grantee_matches = match &grant.grantee {
            Grantee::CanonicalUser { id, .. } => {
                // Owner always matches
                context.principal == *id
            }
            Grantee::Group { uri } => {
                if uri == "http://acs.amazonaws.com/groups/global/AllUsers" {
                    true // Anyone
                } else if uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
                    context.is_authenticated
                } else {
                    false
                }
            }
        };

        if !grantee_matches {
            return false;
        }

        // Check if permission covers the action
        Self::permission_covers_action(&grant.permission, &context.action)
    }

    fn permission_covers_action(permission: &Permission, action: &str) -> bool {
        match permission {
            Permission::FullControl => true,
            Permission::Read => action.contains("GetObject") || action.contains("ListBucket"),
            Permission::Write => action.contains("PutObject") || action.contains("DeleteObject"),
            Permission::ReadAcp => {
                action.contains("GetObjectAcl") || action.contains("GetBucketAcl")
            }
            Permission::WriteAcp => {
                action.contains("PutObjectAcl") || action.contains("PutBucketAcl")
            }
        }
    }

    /// Evaluate a bucket policy document
    pub fn evaluate_policy(policy: &BucketPolicyDocument, context: &AuthContext) -> PolicyEffect {
        let mut has_allow = false;
        let mut has_deny = false;

        for statement in &policy.statement {
            if !Self::statement_applies(statement, context) {
                continue;
            }

            match statement.effect.as_str() {
                "Allow" => has_allow = true,
                "Deny" => has_deny = true,
                _ => {}
            }
        }

        // Explicit deny always wins
        if has_deny {
            PolicyEffect::Deny
        } else if has_allow {
            PolicyEffect::Allow
        } else {
            PolicyEffect::Neutral
        }
    }

    fn statement_applies(statement: &PolicyStatementDocument, context: &AuthContext) -> bool {
        // Check principal
        if !Self::principal_matches(&statement.principal, context) {
            return false;
        }

        // Check action
        if !Self::action_matches(&statement.action, &context.action) {
            return false;
        }

        // Check resource
        if !Self::resource_matches(&statement.resource, &context.resource) {
            return false;
        }

        true
    }

    fn principal_matches(principal: &Principal, context: &AuthContext) -> bool {
        match principal {
            Principal::All(s) if s == "*" => true,
            Principal::AWS(list) => match list {
                StringOrArray::Single(p) => p == &context.principal || p == "*",
                StringOrArray::Multiple(principals) => {
                    principals.contains(&context.principal) || principals.contains(&"*".to_string())
                }
            },
            _ => false,
        }
    }

    fn action_matches(actions: &ActionList, context_action: &str) -> bool {
        let check_action = |action: &str| -> bool {
            if action == "*" || action == "s3:*" {
                return true;
            }
            // Simple wildcard matching
            if action.ends_with('*') {
                let prefix = action.trim_end_matches('*');
                context_action.starts_with(prefix)
            } else {
                action == context_action
            }
        };

        match actions {
            ActionList::Single(action) => check_action(action),
            ActionList::Multiple(action_list) => action_list.iter().any(|a| check_action(a)),
        }
    }

    fn resource_matches(resources: &ResourceList, context_resource: &str) -> bool {
        let check_resource = |resource: &str| -> bool {
            if resource == "*" {
                return true;
            }
            // Simple wildcard matching
            if resource.ends_with('*') {
                let prefix = resource.trim_end_matches('*');
                context_resource.starts_with(prefix)
            } else {
                resource == context_resource
            }
        };

        match resources {
            ResourceList::Single(resource) => check_resource(resource),
            ResourceList::Multiple(resource_list) => {
                resource_list.iter().any(|r| check_resource(r))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
    Neutral, // No matching statement
}

// ============================================================================
// Bucket Policy Document Models
// ============================================================================

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
