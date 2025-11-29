//! Client-side TOML representation of network policies.
//!
//! This module provides a human-friendly TOML format for specifying network policies,
//! which are then converted to the protobuf `NetworkPolicy` format for transmission to the server.

use crate::jail::{
    HostPattern, IpPattern, NetworkAction, NetworkPattern, NetworkPolicy, NetworkRule,
};
use serde::Deserialize;

/// TOML-friendly policy format (used for loading from files)
#[derive(Debug, Deserialize)]
pub struct ClientNetworkPolicy {
    pub rules: Vec<ClientNetworkRule>,
}

#[derive(Debug, Deserialize)]
pub struct ClientNetworkRule {
    pub pattern: ClientNetworkPattern,
    pub action: ActionName,
    pub credential: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ClientNetworkPattern {
    Host { host: String, path: Option<String> },
    Ip { cidr: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionName {
    Allow,
    Deny,
}

impl ActionName {
    fn to_proto(&self) -> i32 {
        match self {
            ActionName::Allow => NetworkAction::Allow as i32,
            ActionName::Deny => NetworkAction::Deny as i32,
        }
    }
}

impl ClientNetworkPolicy {
    pub fn to_proto(&self) -> NetworkPolicy {
        NetworkPolicy {
            rules: self.rules.iter().map(|r| r.to_proto()).collect(),
        }
    }
}

impl ClientNetworkRule {
    fn to_proto(&self) -> NetworkRule {
        NetworkRule {
            pattern: Some(self.pattern.to_proto()),
            action: self.action.to_proto(),
            credential: self.credential.clone(),
        }
    }
}

impl ClientNetworkPattern {
    fn to_proto(&self) -> NetworkPattern {
        match self {
            ClientNetworkPattern::Host { host, path } => NetworkPattern {
                pattern: Some(crate::jail::network_pattern::Pattern::Host(HostPattern {
                    host: host.clone(),
                    path: path.clone(),
                })),
            },
            ClientNetworkPattern::Ip { cidr } => NetworkPattern {
                pattern: Some(crate::jail::network_pattern::Pattern::Ip(IpPattern {
                    cidr: cidr.clone(),
                })),
            },
        }
    }
}
