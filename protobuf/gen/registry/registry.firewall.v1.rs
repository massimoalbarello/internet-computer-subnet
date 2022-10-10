/// Firewall configuration - Deprecated
#[derive(
    candid::CandidType, serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message,
)]
pub struct FirewallConfig {
    /// The firewall configuration content
    #[prost(string, tag = "1")]
    pub firewall_config: ::prost::alloc::string::String,
    /// List of allowed IPv4 prefixes
    #[prost(string, repeated, tag = "2")]
    pub ipv4_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// List of allowed IPv6 prefixes
    #[prost(string, repeated, tag = "3")]
    pub ipv6_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(
    candid::CandidType, serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message,
)]
pub struct FirewallRule {
    #[prost(string, repeated, tag = "1")]
    pub ipv4_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag = "2")]
    pub ipv6_prefixes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint32, repeated, tag = "3")]
    pub ports: ::prost::alloc::vec::Vec<u32>,
    #[prost(enumeration = "FirewallAction", tag = "4")]
    pub action: i32,
    #[prost(string, tag = "5")]
    pub comment: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "6")]
    pub user: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "FirewallRuleDirection", optional, tag = "7")]
    pub direction: ::core::option::Option<i32>,
}
#[derive(
    candid::CandidType, serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message,
)]
pub struct FirewallRuleSet {
    #[prost(message, repeated, tag = "1")]
    pub entries: ::prost::alloc::vec::Vec<FirewallRule>,
}
/// Available actions for firewall rules
#[derive(
    candid::CandidType,
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum FirewallAction {
    Unspecified = 0,
    /// Allow traffic
    Allow = 1,
    /// Deny (drop) traffic
    Deny = 2,
    /// Reject traffic (send ICMP error back)
    Reject = 3,
}
#[derive(
    candid::CandidType,
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum FirewallRuleDirection {
    Unspecified = 0,
    Inbound = 1,
    Outbound = 2,
}
