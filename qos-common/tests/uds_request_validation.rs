//! UDS service unit tests for request parsing and response generation.
//!
//! Tests the `parse_and_validate_request` logic that the UDS server uses
//! to handle incoming JSON lines. This covers:
//! - Valid command parsing (add, delete, list)
//! - Invalid JSON error responses
//! - Unknown command error responses
//! - rate/burst == 0 validation
//! - Missing fields error handling
//!
//! **Validates: Requirements 4.7, 4.8**

use serde::{Deserialize, Serialize};

/// JSON request from the UDS client (mirrors qos/src/protocol.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum Request {
    #[serde(rename = "add")]
    Add { ip: String, rate: u64, burst: u64 },
    #[serde(rename = "delete")]
    Delete { ip: String },
    #[serde(rename = "list")]
    List,
}

/// JSON response sent back to the UDS client (mirrors qos/src/protocol.rs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Parse and validate a JSON line, returning a validated `Request` or an error `Response`.
///
/// This mirrors the logic in `qos/src/protocol.rs::parse_and_validate_request`.
fn parse_and_validate_request(line: &str) -> Result<Request, Response> {
    let json_value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Err(Response {
                status: "error".to_string(),
                data: None,
                message: Some(format!("invalid JSON: {}", e)),
            });
        }
    };

    let request: Request = match serde_json::from_value(json_value.clone()) {
        Ok(r) => r,
        Err(_) => {
            let cmd = json_value
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            return Err(Response {
                status: "error".to_string(),
                data: None,
                message: Some(format!("unknown command: {}", cmd)),
            });
        }
    };

    if let Request::Add { rate, burst, .. } = &request {
        if *rate == 0 || *burst == 0 {
            return Err(Response {
                status: "error".to_string(),
                data: None,
                message: Some("rate and burst must be positive".to_string()),
            });
        }
    }

    Ok(request)
}

// --- Invalid JSON tests ---

#[test]
fn test_invalid_json_returns_error() {
    let resp = parse_and_validate_request("not json at all").unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
}

#[test]
fn test_empty_string_returns_error() {
    let resp = parse_and_validate_request("").unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
}

#[test]
fn test_partial_json_returns_error() {
    let resp = parse_and_validate_request(r#"{"command": "add""#).unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
}

// --- Unknown command tests ---

#[test]
fn test_unknown_command_returns_error() {
    let resp = parse_and_validate_request(r#"{"command": "restart"}"#).unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp
        .message
        .as_ref()
        .unwrap()
        .contains("unknown command: restart"),);
}

#[test]
fn test_missing_command_field_returns_error() {
    let resp = parse_and_validate_request(r#"{"ip": "10.0.0.0/8"}"#).unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp
        .message
        .as_ref()
        .unwrap()
        .contains("unknown command: <missing>"),);
}

// --- rate/burst == 0 validation tests ---

#[test]
fn test_add_rate_zero_returns_error() {
    let resp = parse_and_validate_request(
        r#"{"command": "add", "ip": "10.0.0.0/8", "rate": 0, "burst": 1024}"#,
    )
    .unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp
        .message
        .as_ref()
        .unwrap()
        .contains("rate and burst must be positive"),);
}

#[test]
fn test_add_burst_zero_returns_error() {
    let resp = parse_and_validate_request(
        r#"{"command": "add", "ip": "10.0.0.0/8", "rate": 1024, "burst": 0}"#,
    )
    .unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp
        .message
        .as_ref()
        .unwrap()
        .contains("rate and burst must be positive"),);
}

#[test]
fn test_add_both_zero_returns_error() {
    let resp = parse_and_validate_request(
        r#"{"command": "add", "ip": "10.0.0.0/8", "rate": 0, "burst": 0}"#,
    )
    .unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp
        .message
        .as_ref()
        .unwrap()
        .contains("rate and burst must be positive"),);
}

// --- Valid command parsing tests ---

#[test]
fn test_valid_add_command() {
    let req = parse_and_validate_request(
        r#"{"command": "add", "ip": "192.168.1.0/24", "rate": 1048576, "burst": 2097152}"#,
    )
    .unwrap();
    assert_eq!(
        req,
        Request::Add {
            ip: "192.168.1.0/24".to_string(),
            rate: 1048576,
            burst: 2097152,
        }
    );
}

#[test]
fn test_valid_delete_command() {
    let req = parse_and_validate_request(r#"{"command": "delete", "ip": "10.0.0.1"}"#).unwrap();
    assert_eq!(
        req,
        Request::Delete {
            ip: "10.0.0.1".to_string(),
        }
    );
}

#[test]
fn test_valid_list_command() {
    let req = parse_and_validate_request(r#"{"command": "list"}"#).unwrap();
    assert_eq!(req, Request::List);
}

// --- Error response structure tests ---

#[test]
fn test_error_response_has_no_data() {
    let resp = parse_and_validate_request("garbage").unwrap_err();
    assert!(resp.data.is_none());
}

#[test]
fn test_add_missing_fields_returns_error() {
    let resp = parse_and_validate_request(r#"{"command": "add", "ip": "10.0.0.0/8"}"#).unwrap_err();
    assert_eq!(resp.status, "error");
    assert!(resp.message.is_some());
}
