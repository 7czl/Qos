use anyhow::{anyhow, Result};
use qos_common::LpmKeyV4;
use serde::{Deserialize, Serialize};

/// JSON request from the UDS client.
///
/// Uses tagged enum deserialization: the `"command"` field determines the variant.
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

/// JSON response sent back to the UDS client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Rule information returned in list responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleInfo {
    pub ip: String,
    pub rate: u64,
    pub burst: u64,
}

/// Parse a CIDR string (e.g. "192.168.1.0/24") into an `LpmKeyV4`.
///
/// If no prefix length is specified (e.g. "10.0.0.1"), defaults to /32.
pub fn parse_cidr(s: &str) -> Result<LpmKeyV4> {
    let (addr_str, prefix_len) = if let Some((a, p)) = s.split_once('/') {
        let prefix_len: u32 = p
            .parse()
            .map_err(|_| anyhow!("invalid prefix length: {}", p))?;
        if prefix_len > 32 {
            return Err(anyhow!("prefix length {} out of range (0-32)", prefix_len));
        }
        (a, prefix_len)
    } else {
        (s, 32)
    };

    let addr: std::net::Ipv4Addr = addr_str
        .parse()
        .map_err(|_| anyhow!("invalid IPv4 address: {}", addr_str))?;

    let addr_bits = u32::from(addr); // host byte order
    let addr_be = addr_bits.to_be(); // network byte order

    Ok(LpmKeyV4 {
        prefix_len,
        addr: addr_be,
    })
}

/// Format an `LpmKeyV4` back into a CIDR string (e.g. "192.168.1.0/24").
pub fn format_cidr(key: &LpmKeyV4) -> String {
    let addr = std::net::Ipv4Addr::from(u32::from_be(key.addr));
    format!("{}/{}", addr, key.prefix_len)
}

/// Parse and validate a JSON line, returning a validated `Request` or an error `Response`.
///
/// This function handles:
/// - Invalid JSON detection
/// - Unknown command detection
/// - rate/burst == 0 validation for add commands
pub fn parse_and_validate_request(line: &str) -> Result<Request, Response> {
    // Try to parse as a JSON value first to distinguish invalid JSON from unknown commands
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

    // Check for unknown command: valid JSON object but unrecognised "command" field
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

    // Validate rate/burst for add commands
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // --- parse_cidr unit tests ---

    #[test]
    fn test_parse_cidr_with_prefix() {
        let key = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(key.prefix_len, 24);
        // 192.168.1.0 = 0xC0A80100
        assert_eq!(key.addr, 0xC0A80100_u32.to_be());
    }

    #[test]
    fn test_parse_cidr_single_host() {
        let key = parse_cidr("10.0.0.1").unwrap();
        assert_eq!(key.prefix_len, 32);
        assert_eq!(key.addr, 0x0A000001_u32.to_be());
    }

    #[test]
    fn test_parse_cidr_host_with_32() {
        let key = parse_cidr("10.0.0.1/32").unwrap();
        assert_eq!(key.prefix_len, 32);
        assert_eq!(key.addr, 0x0A000001_u32.to_be());
    }

    #[test]
    fn test_parse_cidr_zero() {
        let key = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(key.prefix_len, 0);
        assert_eq!(key.addr, 0u32.to_be());
    }

    #[test]
    fn test_parse_cidr_invalid_address() {
        assert!(parse_cidr("999.999.999.999/24").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid_prefix() {
        assert!(parse_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_non_numeric() {
        assert!(parse_cidr("10.0.0.0/abc").is_err());
    }

    #[test]
    fn test_parse_cidr_empty() {
        assert!(parse_cidr("").is_err());
    }

    // --- format_cidr unit tests ---

    #[test]
    fn test_format_cidr_24() {
        let key = LpmKeyV4 {
            prefix_len: 24,
            addr: 0xC0A80100_u32.to_be(),
        };
        assert_eq!(format_cidr(&key), "192.168.1.0/24");
    }

    #[test]
    fn test_format_cidr_32() {
        let key = LpmKeyV4 {
            prefix_len: 32,
            addr: 0x0A000001_u32.to_be(),
        };
        assert_eq!(format_cidr(&key), "10.0.0.1/32");
    }

    // --- roundtrip test ---

    #[test]
    fn test_parse_format_roundtrip() {
        let input = "172.16.0.0/12";
        let key = parse_cidr(input).unwrap();
        assert_eq!(format_cidr(&key), input);
    }

    // --- Request serde tests ---

    #[test]
    fn test_request_add_deserialize() {
        let json = r#"{"command": "add", "ip": "192.168.1.0/24", "rate": 1048576, "burst": 2097152}"#;
        let req: Request = serde_json::from_str(json).unwrap();
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
    fn test_request_delete_deserialize() {
        let json = r#"{"command": "delete", "ip": "192.168.1.0/24"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(
            req,
            Request::Delete {
                ip: "192.168.1.0/24".to_string(),
            }
        );
    }

    #[test]
    fn test_request_list_deserialize() {
        let json = r#"{"command": "list"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req, Request::List);
    }

    #[test]
    fn test_request_add_serialize_roundtrip() {
        let req = Request::Add {
            ip: "10.0.0.0/8".to_string(),
            rate: 500000,
            burst: 1000000,
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn test_request_unknown_command() {
        let json = r#"{"command": "unknown"}"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }

    // --- Response serde tests ---

    #[test]
    fn test_response_ok_serialize() {
        let resp = Response {
            status: "ok".to_string(),
            data: None,
            message: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"status":"ok"}"#);
    }

    #[test]
    fn test_response_error_serialize() {
        let resp = Response {
            status: "error".to_string(),
            data: None,
            message: Some("invalid CIDR format".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("\"message\":\"invalid CIDR format\""));
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_response_list_serialize() {
        let rules = vec![RuleInfo {
            ip: "192.168.1.0/24".to_string(),
            rate: 1048576,
            burst: 2097152,
        }];
        let resp = Response {
            status: "ok".to_string(),
            data: Some(serde_json::to_value(&rules).unwrap()),
            message: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"data\""));
        assert!(json.contains("192.168.1.0/24"));
    }

    // --- RuleInfo serde test ---

    #[test]
    fn test_rule_info_roundtrip() {
        let rule = RuleInfo {
            ip: "10.0.0.0/8".to_string(),
            rate: 1048576,
            burst: 2097152,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let rule2: RuleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, rule2);
    }

    // --- Property-based tests ---

    // Feature: ebpf-download-rate-limiter, Property 6: JSON 序列化往返
    // **Validates: Requirements 4.8**
    //
    // For any valid Request object, serializing to JSON and deserializing back
    // should yield a value equal to the original. Same for Response objects.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_request_json_roundtrip(
            a in 0u8..=255u8,
            b in 0u8..=255u8,
            c in 0u8..=255u8,
            d in 0u8..=255u8,
            prefix_len in 0u32..=32u32,
            rate in 1u64..=u64::MAX,
            burst in 1u64..=u64::MAX,
            variant in 0u8..=2u8,
        ) {
            let ip = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix_len);
            let request = match variant {
                0 => Request::Add { ip: ip.clone(), rate, burst },
                1 => Request::Delete { ip: ip.clone() },
                _ => Request::List,
            };

            let json = serde_json::to_string(&request).unwrap();
            let deserialized: Request = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&deserialized, &request,
                "Request roundtrip failed for JSON: {}", json);
        }

        #[test]
        fn property_response_json_roundtrip(
            status_variant in 0u8..=1u8,
            has_message in proptest::bool::ANY,
            msg_len in 1usize..=50usize,
            msg_seed in 0u64..=u64::MAX,
            has_data in proptest::bool::ANY,
            data_val in proptest::option::of(-1000i64..1000i64),
        ) {
            let status = if status_variant == 0 { "ok".to_string() } else { "error".to_string() };

            let message = if has_message {
                // Generate a simple deterministic message from seed
                Some(format!("msg_{}", msg_seed))
            } else {
                None
            };

            let data = if has_data {
                match data_val {
                    Some(v) => Some(serde_json::json!(v)),
                    // Skip Value::Null — it's ambiguous with None for Option<Value>
                    None => None,
                }
            } else {
                None
            };

            let response = Response { status, data, message };

            let json = serde_json::to_string(&response).unwrap();
            let deserialized: Response = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&deserialized, &response,
                "Response roundtrip failed for JSON: {}", json);
        }
    }

    // Feature: ebpf-download-rate-limiter, Property 7: 无效命令错误处理
    // **Validates: Requirements 4.7**
    //
    // For any malformed JSON string or JSON object with an unknown "command" field,
    // serde_json::from_str::<Request> should return Err (deserialization failure).
    // This validates the deserialization layer rejects invalid inputs.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_invalid_json_fails_to_deserialize(
            s in "[^{}\\[\\]\"]*" // random strings that are NOT valid JSON
        ) {
            // Strings that are not valid JSON should fail to deserialize as Request
            let result = serde_json::from_str::<Request>(&s);
            prop_assert!(result.is_err(),
                "Expected deserialization failure for non-JSON string: {:?}", s);
        }

        #[test]
        fn property_unknown_command_fails_to_deserialize(
            cmd in "[a-zA-Z0-9_]{1,20}"
                .prop_filter("must not be a known command",
                    |c| c != "add" && c != "delete" && c != "list")
        ) {
            // JSON objects with unknown command values should fail
            let json = format!(r#"{{"command": "{}"}}"#, cmd);
            let result = serde_json::from_str::<Request>(&json);
            prop_assert!(result.is_err(),
                "Expected deserialization failure for unknown command '{}': json={}", cmd, json);
        }

        #[test]
        fn property_add_missing_fields_fails_to_deserialize(
            has_ip in proptest::bool::ANY,
            has_rate in proptest::bool::ANY,
            has_burst in proptest::bool::ANY,
        ) {
            // At least one field must be missing for this test to be meaningful
            prop_assume!(!(has_ip && has_rate && has_burst));

            let mut parts = vec![r#""command": "add""#.to_string()];
            if has_ip {
                parts.push(r#""ip": "10.0.0.0/8""#.to_string());
            }
            if has_rate {
                parts.push(r#""rate": 1000"#.to_string());
            }
            if has_burst {
                parts.push(r#""burst": 2000"#.to_string());
            }
            let json = format!("{{{}}}", parts.join(", "));
            let result = serde_json::from_str::<Request>(&json);
            prop_assert!(result.is_err(),
                "Expected deserialization failure for add with missing fields: {}", json);
        }
    }

    // Feature: ebpf-download-rate-limiter, Property 4: CIDR 字符串解析正确性
    // **Validates: Requirements 4.4, 3.1, 3.2**
    //
    // For any valid IPv4 CIDR string (e.g. "10.0.0.0/8", "192.168.1.1/32"),
    // after parsing into LpmKeyV4:
    // - prefix_len should equal the CIDR prefix length
    // - addr should equal the network byte order representation of the IP address
    // Formatting back should produce an equivalent CIDR string, and
    // parse_cidr(format_cidr(key)) should roundtrip back to the same key.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_cidr_parse_correctness(
            a in 0u8..=255u8,
            b in 0u8..=255u8,
            c in 0u8..=255u8,
            d in 0u8..=255u8,
            prefix_len in 0u32..=32u32,
        ) {
            let cidr = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix_len);

            // Parse should succeed for any valid IPv4 + prefix_len in 0..=32
            let key = parse_cidr(&cidr).unwrap();

            // prefix_len must match
            prop_assert_eq!(key.prefix_len, prefix_len,
                "prefix_len mismatch for CIDR '{}'", cidr);

            // addr must be the network byte order (big-endian) representation
            let expected_addr = u32::from_be_bytes([a, b, c, d]);
            let expected_addr_be = expected_addr.to_be();
            prop_assert_eq!(key.addr, expected_addr_be,
                "addr mismatch for CIDR '{}': expected 0x{:08X}, got 0x{:08X}",
                cidr, expected_addr_be, key.addr);

            // Roundtrip: format_cidr then parse_cidr should yield the same key
            let formatted = format_cidr(&key);
            let roundtrip_key = parse_cidr(&formatted).unwrap();
            prop_assert_eq!(roundtrip_key.prefix_len, key.prefix_len,
                "roundtrip prefix_len mismatch: '{}' -> '{}' -> prefix_len {}",
                cidr, formatted, roundtrip_key.prefix_len);
            prop_assert_eq!(roundtrip_key.addr, key.addr,
                "roundtrip addr mismatch: '{}' -> '{}' -> addr 0x{:08X}",
                cidr, formatted, roundtrip_key.addr);
        }
    }

    // --- UDS-level parse_and_validate_request tests ---
    // These test the request parsing and validation logic used by the UDS server,
    // covering error scenarios: invalid JSON, unknown commands, invalid CIDR, rate/burst == 0.
    // **Validates: Requirements 4.7, 4.8**

    // Invalid JSON tests

    #[test]
    fn test_validate_invalid_json_returns_error() {
        let resp = parse_and_validate_request("not json at all").unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
    }

    #[test]
    fn test_validate_empty_string_returns_error() {
        let resp = parse_and_validate_request("").unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
    }

    #[test]
    fn test_validate_partial_json_returns_error() {
        let resp = parse_and_validate_request(r#"{"command": "add""#).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
    }

    // Unknown command tests

    #[test]
    fn test_validate_unknown_command_returns_error() {
        let resp = parse_and_validate_request(r#"{"command": "restart"}"#).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("unknown command: restart"));
    }

    #[test]
    fn test_validate_missing_command_field_returns_error() {
        let resp = parse_and_validate_request(r#"{"ip": "10.0.0.0/8"}"#).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("unknown command: <missing>"));
    }

    // rate/burst == 0 validation tests

    #[test]
    fn test_validate_add_rate_zero_returns_error() {
        let resp = parse_and_validate_request(
            r#"{"command": "add", "ip": "10.0.0.0/8", "rate": 0, "burst": 1024}"#,
        ).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("rate and burst must be positive"));
    }

    #[test]
    fn test_validate_add_burst_zero_returns_error() {
        let resp = parse_and_validate_request(
            r#"{"command": "add", "ip": "10.0.0.0/8", "rate": 1024, "burst": 0}"#,
        ).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("rate and burst must be positive"));
    }

    #[test]
    fn test_validate_add_both_zero_returns_error() {
        let resp = parse_and_validate_request(
            r#"{"command": "add", "ip": "10.0.0.0/8", "rate": 0, "burst": 0}"#,
        ).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("rate and burst must be positive"));
    }

    // Valid command parsing tests

    #[test]
    fn test_validate_valid_add_command() {
        let req = parse_and_validate_request(
            r#"{"command": "add", "ip": "192.168.1.0/24", "rate": 1048576, "burst": 2097152}"#,
        ).unwrap();
        assert_eq!(req, Request::Add {
            ip: "192.168.1.0/24".to_string(),
            rate: 1048576,
            burst: 2097152,
        });
    }

    #[test]
    fn test_validate_valid_delete_command() {
        let req = parse_and_validate_request(r#"{"command": "delete", "ip": "10.0.0.1"}"#).unwrap();
        assert_eq!(req, Request::Delete { ip: "10.0.0.1".to_string() });
    }

    #[test]
    fn test_validate_valid_list_command() {
        let req = parse_and_validate_request(r#"{"command": "list"}"#).unwrap();
        assert_eq!(req, Request::List);
    }

    // Error response structure tests

    #[test]
    fn test_validate_error_response_has_no_data() {
        let resp = parse_and_validate_request("garbage").unwrap_err();
        assert!(resp.data.is_none());
    }

    #[test]
    fn test_validate_add_missing_fields_returns_error() {
        let resp = parse_and_validate_request(r#"{"command": "add", "ip": "10.0.0.0/8"}"#).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.is_some());
    }
}
