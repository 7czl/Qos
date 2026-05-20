use anyhow::{anyhow, Result};
use qos_common::LpmKeyV4;
use serde::{Deserialize, Serialize};

/// Direction of traffic to which a rule applies.
///
/// - `Download`: incoming traffic (TC ingress), matched against source IP.
/// - `Upload`: outgoing traffic (TC egress), matched against destination IP.
/// - `Both`: rule is installed in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Download,
    Upload,
    Both,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::Download
    }
}

/// JSON request from the UDS client.
///
/// Uses tagged enum deserialization: the `"command"` field determines the variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum Request {
    #[serde(rename = "add")]
    Add {
        ip: String,
        rate: u64,
        burst: u64,
        #[serde(default)]
        direction: Direction,
    },
    #[serde(rename = "delete")]
    Delete {
        ip: String,
        #[serde(default)]
        direction: Direction,
    },
    #[serde(rename = "list")]
    List {
        #[serde(default)]
        direction: Option<Direction>,
    },
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
    pub direction: Direction,
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
        assert_eq!(key.addr, 0xC0A80100_u32.to_be());
    }

    #[test]
    fn test_parse_cidr_single_host() {
        let key = parse_cidr("10.0.0.1").unwrap();
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
    fn test_format_cidr_24() {
        let key = LpmKeyV4 {
            prefix_len: 24,
            addr: 0xC0A80100_u32.to_be(),
        };
        assert_eq!(format_cidr(&key), "192.168.1.0/24");
    }

    #[test]
    fn test_parse_format_roundtrip() {
        let input = "172.16.0.0/12";
        let key = parse_cidr(input).unwrap();
        assert_eq!(format_cidr(&key), input);
    }

    // --- Request serde tests ---

    #[test]
    fn test_request_add_default_direction() {
        // Backward compatibility: missing "direction" defaults to download
        let json = r#"{"command": "add", "ip": "192.168.1.0/24", "rate": 1048576, "burst": 2097152}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(
            req,
            Request::Add {
                ip: "192.168.1.0/24".to_string(),
                rate: 1048576,
                burst: 2097152,
                direction: Direction::Download,
            }
        );
    }

    #[test]
    fn test_request_add_upload() {
        let json = r#"{"command":"add","ip":"10.0.0.0/8","rate":500000,"burst":1000000,"direction":"upload"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(
            req,
            Request::Add {
                ip: "10.0.0.0/8".to_string(),
                rate: 500000,
                burst: 1000000,
                direction: Direction::Upload,
            }
        );
    }

    #[test]
    fn test_request_add_both() {
        let json = r#"{"command":"add","ip":"10.0.0.0/8","rate":500000,"burst":1000000,"direction":"both"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        if let Request::Add { direction, .. } = req {
            assert_eq!(direction, Direction::Both);
        } else {
            panic!("expected Add");
        }
    }

    #[test]
    fn test_request_delete_default_direction() {
        let json = r#"{"command": "delete", "ip": "192.168.1.0/24"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(
            req,
            Request::Delete {
                ip: "192.168.1.0/24".to_string(),
                direction: Direction::Download,
            }
        );
    }

    #[test]
    fn test_request_list_no_filter() {
        let json = r#"{"command": "list"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req, Request::List { direction: None });
    }

    #[test]
    fn test_request_list_filter_upload() {
        let json = r#"{"command":"list","direction":"upload"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(
            req,
            Request::List {
                direction: Some(Direction::Upload)
            }
        );
    }

    // --- parse_and_validate_request tests ---

    #[test]
    fn test_validate_invalid_json_returns_error() {
        let resp = parse_and_validate_request("not json at all").unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("invalid JSON"));
    }

    #[test]
    fn test_validate_unknown_command_returns_error() {
        let resp = parse_and_validate_request(r#"{"command": "restart"}"#).unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp.message.as_ref().unwrap().contains("unknown command: restart"));
    }

    #[test]
    fn test_validate_add_rate_zero_returns_error() {
        let resp = parse_and_validate_request(
            r#"{"command":"add","ip":"10.0.0.0/8","rate":0,"burst":1024}"#,
        )
        .unwrap_err();
        assert_eq!(resp.status, "error");
        assert!(resp
            .message
            .as_ref()
            .unwrap()
            .contains("rate and burst must be positive"));
    }

    #[test]
    fn test_validate_valid_add_with_direction() {
        let req = parse_and_validate_request(
            r#"{"command":"add","ip":"192.168.1.0/24","rate":1048576,"burst":2097152,"direction":"upload"}"#,
        )
        .unwrap();
        assert_eq!(
            req,
            Request::Add {
                ip: "192.168.1.0/24".to_string(),
                rate: 1048576,
                burst: 2097152,
                direction: Direction::Upload,
            }
        );
    }

    // --- Property-based tests ---

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: ebpf-download-rate-limiter, Property 4: CIDR parse correctness
        #[test]
        fn property_cidr_parse_correctness(
            a in 0u8..=255u8,
            b in 0u8..=255u8,
            c in 0u8..=255u8,
            d in 0u8..=255u8,
            prefix_len in 0u32..=32u32,
        ) {
            let cidr = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix_len);
            let key = parse_cidr(&cidr).unwrap();
            prop_assert_eq!(key.prefix_len, prefix_len);
            let expected_addr_be = u32::from_be_bytes([a, b, c, d]).to_be();
            prop_assert_eq!(key.addr, expected_addr_be);
            let formatted = format_cidr(&key);
            let roundtrip_key = parse_cidr(&formatted).unwrap();
            prop_assert_eq!(roundtrip_key.prefix_len, key.prefix_len);
            prop_assert_eq!(roundtrip_key.addr, key.addr);
        }

        // Feature: ebpf-download-rate-limiter, Property 6: JSON roundtrip
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
            dir_idx in 0u8..=2u8,
        ) {
            let ip = format!("{}.{}.{}.{}/{}", a, b, c, d, prefix_len);
            let direction = match dir_idx {
                0 => Direction::Download,
                1 => Direction::Upload,
                _ => Direction::Both,
            };
            let request = match variant {
                0 => Request::Add { ip: ip.clone(), rate, burst, direction },
                1 => Request::Delete { ip: ip.clone(), direction },
                _ => Request::List { direction: Some(direction) },
            };
            let json = serde_json::to_string(&request).unwrap();
            let deserialized: Request = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&deserialized, &request);
        }
    }
}
