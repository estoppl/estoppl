use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request envelope used by MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// The MCP tools/call params we care about intercepting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

impl JsonRpcRequest {
    pub fn is_tool_call(&self) -> bool {
        self.method == "tools/call"
    }

    /// Extract tool call params from a tools/call request.
    pub fn tool_call_params(&self) -> Option<ToolCallParams> {
        if !self.is_tool_call() {
            return None;
        }
        self.params
            .as_ref()
            .and_then(|p| serde_json::from_value(p.clone()).ok())
    }
}

impl JsonRpcResponse {
    pub fn error(id: Option<serde_json::Value>, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tools_call_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stripe.create_payment","arguments":{"amount":100}}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.is_tool_call());
        let params = req.tool_call_params().unwrap();
        assert_eq!(params.name, "stripe.create_payment");
        assert_eq!(params.arguments["amount"], 100);
    }

    #[test]
    fn parse_non_tool_call() {
        let json = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(!req.is_tool_call());
        assert!(req.tool_call_params().is_none());
    }

    #[test]
    fn parse_notification_no_id() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
        assert!(!req.is_tool_call());
    }

    #[test]
    fn parse_success_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn parse_error_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"blocked"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32001);
        assert_eq!(err.message, "blocked");
    }

    #[test]
    fn error_response_serializes_correctly() {
        let resp = JsonRpcResponse::error(
            Some(serde_json::json!(42)),
            -32001,
            "Blocked by policy".to_string(),
        );
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("-32001"));
        assert!(json.contains("Blocked by policy"));
        assert!(json.contains("42"));
    }

    #[test]
    fn tools_call_with_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc-123","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp"}}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.is_tool_call());
        assert_eq!(req.id, Some(serde_json::json!("abc-123")));
    }
}
