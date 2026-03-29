use std::io::Write;
use std::process::{Command, Stdio};

/// Get the absolute path to the estoppl binary.
fn estoppl_bin() -> String {
    // cargo sets this env var pointing to the workspace root during `cargo test`
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set — run via `cargo test`");
    let bin_path = std::path::Path::new(&manifest_dir)
        .join("target")
        .join("debug")
        .join("estoppl");

    // Build if not already built.
    if !bin_path.exists() {
        let output = Command::new("cargo")
            .args(["build", "--quiet"])
            .current_dir(&manifest_dir)
            .output()
            .expect("Failed to build");
        assert!(output.status.success(), "cargo build failed");
    }

    assert!(bin_path.exists(), "Binary not found at {:?}", bin_path);
    bin_path.to_str().unwrap().to_string()
}

#[test]
fn test_init_creates_config_and_keys() {
    let dir = tempfile::TempDir::new().unwrap();

    let output = Command::new(estoppl_bin())
        .args(["init", "--agent-id", "test-bot"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "init failed: {}", stdout);
    assert!(stdout.contains("Created estoppl.toml"));
    assert!(stdout.contains("Generated Ed25519 keypair"));

    // Verify files created.
    assert!(dir.path().join("estoppl.toml").exists());
    assert!(
        dir.path()
            .join(".estoppl/keys/estoppl-signing.key")
            .exists()
    );
    assert!(
        dir.path()
            .join(".estoppl/keys/estoppl-signing.pub")
            .exists()
    );
    assert!(dir.path().join(".estoppl/events.db").exists());

    // Verify config content.
    let config = std::fs::read_to_string(dir.path().join("estoppl.toml")).unwrap();
    assert!(config.contains("test-bot"));
}

#[test]
fn test_init_fails_if_config_exists() {
    let dir = tempfile::TempDir::new().unwrap();

    // First init should succeed.
    let output = Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    // Second init should fail.
    let output = Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_audit_empty_db() {
    let dir = tempfile::TempDir::new().unwrap();

    // Init first.
    Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = Command::new(estoppl_bin())
        .args(["audit"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("No events found"));
}

#[test]
fn test_audit_verify_empty_db() {
    let dir = tempfile::TempDir::new().unwrap();

    Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = Command::new(estoppl_bin())
        .args(["audit", "--verify"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("INTACT"));
}

#[test]
fn test_report_empty_db() {
    let dir = tempfile::TempDir::new().unwrap();

    Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = Command::new(estoppl_bin())
        .args(["report"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let report_path = dir.path().join("estoppl-report.html");
    assert!(report_path.exists());

    let html = std::fs::read_to_string(report_path).unwrap();
    assert!(html.contains("Estoppl"));
    assert!(html.contains("For internal review"));
}

#[test]
fn test_stats_empty_db() {
    let dir = tempfile::TempDir::new().unwrap();

    Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = Command::new(estoppl_bin())
        .args(["stats"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("No events recorded yet"));
}

#[test]
fn test_report_custom_output_path() {
    let dir = tempfile::TempDir::new().unwrap();

    Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let output = Command::new(estoppl_bin())
        .args(["report", "--output", "custom-report.html"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(dir.path().join("custom-report.html").exists());
}

#[test]
fn test_audit_filters() {
    let dir = tempfile::TempDir::new().unwrap();

    Command::new(estoppl_bin())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Filter by tool — should return no events (empty db)
    let output = Command::new(estoppl_bin())
        .args(["audit", "--tool", "stripe.create_payment"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("No events found"));

    // Filter by decision
    let output = Command::new(estoppl_bin())
        .args(["audit", "--decision", "block"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());

    // Filter by since
    let output = Command::new(estoppl_bin())
        .args(["audit", "--since", "2026-01-01T00:00:00Z"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());
}

#[test]
fn test_help_output() {
    let output = Command::new(estoppl_bin())
        .args(["--help"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("init"));
    assert!(stdout.contains("start"));
    assert!(stdout.contains("start-http"));
    assert!(stdout.contains("audit"));
    assert!(stdout.contains("report"));
    assert!(stdout.contains("tail"));
    assert!(stdout.contains("stats"));
    assert!(stdout.contains("wrap"));
    assert!(stdout.contains("unwrap"));
    assert!(stdout.contains("dashboard"));
}

#[test]
fn test_wrap_dry_run() {
    let dir = tempfile::TempDir::new().unwrap();

    // Create a fake MCP client config
    let config_dir = dir.path().join("fake-client");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("mcp.json");
    std::fs::write(
        &config_path,
        r#"{
            "mcpServers": {
                "stripe": {
                    "command": "npx",
                    "args": ["@stripe/mcp-server"]
                }
            }
        }"#,
    )
    .unwrap();

    // wrap --dry-run shouldn't modify the file
    let output = Command::new(estoppl_bin())
        .args(["wrap", "--dry-run"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(output.status.success());

    // Original file should be unchanged
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("\"command\": \"npx\"") || content.contains("\"command\":\"npx\""));
}

#[test]
fn test_wrap_no_configs_found() {
    let dir = tempfile::TempDir::new().unwrap();

    let output = Command::new(estoppl_bin())
        .args(["wrap"])
        .current_dir(dir.path())
        .env("HOME", dir.path().to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("No MCP client configs found"));
}

#[test]
fn test_stdio_proxy_with_fake_server() {
    let dir = tempfile::TempDir::new().unwrap();

    // Init.
    Command::new(estoppl_bin())
        .args(["init", "--agent-id", "e2e-agent"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    // Write a fake MCP server script that echoes back results.
    let script_path = dir.path().join("fake-mcp.sh");
    std::fs::write(
        &script_path,
        r#"#!/bin/bash
while IFS= read -r line; do
    id=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('id',''))" 2>/dev/null)
    if [ -n "$id" ]; then
        echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}"
    fi
done
"#,
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Start the proxy with the fake server, send a tool call, read the response.
    let mut child = Command::new(estoppl_bin())
        .args([
            "start",
            "--upstream-cmd",
            "bash",
            "--upstream-args",
            script_path.to_str().unwrap(),
        ])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy");

    let child_stdin = child.stdin.as_mut().unwrap();

    // Send an allowed tool call.
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_portfolio","arguments":{}}}"#;
    writeln!(child_stdin, "{}", req).unwrap();

    // Send a tool call that should be blocked (amount over threshold).
    let req_blocked = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_payment","arguments":{"amount":999999}}}"#;
    writeln!(child_stdin, "{}", req_blocked).unwrap();

    // Close stdin to signal EOF.
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have received responses for both calls.
    // Call 1: forwarded to upstream, got result back.
    // Call 2: blocked by policy, got error response.
    assert!(
        stdout.contains("\"id\":2") || stdout.contains("\"id\": 2"),
        "Expected response for blocked call, got: {}",
        stdout
    );

    // Now check the audit log.
    let audit_output = Command::new(estoppl_bin())
        .args(["audit", "-n", "10"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let audit_stdout = String::from_utf8_lossy(&audit_output.stdout);

    // Should show the tool calls.
    assert!(
        audit_stdout.contains("BLOCK") || audit_stdout.contains("ALLOW"),
        "Audit should contain logged events: {}",
        audit_stdout
    );

    // Verify chain integrity.
    let verify_output = Command::new(estoppl_bin())
        .args(["audit", "--verify"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(
        verify_stdout.contains("INTACT"),
        "Chain should be intact: {}",
        verify_stdout
    );
}

#[test]
fn test_config_relative_db_path() {
    // When --config points to a file in a subdirectory, the relative db_path
    // should resolve against the config file's directory, not the process cwd.
    let dir = tempfile::TempDir::new().unwrap();

    // Create a subdirectory with estoppl.toml
    let sub = dir.path().join("project");
    std::fs::create_dir_all(&sub).unwrap();

    // Init in the subdirectory
    let output = Command::new(estoppl_bin())
        .args(["init", "--agent-id", "test-agent"])
        .current_dir(&sub)
        .output()
        .unwrap();
    assert!(output.status.success(), "init failed");

    // The db should be at project/.estoppl/events.db
    assert!(sub.join(".estoppl/events.db").exists());

    // Now run audit from the parent dir using --config pointing to the subdirectory
    let output = Command::new(estoppl_bin())
        .args([
            "audit",
            "-n",
            "5",
            "--config",
            sub.join("estoppl.toml").to_str().unwrap(),
        ])
        .current_dir(dir.path()) // different from config location
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "audit should succeed with --config from different cwd: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("No events found"),
        "Should read the correct db: {}",
        stdout
    );
}

#[test]
fn test_wrap_embeds_config_path() {
    let dir = tempfile::TempDir::new().unwrap();

    // Create estoppl.toml in the working directory
    std::fs::write(
        dir.path().join("estoppl.toml"),
        "[agent]\nid = \"test\"\n",
    )
    .unwrap();

    // Create a fake MCP client config
    let fake_home = dir.path().join("fakehome");
    std::fs::create_dir_all(fake_home.join(".cursor")).unwrap();
    std::fs::write(
        fake_home.join(".cursor/mcp.json"),
        r#"{"mcpServers":{"test":{"command":"echo","args":["hello"]}}}"#,
    )
    .unwrap();

    // Run wrap with HOME pointing to fake home
    let output = Command::new(estoppl_bin())
        .args(["wrap", "--client", "cursor"])
        .current_dir(dir.path())
        .env("HOME", fake_home.to_str().unwrap())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "wrap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read the wrapped config and verify --config is embedded
    let wrapped = std::fs::read_to_string(fake_home.join(".cursor/mcp.json")).unwrap();
    let config: serde_json::Value = serde_json::from_str(&wrapped).unwrap();
    let args = config["mcpServers"]["test"]["args"]
        .as_array()
        .expect("args should be array");

    let args_str: Vec<&str> = args.iter().map(|v| v.as_str().unwrap()).collect();

    // Should contain --config with the absolute path
    assert!(
        args_str.contains(&"--config"),
        "Wrapped args should contain --config: {:?}",
        args_str
    );

    let config_idx = args_str.iter().position(|a| *a == "--config").unwrap();
    let config_path = args_str[config_idx + 1];
    assert!(
        config_path.ends_with("estoppl.toml"),
        "Config path should point to estoppl.toml: {}",
        config_path
    );
    assert!(
        std::path::Path::new(config_path).is_absolute(),
        "Config path should be absolute: {}",
        config_path
    );
}
