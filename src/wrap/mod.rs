use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

/// Known MCP client config locations.
struct McpClient {
    name: &'static str,
    config_path: PathBuf,
}

fn detect_clients() -> Vec<McpClient> {
    let home = match std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        Ok(h) => PathBuf::from(h),
        Err(_) => return vec![],
    };

    fn claude_desktop_path(home: &std::path::Path) -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            Some(home.join("Library/Application Support/Claude/claude_desktop_config.json"))
        }
        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA")
                .ok()
                .map(|a| PathBuf::from(a).join("Claude/claude_desktop_config.json"))
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = home;
            None
        }
    }

    let mut clients = Vec::new();

    if let Some(path) = claude_desktop_path(&home) {
        clients.push(McpClient {
            name: "Claude Desktop",
            config_path: path,
        });
    }

    clients.push(McpClient {
        name: "Cursor",
        config_path: home.join(".cursor/mcp.json"),
    });
    clients.push(McpClient {
        name: "Windsurf",
        config_path: home.join(".codeium/windsurf/mcp_config.json"),
    });

    clients
}

/// Get the path to the estoppl binary.
fn estoppl_bin_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "estoppl".to_string())
}

/// Resolve the absolute path to estoppl.toml in the current directory (if it exists).
fn config_path() -> Option<String> {
    std::env::current_dir()
        .ok()
        .map(|d| d.join("estoppl.toml"))
        .filter(|p| p.exists())
        .and_then(|p| p.to_str().map(String::from))
}

/// Wrap a single MCP client config. Returns (servers_wrapped, servers_skipped).
fn wrap_config(config: &mut Value, config_path: Option<&str>) -> (usize, usize) {
    let mut wrapped = 0;
    let mut skipped = 0;

    let servers = match config.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        Some(s) => s,
        None => return (0, 0),
    };

    let bin = estoppl_bin_path();

    for (_name, server) in servers.iter_mut() {
        let obj = match server.as_object_mut() {
            Some(o) => o,
            None => continue,
        };

        // Skip already wrapped
        if obj.get("_estoppl_wrapped").and_then(|v| v.as_bool()) == Some(true) {
            skipped += 1;
            continue;
        }

        // Skip HTTP-only servers (no command field)
        let original_cmd = match obj.get("command").and_then(|v| v.as_str()) {
            Some(cmd) => cmd.to_string(),
            None => {
                skipped += 1;
                continue;
            }
        };

        let original_args: Vec<Value> = obj
            .get("args")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Save original for restore
        let mut original = serde_json::Map::new();
        original.insert("command".to_string(), Value::String(original_cmd.clone()));
        original.insert("args".to_string(), Value::Array(original_args.clone()));
        obj.insert("_estoppl_original".to_string(), Value::Object(original));

        // Build new args: ["start", [--config <path>], "--upstream-cmd", original_cmd, "--upstream-args", ...original_args]
        let mut new_args: Vec<Value> = vec![Value::String("start".to_string())];
        if let Some(cp) = config_path {
            new_args.push(Value::String("--config".to_string()));
            new_args.push(Value::String(cp.to_string()));
        }
        new_args.push(Value::String("--upstream-cmd".to_string()));
        new_args.push(Value::String(original_cmd));
        if !original_args.is_empty() {
            new_args.push(Value::String("--upstream-args".to_string()));
            new_args.extend(original_args);
        }

        obj.insert("command".to_string(), Value::String(bin.clone()));
        obj.insert("args".to_string(), Value::Array(new_args));
        obj.insert("_estoppl_wrapped".to_string(), Value::Bool(true));

        wrapped += 1;
    }

    (wrapped, skipped)
}

/// Restore a wrapped config to its original state. Returns number restored.
fn restore_config(config: &mut Value) -> usize {
    let mut restored = 0;

    let servers = match config.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        Some(s) => s,
        None => return 0,
    };

    for (_name, server) in servers.iter_mut() {
        let obj = match server.as_object_mut() {
            Some(o) => o,
            None => continue,
        };

        if obj.get("_estoppl_wrapped").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }

        if let Some(original) = obj.get("_estoppl_original").cloned()
            && let Some(orig_obj) = original.as_object()
        {
            if let Some(cmd) = orig_obj.get("command") {
                obj.insert("command".to_string(), cmd.clone());
            }
            if let Some(args) = orig_obj.get("args") {
                obj.insert("args".to_string(), args.clone());
            }
        }

        obj.remove("_estoppl_wrapped");
        obj.remove("_estoppl_original");
        restored += 1;
    }

    restored
}

/// Auto-wrap MCP client configs to route tool calls through estoppl.
///
/// Discovers MCP client configs (Claude Desktop, Cursor, Windsurf) and rewrites
/// each stdio server entry to launch via `estoppl start`. If `estoppl.toml` exists
/// in the current directory, its absolute path is embedded via `--config` so the
/// proxy finds its config regardless of the MCP client's working directory.
///
/// Creates a `.estoppl-backup` file before first modification. Idempotent — already
/// wrapped servers are skipped. HTTP-only servers (no `command` field) are skipped.
/// Use `restore=true` (or `estoppl unwrap`) to reverse.
pub fn run_wrap(dry_run: bool, restore: bool, client_filter: Option<&str>) -> Result<()> {
    let clients = detect_clients();
    let cp = config_path();
    let mut found_any = false;

    if !restore && cp.is_none() {
        anyhow::bail!(
            "estoppl.toml not found in current directory ({}). \
             Run `estoppl init` first, or `cd` to the directory containing estoppl.toml.",
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        );
    }

    for client in &clients {
        if let Some(filter) = client_filter {
            let name = client.name.to_lowercase();
            let f = filter.to_lowercase().replace("-", " ");
            if !name.contains(&f) && !name.replace(" ", "-").contains(&filter.to_lowercase()) {
                continue;
            }
        }

        if !client.config_path.exists() {
            continue;
        }

        found_any = true;
        let path = &client.config_path;
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let mut config: Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        if restore {
            let count = restore_config(&mut config);
            if count == 0 {
                println!("{}: nothing to restore", client.name);
                continue;
            }
            if dry_run {
                println!("{}: would restore {} servers (dry run)", client.name, count);
                continue;
            }
            let output = serde_json::to_string_pretty(&config)?;
            std::fs::write(path, &output)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            println!("{}: restored {} servers", client.name, count);
        } else {
            // Create backup before wrapping
            let backup_path = path.with_extension("json.estoppl-backup");
            if !backup_path.exists() && !dry_run {
                std::fs::copy(path, &backup_path).with_context(|| {
                    format!("Failed to create backup at {}", backup_path.display())
                })?;
            }

            let (wrapped, skipped) = wrap_config(&mut config, cp.as_deref());
            if wrapped == 0 {
                println!(
                    "{}: no servers to wrap ({} already wrapped or HTTP-only)",
                    client.name, skipped
                );
                continue;
            }

            if dry_run {
                println!("{}: would wrap {} servers (dry run)", client.name, wrapped);
                println!("  Config: {}", path.display());
                // Show preview
                let preview = serde_json::to_string_pretty(&config)?;
                println!("{}", preview);
                continue;
            }

            let output = serde_json::to_string_pretty(&config)?;
            std::fs::write(path, &output)
                .with_context(|| format!("Failed to write {}", path.display()))?;
            println!(
                "{}: wrapped {} servers ({} skipped)",
                client.name, wrapped, skipped
            );
            println!("  Config: {}", path.display());
            println!("  Backup: {}", backup_path.display());
        }
    }

    if !found_any {
        println!("No MCP client configs found. Looked for:");
        for client in &clients {
            println!("  {}: {}", client.name, client.config_path.display());
        }
    } else if !dry_run && !restore {
        println!();
        println!("Restart your IDE (Cursor, Claude Desktop) to activate estoppl.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Value {
        serde_json::json!({
            "mcpServers": {
                "stripe": {
                    "command": "npx",
                    "args": ["@stripe/mcp-server"]
                },
                "github": {
                    "command": "npx",
                    "args": ["@github/mcp-server", "--token", "abc"]
                },
                "remote": {
                    "url": "http://localhost:3000/mcp"
                }
            }
        })
    }

    #[test]
    fn wrap_transforms_stdio_servers() {
        let mut config = sample_config();
        let (wrapped, skipped) = wrap_config(&mut config, None);

        assert_eq!(wrapped, 2); // stripe + github
        assert_eq!(skipped, 1); // remote (HTTP-only)

        let stripe = &config["mcpServers"]["stripe"];
        assert_eq!(stripe["_estoppl_wrapped"], true);
        assert!(
            stripe["command"].as_str().unwrap().contains("estoppl")
                || stripe["command"] == "estoppl"
        );

        let args: Vec<&str> = stripe["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args[0], "start");
        assert_eq!(args[1], "--upstream-cmd");
        assert_eq!(args[2], "npx");
        assert_eq!(args[3], "--upstream-args");
        assert_eq!(args[4], "@stripe/mcp-server");
    }

    #[test]
    fn wrap_is_idempotent() {
        let mut config = sample_config();
        let (wrapped1, _) = wrap_config(&mut config, None);
        let (wrapped2, skipped2) = wrap_config(&mut config, None);

        assert_eq!(wrapped1, 2);
        assert_eq!(wrapped2, 0);
        assert_eq!(skipped2, 3); // 2 already wrapped + 1 HTTP
    }

    #[test]
    fn restore_reverses_wrap() {
        let mut config = sample_config();
        let original = config.clone();

        wrap_config(&mut config, None);
        assert_ne!(config, original);

        let restored = restore_config(&mut config);
        assert_eq!(restored, 2);

        // After restore, the config should match original (minus the HTTP server which was untouched)
        assert_eq!(
            config["mcpServers"]["stripe"]["command"],
            original["mcpServers"]["stripe"]["command"]
        );
        assert_eq!(
            config["mcpServers"]["stripe"]["args"],
            original["mcpServers"]["stripe"]["args"]
        );
        assert!(
            config["mcpServers"]["stripe"]
                .get("_estoppl_wrapped")
                .is_none()
        );
    }

    #[test]
    fn skips_http_only_servers() {
        let mut config = serde_json::json!({
            "mcpServers": {
                "remote": {
                    "url": "http://localhost:3000/mcp"
                }
            }
        });
        let (wrapped, skipped) = wrap_config(&mut config, None);
        assert_eq!(wrapped, 0);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn handles_empty_config() {
        let mut config = serde_json::json!({});
        let (wrapped, skipped) = wrap_config(&mut config, None);
        assert_eq!(wrapped, 0);
        assert_eq!(skipped, 0);
    }
}
