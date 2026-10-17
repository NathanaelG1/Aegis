#![cfg(all(feature = "sprite-demo", unix))]

#[test]
fn authenticated_http_and_separate_mcp_agent_workflow() {
    let output = std::process::Command::new("python3")
        .args([
            "scripts/sprite_evidence.py",
            "--binary",
            env!("CARGO_BIN_EXE_aegis"),
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("Python 3 is required for the HTTP/MCP evidence harness");
    assert!(
        output.status.success(),
        "synthetic HTTP/MCP evidence failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], true);
    assert!(report["checks_passed"].as_u64().unwrap() >= 50);
}
