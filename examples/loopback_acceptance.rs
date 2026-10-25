//! Real HY2 protocol/failure test against a local fixture server. Public HTTPS
//! services see this machine's normal egress IP. Never reads production nodes.
use proxypilot::{
    config::generate_config,
    diagnostics,
    nodes::{NodeRecord, NodeSecret, SecretVault, WindowsCredentialVault},
    process,
    runtime::RuntimeManager,
    settings::Settings,
};
use serde_json::json;
use std::{
    path::PathBuf,
    process::{Child, Stdio},
    time::Duration,
};
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: loopback_acceptance <sing-box.exe> <fixture-cert.pem> <fixture-key.pem>".into(),
        );
    }
    let core = PathBuf::from(&args[0]);
    let directory =
        std::env::temp_dir().join(format!("proxypilot-loopback-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).map_err(|_| "cannot create fixture dir")?;
    // Verify the actual Windows backend using a unique, synthetic entry.
    let vault = WindowsCredentialVault;
    let key = format!("acceptance-{}", uuid::Uuid::new_v4());
    vault.set(&key, "synthetic-acceptance-secret")?;
    let retrieved = vault.get(&key);
    vault.delete(&key)?;
    if retrieved? != "synthetic-acceptance-secret" {
        return Err("native credential roundtrip failed".into());
    }
    println!("Native Windows credential roundtrip and deletion passed");
    let sockets: Vec<_> = (0..2)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<_> = sockets
        .iter()
        .map(|s| s.local_addr().unwrap().port())
        .collect();
    let server_config = json!({"log":{"disabled":true},"dns":{"servers":[{"type":"local","tag":"local"}]},
        "route":{"default_domain_resolver":"local"},
        "inbounds":ports.iter().enumerate().map(|(i,p)| json!({"type":"hysteria2","tag":format!("server-{i}"),"listen":"127.0.0.1","listen_port":p,"users":[{"name":"fixture","password":"synthetic-only"}],"tls":{"enabled":true,"certificate_path":args[1],"key_path":args[2]}})).collect::<Vec<_>>(),"outbounds":[{"type":"direct"}]});
    let server_path = directory.join("server.json");
    proxypilot::settings::write_json(&server_path, &server_config)?;
    let mut check = process::command(&core);
    check.arg("check").arg("-c").arg(&server_path);
    let checked = process::output(check, Duration::from_secs(15))?;
    if !checked.status.success() {
        return Err(format!(
            "fixture server config failed: {}",
            String::from_utf8_lossy(&checked.stderr)
        ));
    }
    drop(sockets);
    let mut server = Server(
        process::command(&core)
            .arg("run")
            .arg("-c")
            .arg(&server_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot start fixture server")?,
    );
    std::thread::sleep(Duration::from_millis(500));
    if server
        .0
        .try_wait()
        .map_err(|_| "fixture state error")?
        .is_some()
    {
        return Err("fixture server exited".into());
    }
    let listeners: Vec<_> = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let nodes: Vec<_> = ports
        .iter()
        .enumerate()
        .map(|(i, p)| NodeRecord {
            id: format!("loopback-{i}"),
            name: format!("Local {i}"),
            server: "127.0.0.1".into(),
            server_port: *p,
            enabled: true,
            sni: Some("localhost".into()),
            insecure: true,
            obfs_type: None,
            warnings: vec![],
            profile_name: format!("Local {i}"),
            listen_port: listeners[i].local_addr().unwrap().port(),
            secret_key: "synthetic".into(),
        })
        .collect();
    let config = generate_config(&nodes, |_| {
        Ok(NodeSecret {
            password: "synthetic-only".into(),
            obfs_password: None,
        })
    })
    .map_err(|e| e.to_string())?;
    drop(listeners);
    let mut runtime = RuntimeManager::with_directory(directory.join("client"));
    runtime.choose_core(core)?;
    runtime.start_config(config)?;
    let settings = Settings {
        ip_url: "https://icanhazip.com/".into(),
        ..Settings::default()
    };
    let ports: Vec<_> = nodes.iter().map(|n| n.listen_port).collect();
    let dns = diagnostics::batch(&ports, true, &settings);
    if !dns.iter().all(|r| r.success) {
        return Err(format!(
            "HY2 remote DNS request failed: {:?}",
            dns.iter().map(|r| &r.message).collect::<Vec<_>>()
        ));
    }
    println!("Two real loopback HY2 remote-DNS HTTPS requests passed");
    let results = runtime.isolation_test(&nodes[0].id, nodes[0].listen_port, &settings)?;
    let passed = results.iter().all(|r| {
        if r.kind == "isolation_fault" && r.port == nodes[0].listen_port {
            !r.success
        } else {
            r.success
        }
    });
    runtime.stop()?;
    drop(runtime);
    drop(server);
    let _ = std::fs::remove_file(server_path);
    let _ = std::fs::remove_dir(directory.join("client"));
    let _ = std::fs::remove_dir(directory);
    if !passed {
        return Err("failure isolation/recovery did not pass".into());
    }
    println!("HY2 baseline, selected failure, unaffected endpoint and recovery passed");
    Ok(())
}
