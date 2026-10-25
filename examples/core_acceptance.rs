//! Local acceptance with synthetic credentials; never reads the user's node store.
use proxypilot::{
    config::generate_config,
    core,
    nodes::{NodeRecord, NodeSecret},
    runtime::RuntimeManager,
};
fn main() -> Result<(), String> {
    let path = match std::env::args().nth(1) {
        Some(path) => path.into(),
        None => core::download_official()?,
    };
    let directory =
        std::env::temp_dir().join(format!("proxypilot-acceptance-{}", uuid::Uuid::new_v4()));
    let mut runtime = RuntimeManager::with_directory(directory.clone());
    println!("{}", runtime.choose_core(path)?);
    for count in [1, 2, 10] {
        let reservations: Vec<_> = (0..count)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let nodes: Vec<_> = reservations
            .iter()
            .enumerate()
            .map(|(i, socket)| NodeRecord {
                id: format!("fixture-{i}"),
                name: format!("Fixture {i}"),
                server: "127.0.0.1".into(),
                server_port: 9,
                enabled: true,
                sni: Some("example.invalid".into()),
                insecure: false,
                obfs_type: None,
                warnings: vec![],
                profile_name: format!("Profile {i}"),
                listen_port: socket.local_addr().unwrap().port(),
                secret_key: "fixture".into(),
            })
            .collect();
        let config = generate_config(&nodes, |_| {
            Ok(NodeSecret {
                password: "synthetic-only".into(),
                obfs_password: None,
            })
        })
        .map_err(|e| e.to_string())?;
        runtime.check_only(&config)?;
        assert!(!directory.join("runtime.json").exists());
        assert!(
            runtime.start_config(config.clone()).is_err(),
            "occupied ports must block startup"
        );
        drop(reservations);
        runtime.start_config(config)?;
        assert!(runtime.is_running());
        runtime.stop()?;
        assert!(!runtime.is_running());
        assert!(!directory.join("runtime.json").exists());
        println!("{count} nodes: check, conflict handling, listeners, stop and cleanup passed");
    }
    drop(runtime);
    let _ = std::fs::remove_dir(&directory);
    Ok(())
}
