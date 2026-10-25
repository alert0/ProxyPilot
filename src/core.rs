use crate::{
    process,
    settings::{data_dir, write_json},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub fn sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|_| "无法读取核心文件")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|_| "无法计算核心哈希")?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub fn verify_hash(path: &Path, expected: &str) -> Result<String, String> {
    let actual = sha256(path)?;
    if expected.len() != 64
        || !expected.bytes().all(|b| b.is_ascii_hexdigit())
        || !actual.eq_ignore_ascii_case(expected)
    {
        return Err("SHA-256 不匹配，已拒绝使用该文件".into());
    }
    Ok(actual)
}

fn transfer_error(stage: &str, code: Option<i32>, http: Option<u16>) -> String {
    let reason = match code {
        Some(5) => "无法解析下载代理地址，请检查代理环境变量",
        Some(6) => "无法解析官方域名，请检查 DNS 与网络",
        Some(7) => "无法连接官方服务器或下载代理",
        Some(22) => "官方服务器返回 HTTP 错误，可能是限流或临时不可用",
        Some(23) => "无法写入下载文件，请检查磁盘空间与目录权限",
        Some(28) => "网络连接或传输超时，请稍后重试，或手动选择本地核心",
        Some(35) => "TLS 握手失败，请检查网络、代理或 HTTPS 检查软件",
        Some(60) => "服务器证书校验失败，未跳过证书验证",
        Some(63) => "下载文件超过 100 MiB 限制",
        _ => "下载工具执行失败，请检查网络或使用本地核心",
    };
    format!(
        "{stage}失败：{reason}（curl {:?}，HTTP {}）",
        code,
        http.map_or("未知".into(), |code| code.to_string())
    )
}

/// Fetch the Windows x64 asset only from the official release; fail closed if
/// GitHub does not supply a SHA-256 digest. A digest is not a publisher signature.
pub fn download_official() -> Result<PathBuf, String> {
    let mut cmd = process::command("curl.exe");
    cmd.args([
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-time",
        "15",
        "--connect-timeout",
        "10",
        "--retry",
        "2",
        "--retry-delay",
        "1",
        "--retry-max-time",
        "40",
        "--retry-all-errors",
        "--user-agent",
        "ProxyPilot",
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
    ]);
    let result = process::output(cmd, Duration::from_secs(60))
        .map_err(|error| format!("查询官方版本：{error}"))?;
    if !result.status.success() {
        return Err(transfer_error(
            "查询官方发布信息",
            result.status.code(),
            None,
        ));
    }
    let release: serde_json::Value =
        serde_json::from_slice(&result.stdout).map_err(|_| "官方发布信息格式无效")?;
    let version = release["tag_name"].as_str().ok_or("官方版本信息缺失")?;
    let name = format!(
        "sing-box-{}-windows-amd64.zip",
        version.trim_start_matches('v')
    );
    let asset = release["assets"]
        .as_array()
        .and_then(|assets| assets.iter().find(|a| a["name"] == name))
        .ok_or("官方发布缺少 Windows x64 压缩包")?;
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or("下载地址缺失")?;
    if !url.starts_with("https://github.com/SagerNet/sing-box/releases/download/") {
        return Err("下载来源不是官方仓库".into());
    }
    let digest = asset["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .ok_or("官方发布缺少 SHA-256，已拒绝下载")?;
    let root = data_dir()?.join("cores");
    fs::create_dir_all(&root).map_err(|_| "无法创建核心目录")?;
    let directory = root.join(uuid::Uuid::new_v4().to_string());
    fs::create_dir(&directory).map_err(|_| "无法创建下载目录")?;
    let archive = directory.join("download.zip");
    let installed = (|| {
        let mut cmd = process::command("curl.exe");
        cmd.args([
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "60",
            "--connect-timeout",
            "10",
            "--retry",
            "2",
            "--retry-delay",
            "1",
            "--retry-max-time",
            "180",
            "--retry-all-errors",
            "--write-out",
            "%{http_code}",
            "--max-filesize",
            "104857600",
            "--output",
        ])
        .arg(&archive)
        .arg(url);
        let result = process::output(cmd, Duration::from_secs(190))
            .map_err(|error| format!("下载官方核心：{error}"))?;
        if !result.status.success() {
            let http = std::str::from_utf8(&result.stdout)
                .ok()
                .and_then(|text| text.trim().parse::<u16>().ok());
            return Err(transfer_error("下载官方核心", result.status.code(), http));
        }
        verify_hash(&archive, digest)?;
        let file = fs::File::open(&archive).map_err(|_| "无法读取下载文件")?;
        let mut zip = zip::ZipArchive::new(file).map_err(|_| "下载包不是有效 ZIP")?;
        let mut executable = None;
        for index in 0..zip.len() {
            let mut entry = zip.by_index(index).map_err(|_| "ZIP 文件损坏")?;
            if entry
                .enclosed_name()
                .and_then(|p| p.file_name().map(|n| n == "sing-box.exe"))
                .unwrap_or(false)
            {
                if executable.is_some() || entry.size() > 209715200 {
                    return Err("压缩包中的核心文件异常".into());
                }
                let path = directory.join("sing-box.exe");
                let mut output = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|_| "无法写入核心文件")?;
                std::io::copy(&mut entry, &mut output).map_err(|_| "无法解压核心")?;
                output.flush().map_err(|_| "无法刷新核心文件")?;
                executable = Some(path);
            }
        }
        let path = executable.ok_or("压缩包中没有 sing-box.exe")?;
        write_json(
            &directory.join("provenance.json"),
            &serde_json::json!({"version": version, "source": url, "archive_sha256": digest, "executable_sha256": sha256(&path)?}),
        )?;
        Ok(path)
    })();
    let _ = fs::remove_file(archive);
    installed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_errors_distinguish_timeout_http_and_disk_failure() {
        assert!(transfer_error("下载", Some(28), None).contains("超时"));
        assert!(transfer_error("查询", Some(22), Some(429)).contains("429"));
        assert!(transfer_error("下载", Some(23), None).contains("磁盘"));
        assert!(transfer_error("下载", Some(60), None).contains("未跳过"));
    }
    #[test]
    fn detects_corruption() {
        let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::write(&path, b"abc").unwrap();
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_hash(&path, expected).is_ok());
        fs::write(&path, b"abcd").unwrap();
        assert!(verify_hash(&path, expected).is_err());
        fs::remove_file(path).unwrap();
    }
}
