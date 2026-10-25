param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not $SkipBuild) {
        cargo build --release --locked
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    }
    $metadataText = cargo metadata --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Dependency inventory failed' }
    $metadata = $metadataText | ConvertFrom-Json
    $version = ($metadata.packages | Where-Object name -EQ 'proxypilot').version
    $output = Join-Path $root "dist/ProxyPilot-$version"
    New-Item -ItemType Directory -Force -Path $output | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'target/release/proxypilot.exe') -Destination (Join-Path $output 'proxypilot.exe')
    Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination $output
    Copy-Item -LiteralPath (Join-Path $root 'CHANGELOG.md') -Destination $output
    Copy-Item -LiteralPath (Join-Path $root 'docs') -Destination $output -Recurse -Force
    $licenses = Join-Path $output 'licenses'
    New-Item -ItemType Directory -Force -Path $licenses | Out-Null
    $inventory = [Collections.Generic.List[string]]::new()
    $inventory.Add('# Third-party dependency inventory')
    $inventory.Add('Generated from Cargo.lock for Windows x64. Core is downloaded separately. This inventory does not grant a license for ProxyPilot or certify distribution compliance. Slint offers GPL/commercial/royalty-free alternatives; select applicable terms before public distribution.')
    $inventory.Add('')
    foreach ($package in ($metadata.packages | Sort-Object name,version)) {
        if ($package.name -eq 'proxypilot') { continue }
        $inventory.Add("- $($package.name) $($package.version): $($package.license) $($package.repository)")
        $source = Split-Path -Parent $package.manifest_path
        $files = @(Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)' })
        if ($files.Count -gt 0) {
            $destination = Join-Path $licenses "$($package.name)-$($package.version)"
            New-Item -ItemType Directory -Force -Path $destination | Out-Null
            foreach ($file in $files) { Copy-Item -LiteralPath $file.FullName -Destination $destination }
        }
    }
    $inventory | Set-Content -LiteralPath (Join-Path $output 'THIRD-PARTY-NOTICES.md') -Encoding utf8
    $sourceOutput = Join-Path $output 'source'
    New-Item -ItemType Directory -Force -Path $sourceOutput | Out-Null
    foreach ($name in @('src','ui','scripts','Cargo.toml','Cargo.lock','build.rs','rust-toolchain.toml','examples')) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $sourceOutput -Recurse -Force
    }
    $archive = Join-Path $root "dist/ProxyPilot-$version-windows-x64.zip"
    Compress-Archive -Path "$output/*" -DestinationPath $archive -Force
    Get-FileHash -LiteralPath $archive -Algorithm SHA256 | Format-List
    Write-Output "Portable package: $archive"
} finally { Pop-Location }
