[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go mod download all
if ($LASTEXITCODE -ne 0) { throw 'Dependency download failed' }
go build -trimpath -ldflags='-s -w' -o dist/masque-speed-windows-amd64.exe .
if ($LASTEXITCODE -ne 0) { throw 'Windows x64 build failed' }
go run ./cmd/release-notices -out dist
if ($LASTEXITCODE -ne 0) { throw 'License collection failed' }
Copy-Item README.md, THIRD_PARTY_NOTICES.md, examples/fofa-example.csv dist/
Compress-Archive -Force -Path dist/masque-speed-windows-amd64.exe, dist/README.md, dist/THIRD_PARTY_NOTICES.md, dist/fofa-example.csv, dist/licenses, dist/modules.txt -DestinationPath dist/masque-speed-windows-amd64.zip
Get-FileHash -Algorithm SHA256 dist/masque-speed-windows-amd64.exe, dist/masque-speed-windows-amd64.zip
