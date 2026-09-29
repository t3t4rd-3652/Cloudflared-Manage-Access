# Signe les fichiers donnés avec le certificat fourni par les secrets de la CI (SIGNING_CERT_BASE64 / _PASSWORD).
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Patterns)
$ErrorActionPreference = 'Stop'
$cert = Join-Path $env:RUNNER_TEMP 'cert.pfx'
[IO.File]::WriteAllBytes($cert, [Convert]::FromBase64String($env:SIGNING_CERT_BASE64))
try {
    $signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' | Sort-Object FullName | Select-Object -Last 1
    foreach ($pattern in $Patterns) {
        foreach ($file in Get-ChildItem $pattern) {
            & $signtool.FullName sign /f $cert /p $env:SIGNING_CERT_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $file.FullName
            if ($LASTEXITCODE -ne 0) { throw "Échec de la signature : $($file.Name)" }
        }
    }
}
finally {
    Remove-Item $cert -ErrorAction SilentlyContinue
}
