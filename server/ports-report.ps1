# ports-report.ps1 : ports TCP en écoute sur un serveur Windows, au format NDJSON de ports-report 2.
#
# Cloudflared Manage Access l'envoie par l'entrée standard, sans rien installer sur le serveur :
#   powershell -NoProfile -NonInteractive -Command "& {[Console]::In.ReadToEnd() | Invoke-Expression}"
# Utilisation à la main :
#   powershell -NoProfile -File ports-report.ps1 [-NoWeb] [-All]
#
# Compatible Windows PowerShell 5.1 (Windows Server 2016 et suivants) et PowerShell 7.
# Sources : Get-NetTCPConnection, sinon `netstat -ano`. Services : Win32_Service. Docker : `docker ps`.

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$PortsReportVersion = '2.1.0'
if (-not (Test-Path variable:CmaNoWeb)) { $CmaNoWeb = $false }
if (-not (Test-Path variable:CmaAll)) { $CmaAll = $false }
if ($args -contains '-NoWeb') { $CmaNoWeb = $true }
if ($args -contains '-All') { $CmaAll = $true }

# 135/139/445 RPC et SMB, 5040 CDP, 5355 LLMNR, 5357 WSD, 20241 métriques de cloudflared.
$DefaultExcludes = @(135, 139, 445, 5040, 5355, 5357, 20241)
# Ports dynamiques RPC des processus système : bruit sans intérêt pour une redirection.
$RpcOwners = @('lsass', 'wininit', 'services', 'spoolsv', 'svchost')
# Services connus pour ne pas parler HTTP : inutile de les sonder.
$NotWeb = @(22, 25, 53, 110, 143, 389, 636, 1433, 1521, 3306, 3389, 5432, 5672, 6379, 11211, 27017)

# --- Ports en écoute -------------------------------------------------------------------------------

$listeners = @{}
function Add-Listener([int]$Port, [string]$Address, [int]$OwnerPid) {
    $Address = $Address.Trim('[', ']')
    if (-not $listeners.ContainsKey($Port)) {
        $listeners[$Port] = @{ Binds = New-Object System.Collections.ArrayList; Pid = $OwnerPid }
    }
    if (-not $listeners[$Port].Binds.Contains($Address)) { [void]$listeners[$Port].Binds.Add($Address) }
}

$source = 'Get-NetTCPConnection'
$connections = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
if ($connections.Count -gt 0) {
    foreach ($c in $connections) { Add-Listener ([int]$c.LocalPort) ([string]$c.LocalAddress) ([int]$c.OwningProcess) }
} else {
    $source = 'netstat'
    foreach ($line in @(netstat -ano -p TCP) + @(netstat -ano -p TCPv6)) {
        # Une socket en écoute a une adresse distante nulle ; l'état est traduit selon la langue du système.
        if ($line -match '^\s*TCP\s+(\S+):(\d+)\s+(0\.0\.0\.0:0|\[::\]:0)\s+\S+\s+(\d+)\s*$') {
            Add-Listener ([int]$Matches[2]) $Matches[1] ([int]$Matches[4])
        }
    }
}

# --- Processus, services Windows et conteneurs -----------------------------------------------------

$processNames = @{}
foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $processNames[[int]$p.Id] = $p.ProcessName }
$servicesByPid = @{}
foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 0 })) {
    $key = [int]$s.ProcessId
    if (-not $servicesByPid.ContainsKey($key)) { $servicesByPid[$key] = New-Object System.Collections.ArrayList }
    [void]$servicesByPid[$key].Add([string]$s.Name)
}

$docker = 'absent'
$containers = @{}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $lines = @(docker ps --format '{{.Names}}|{{.Ports}}' 2>$null)
    if ($LASTEXITCODE -eq 0) {
        $docker = 'ok'
        foreach ($line in $lines) {
            $name, $ports = ([string]$line).Split('|', 2)
            foreach ($m in [regex]::Matches([string]$ports, ':(\d+)->\d+/tcp')) {
                $containers[[int]$m.Groups[1].Value] = $name
            }
        }
    } else {
        $docker = 'denied'
    }
}

function Get-ServiceLabel([int]$OwnerPid) {
    if ($OwnerPid -eq 4) { return 'http.sys' }
    if ($servicesByPid.ContainsKey($OwnerPid)) { return ($servicesByPid[$OwnerPid] | Select-Object -First 1) }
    if ($processNames.ContainsKey($OwnerPid)) { return $processNames[$OwnerPid] }
    return $null
}

function Get-ProbeHost($Binds) {
    if ($Binds.Count -eq 0 -or $Binds.Contains('0.0.0.0')) { return '127.0.0.1' }
    if ($Binds.Contains('::')) { return '::1' }
    $ipv4 = @($Binds | Where-Object { $_ -notmatch ':' })
    if ($ipv4.Count -gt 0) { return $ipv4[0] }
    return $Binds[0]
}

# --- Sonde HTTP et HTTPS ---------------------------------------------------------------------------
# Toutes les sondes partent en parallèle (HTTPS d'abord, puis HTTP pour les ports restés muets) : la
# durée totale reste de quelques secondes même avec des dizaines de ports. Le code est compilé en C# :
# un bloc de script PowerShell n'a pas de runspace sur les threads réseau.

if (-not $CmaNoWeb -and -not ('CmaProbe' -as [type])) {
    Add-Type -IgnoreWarnings -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
public static class CmaProbe {
    static bool Accept(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }
    static string One(string url, int timeout) {
        try {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.Timeout = timeout;
            request.ReadWriteTimeout = timeout;
            request.AllowAutoRedirect = false;
            request.UserAgent = "ports-report";
            HttpWebResponse response;
            try { response = (HttpWebResponse)request.GetResponse(); }
            catch (WebException ex) { response = ex.Response as HttpWebResponse; }
            if (response == null) { return null; }
            using (response) {
                string final = url;
                string location = response.Headers["Location"];
                if (!String.IsNullOrEmpty(location)) { final = new Uri(new Uri(url), location).AbsoluteUri; }
                return ((int)response.StatusCode).ToString() + "|" + final;
            }
        } catch { return null; }
    }
    public static string[] Run(string[] urls, int timeout) {
        // Certificats auto-signés acceptés : on veut savoir si le port parle HTTPS, pas juger son certificat.
        ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(Accept);
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
        ServicePointManager.DefaultConnectionLimit = 256;
        ThreadPool.SetMinThreads(Math.Max(urls.Length, 8), 8);
        var results = new string[urls.Length];
        var tasks = new Task[urls.Length];
        for (int i = 0; i < urls.Length; i++) {
            int index = i;
            tasks[i] = Task.Run(() => { results[index] = One(urls[index], timeout); });
        }
        Task.WaitAll(tasks, timeout + 500);
        return results;
    }
}
'@
}

function Format-UrlHost([string]$TargetHost) {
    if ($TargetHost -match ':') { return "[$TargetHost]" }
    return $TargetHost
}

# --- Sortie ----------------------------------------------------------------------------------------

$meta = [ordered]@{ version = $PortsReportVersion; os = 'windows'; source = $source; docker = $docker; web_probe = (-not $CmaNoWeb) }
Write-Output (ConvertTo-Json -Compress -InputObject ([ordered]@{ v = 2; meta = $meta }))

$selected = New-Object System.Collections.ArrayList
foreach ($port in ($listeners.Keys | Sort-Object)) {
    $owner = [string]$processNames[[int]$listeners[$port].Pid]
    if (-not $CmaAll) {
        if ($DefaultExcludes -contains $port) { continue }
        if ($port -ge 49152 -and $RpcOwners -contains $owner) { continue }
    }
    [void]$selected.Add([int]$port)
}

$web = @{}
if (-not $CmaNoWeb) {
    $candidates = @($selected | Where-Object { $NotWeb -notcontains $_ })
    foreach ($scheme in @('https', 'http')) {
        $pending = @($candidates | Where-Object { -not $web.ContainsKey($_) })
        if ($pending.Count -eq 0) { break }
        $urls = [string[]]@($pending | ForEach-Object {
            "${scheme}://$(Format-UrlHost (Get-ProbeHost $listeners[$_].Binds)):$_/"
        })
        $answers = [CmaProbe]::Run($urls, 1500)
        for ($i = 0; $i -lt $pending.Count; $i++) {
            if ($answers[$i]) {
                $code, $final = $answers[$i].Split('|', 2)
                $web[[int]$pending[$i]] = @{ Scheme = $scheme; Code = [int]$code; Final = $final }
            }
        }
    }
}

foreach ($port in $selected) {
    $entry = $listeners[$port]
    $probe = $web[[int]$port]
    $container = $null
    if ($containers.ContainsKey([int]$port)) { $container = $containers[[int]$port] }
    $line = [ordered]@{
        v = 2
        proto = 'tcp'
        port = [int]$port
        bind = @($entry.Binds | Sort-Object)
        service = (Get-ServiceLabel ([int]$entry.Pid))
        container = $container
        scheme = $(if ($probe) { $probe.Scheme } else { $null })
        http_code = $(if ($probe) { $probe.Code } else { $null })
        final_url = $(if ($probe) { $probe.Final } else { $null })
    }
    Write-Output (ConvertTo-Json -Compress -Depth 3 -InputObject $line)
}
