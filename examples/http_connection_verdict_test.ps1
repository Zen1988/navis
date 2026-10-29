param(
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [string]$BaseUrl = 'http://localhost:8001'
)
$ErrorActionPreference = 'Stop'
$headers = @{ Authorization = "Bearer $Token" }
foreach ($port in @(443, 22)) {
    $body = @{
        graph_build_id = $BuildId
        caller_session_id = 'verdict-' + [guid]::NewGuid().ToString()
        source = '192.0.2.1'
        destination = '198.51.100.10'
        protocol = 'tcp'
        destination_port = $port
        source_port = 50000
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/traces" -Headers $headers -ContentType 'application/json' -Body $body
    $result = $response.results[0]
    if ($port -eq 443 -and $result.connection_verdict.status -ne 'unknown') { throw 'Expected unknown end-to-end verdict for TCP/443' }
    if ($port -eq 22 -and $result.connection_verdict.status -notin @('unknown', 'blocked')) { throw 'Unexpected end-to-end verdict for TCP/22' }
    if ($result.connection_verdict.status -eq 'blocked' -and ($result.alternative_paths.complete -ne $true -or $result.alternative_paths.verdict.status -ne 'blocked')) { throw 'Blocked verdict lacks complete alternative-path evidence' }
    if ($result.coverage.complete -ne $false) { throw "Expected incomplete coverage for TCP/$port" }
    if ($result.coverage.missing.Count -eq 0) { throw "Expected explicit coverage gaps for TCP/$port" }
    if ($port -eq 22 -and $result.status -ne 'blocked') { throw 'Expected candidate path blocked for TCP/22' }
    Write-Host "TCP/$port combined verdict: $($result.connection_verdict.status)"
    @{ verdict = $result.connection_verdict; coverage = $result.coverage } | ConvertTo-Json -Depth 20
}
Write-Host 'HTTP connection verdict checks passed'
