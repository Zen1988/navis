param(
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [string]$BaseUrl = 'http://localhost:8001'
)
$ErrorActionPreference = 'Stop'
$headers = @{ Authorization = "Bearer $Token" }
foreach ($port in @(50000, 50001, 50002)) {
    $body = @{
        graph_build_id = $BuildId
        caller_session_id = 'nat-session-' + [guid]::NewGuid().ToString()
        source = '192.0.2.1'
        destination = '198.51.100.10'
        protocol = 'tcp'
        destination_port = 443
        source_port = $port
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/traces" -Headers $headers -ContentType 'application/json' -Body $body
    $reverse = $response.results[0].reverse_trace
    if ($reverse.status -ne 'unknown') { throw 'Reverse routing is not verified' }
    $mapping = $reverse.nat_session_mappings[0]
    $expected = if ($port -eq 50000) { 'observed' } else { 'unknown' }
    if ($mapping.session_state -ne $expected) { throw "Expected $expected session state for source port $port" }
    if ($mapping.before_reverse_nat.source -ne '10.10.1.10' -or $mapping.after_reverse_nat.source -ne '198.51.100.10') { throw 'Reverse NAT addresses do not match the fixture' }
    if ($mapping.before_reverse_nat.destination_port -ne $port -or $mapping.after_reverse_nat.destination_port -ne $port) { throw 'Reverse NAT ports do not match the session' }
    Write-Host "TCP source port $port`: $($mapping.session_state)"
}
Write-Host 'HTTP NAT session evidence checks passed'
