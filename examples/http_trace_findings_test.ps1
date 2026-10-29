param(
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [string]$BaseUrl = 'http://localhost:8000'
)
$ErrorActionPreference = 'Stop'
$headers = @{ Authorization = "Bearer $Token" }
$body = @{
    graph_build_id = $BuildId
    caller_session_id = 'findings-' + [guid]::NewGuid().ToString()
    source = '192.0.2.1'
    destination = '203.0.113.250'
    protocol = 'tcp'
    destination_port = 443
} | ConvertTo-Json
$response = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/traces" -Headers $headers -ContentType 'application/json' -Body $body
$result = $response.results[0]
if ($result.status -ne 'unknown') { throw 'An unresolved destination must remain unknown' }
if (-not ($result.findings | Where-Object { $_.code -eq 'DESTINATION_UNRESOLVED' })) { throw 'Expected DESTINATION_UNRESOLVED finding' }
Write-Host 'HTTP missing-evidence finding check passed'
$result.findings | ConvertTo-Json -Depth 10
