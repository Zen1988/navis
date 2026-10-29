param(
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [string]$BaseUrl = 'http://localhost:8000'
)
$ErrorActionPreference = 'Stop'
$sessionId = 'integration-' + [guid]::NewGuid().ToString()
$headers = @{ Authorization = "Bearer $Token" }
$body = @{
    graph_build_id = $BuildId
    caller_session_id = $sessionId
    source = '192.0.2.1'
    destination = '198.51.100.10'
    protocol = 'tcp'
    destination_port = 22
} | ConvertTo-Json
$trace = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/traces" -Headers $headers -ContentType 'application/json' -Body $body
if ($trace.code -ne 'TRACE_RESULT_READY' -or $trace.caller_session_id -ne $sessionId) { throw 'Trace session response did not match the request' }
if ($trace.results[0].status -ne 'blocked') { throw 'Expected a blocked overall result' }
if ($trace.results[0].hops.Count -ne 2) { throw 'Expected the trace to stop at the denying firewall' }
$firewall = $trace.results[0].hops[1]
if ($firewall.policy_evaluations[0].decision -ne 'deny') { throw 'Expected firewall default deny' }
$recommendation = Invoke-RestMethod -Uri "$BaseUrl/v1/trace-sessions/$sessionId/recommendations" -Headers $headers
if ($recommendation.code -ne 'RECOMMENDATIONS_AVAILABLE') { throw 'Recommendation not available' }
$draft = $recommendation.recommendations[0].result
if ($draft.source_zone -ne 'APP' -or $draft.destination_zone -ne 'DB' -or $draft.destination_port -ne 22) { throw 'Recommendation does not match expected flow and zones' }
if ($recommendation.trace_session_id -ne $trace.trace_session_id) { throw 'Trace session ID changed' }
try {
    Invoke-RestMethod -Uri "$BaseUrl/v1/trace-sessions/$sessionId/recommendations" | Out-Null
    throw 'Unauthenticated request unexpectedly succeeded'
} catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw }
}
Write-Host "HTTP trace and recommendation retrieval passed for session $sessionId"
Write-Output $recommendation
