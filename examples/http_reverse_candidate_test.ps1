param([Parameter(Mandatory=$true)][string]$Token,[Parameter(Mandatory=$true)][string]$BuildId,[string]$BaseUrl='http://localhost:8001')
$ErrorActionPreference = 'Stop'
$headers = @{Authorization="Bearer $Token"}
$body = @{graph_build_id=$BuildId;caller_session_id='reverse-'+[guid]::NewGuid().ToString();source='192.0.2.1';destination='198.51.100.10';protocol='tcp';destination_port=443;source_port=50000} | ConvertTo-Json
$result = (Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/traces" -Headers $headers -ContentType 'application/json' -Body $body).results[0]
if ($result.reverse_trace.status -ne 'unknown') { throw 'Reverse connection must remain unknown' }
if ($result.reverse_trace.nat_session_mappings[0].session_state -ne 'observed') { throw 'The observed session fixture is missing or expired' }
if ($null -eq $result.reverse_trace.paths) { throw 'Expected a reverse candidate search' }
$search = $result.reverse_trace.paths
if ($search.complete -ne $true -or $search.reverse_assessment.status -ne 'candidate_reachable') { throw 'Expected a complete reverse candidate path' }
$path = $search.paths[0]
$expected = @('10000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000011')
if ($path.hops.Count -ne 3) { throw 'Expected three reverse hops' }
for ($i=0; $i -lt $expected.Count; $i++) {
    if ($path.hops[$i].device_id -ne $expected[$i]) { throw "Unexpected device at reverse hop $($i + 1)" }
}
if ($path.hops[2].source -ne '198.51.100.10' -or $path.hops[2].destination -ne '192.0.2.1') { throw 'Reverse translation was not applied before the final hop' }
Write-Host 'Reverse candidate search completed; inspect evidence and unresolved policy below'
$result.reverse_trace | ConvertTo-Json -Depth 30
