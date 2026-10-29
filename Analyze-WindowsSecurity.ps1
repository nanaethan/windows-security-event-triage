$ErrorActionPreference = 'Continue'

$ProjectRoot = Join-Path $env:USERPROFILE 'Documents\windows-security-event-triage'
$OutputDirectory = Join-Path $ProjectRoot 'output'
$CsvPath = Join-Path $OutputDirectory 'security-findings.csv'
$HtmlPath = Join-Path $OutputDirectory 'security-report.html'

New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

$StartTime = (Get-Date).AddDays(-30)
$EventIds = 4624, 4625, 4672

$Events = @()
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName ='Security'
        Id = $EventIds
        StartTime = $StartTime
    } -MaxEvents 300 -ErrorActionn Stop
} catch { 
    $Events = @()
}
$Findings = $Events | ForEach-Object {
    $Record = $_
    [xml]$EventXml = $Record.ToXml()
    $EventData = @{}

    foreach ($Node in $EventXml.Event.EventData.Data) {
        $EventData[[string]$Node.Name] = [string]$Node.'#text'
    }
        $AccountName = if ($EventData.ContainsKey('TargetUserName')) {
        $EventData['TargetUserName']
    }
    elseif ($EventData.ContainsKey('SubjectUserName')) {
        $EventData['SubjectUserName']
    }
    else {
        ''
    }

    $AccountCategory = if (
        $AccountName -eq 'SYSTEM' -or
        $AccountName -eq 'LOCAL SERVICE' -or
        $AccountName -eq 'NETWORK SERVICE' -or
        $AccountName.EndsWith('$')
    ) {
        'System or computer account'
    }
    elseif ([string]::IsNullOrWhiteSpace($AccountName)) {
        'Not recorded'
    }
    else {
        'User account (name redacted)'
    }
        $EventMeaning = switch ($Record.Id) {
        4624 { 'Successful logon' }
        4625 { 'Failed logon' }
        4672 { 'Sensitive privileges assigned' }
        default { 'Other selected event' }
    }

    $AnalystGuidance = switch ($Record.Id) {
        4624 { 'Review logon type and account category for expected activity.' }
        4625 { 'Review frequency and failure context before escalating.' }
        4672 { 'Correlate the logon ID with a related successful logon.' }
        default { 'Review context.' }
    }
        $SourceCategory = if (
        $EventData.ContainsKey('IpAddress') -and
        $EventData['IpAddress'] -and
        $EventData['IpAddress'] -ne '-' -and
        $EventData['IpAddress'] -ne '127.0.0.1' -and
        $EventData['IpAddress'] -ne '::1'
    ) {
        'Remote address present (redacted)'
    }
    elseif (
        $EventData.ContainsKey('IpAddress') -and
        ($EventData['IpAddress'] -eq '127.0.0.1' -or $EventData['IpAddress'] -eq '::1')
    ) {
        'Localhost'
    }
    else {
        'Not recorded'
    }
        [pscustomobject]@{
        TimeCreated      = $Record.TimeCreated
        EventId          = $Record.Id
        EventMeaning     = $EventMeaning
        AccountCategory  = $AccountCategory
        LogonType        = $EventData['LogonType']
        SourceCategory   = $SourceCategory
        Status           = $EventData['Status']
        AnalystGuidance  = $AnalystGuidance
    }
}

$Findings = $Findings | Sort-Object -Property TimeCreated -Descending
$Findings |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

$Head = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #172033; }
h1 { color: #173f73; }
p { max-width: 900px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th { background: #173f73; color: white; text-align: left; }
th, td { border: 1px solid #ccd5e0; padding: 8px; vertical-align: top; }
tr:nth-child(even) { background: #f3f6f9; }
</style>
'@ 
$PreContent = @"
<h1>Windows Security Event Triage</h1>
<p>Window start: $StartTime</p>
<p>Events reviewed: 4624, 4625, and 4672. Account names, computer names, raw messages, and raw remote addresses are not exported.</p>
"@

$Findings |
    ConvertTo-Html -Head $Head -Title 'Windows Security Event Triage' -PreContent $PreContent |
    Out-File -FilePath $HtmlPath -Encoding UTF8

Write-Host "Created: $CsvPath"
Write-Host "Created: $HtmlPath"
Write-Host "Total findings: $($Findings.Count)"
Write-Host "Failed logons: $(($Findings | Where-Object EventId -eq 4625).Count)"