# You need VirusTotal account for APIKEY.
# CHANGE APIKEY : "XXXX".
# CHANGE FOLDER : where you want to search. 
# .XLSX file will be generated. Keep file with this one.


Write-Host "Type q to save progress. Please be patient for large dir's :)"
# Prompt for number of files to scan
while ($true) {
	$maxFilesToScan = Read-Host "Enter the number of files to scan"
	if ($maxFilesToScan -as [int]) {
        break  # Exit the loop if a valid number is provided
    } else {
        Write-Host "Invalid input. Please enter a valid number."
    }
}

# excel functionality for saving your history of previous scans
$module = Get-Module -ListAvailable -Name ImportExcel

# plus stopwatch
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if ($module -eq $null) {
    Install-Module -Name ImportExcel -Scope CurrentUser -Force -AllowClobber
}

Import-Module ImportExcel

# FOLDER to search. Change as wanted. 
$folders = @("C:\windows\system32")

# Get all PE's in the specified folders
$exeFiles = Get-ChildItem -Path $folders -File -Recurse -Include *.exe -ErrorAction SilentlyContinue

# VirusTotal API script

$VTApiKey = "XXXX"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function submit-VTHash($VThash)
{
    $VTbody = @{resource = $VThash; apikey = $VTApiKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

    return $VTresult
}

# Set sleep time to 4 requests per minute for Public TotalVirus API
$sleepTime = 15 

# array to store the output data
$outputData = @()

# Load the previous results via VirusTotalResults.xlsx file 
$previousResults = @()
$excelFilePath = "VirusTotalResults.xlsx"

if (Test-Path $excelFilePath) {
    $previousResults = Import-Excel -Path $excelFilePath -WorksheetName "VirusTotal Results"
}

# file counter
$filesScanned = 0

# Loop through the files
foreach ($file in $exeFiles) {
    # MD5 hash the file
    $hash = (Get-FileHash -Algorithm MD5 $file.FullName).Hash

    # Check if the file has been scanned previously
    $previouslyScanned = $previousResults | Where-Object { $_.Path -eq $file.FullName }

    if ($previouslyScanned) {
        Write-Host "Skipping file $($file.FullName) as it has been scanned previously."
        continue  # Skip to the next file
    }

    # Submit the hash to VirusTotal
    $VTresult = submit-VTHash $hash

    # Color positive results (you can customize this)
    if ($VTresult.positives -ge 1) {
        $fore = "Magenta"
        $VTpct = ($VTresult.positives / $VTresult.total) * 100
        $VTpct = [math]::Round($VTpct, 2)
    } else {
        $fore = (Get-Host).UI.RawUI.ForegroundColor
        $VTpct = 0
    }

    # Object storage for output in loop
    $output = New-Object PSObject -Property @{
        "Name" = $file.Name
        "Path" = $file.FullName
        "Resource" = $VTresult.resource
        "Scan date" = $VTresult.scan_date
        "Positives" = $VTresult.positives
        "Total Scans" = $VTresult.total
        "Permalink" = $VTresult.permalink
        "Percent" = "$VTpct %"
    }

    # Display results
    Write-Host "New and recent files to check: $($file.FullName)"
    Write-Host "==================="
    Write-Host -f Cyan "Name       : " -NoNewline; Write-Host $output.Name
    Write-Host -f Cyan "Path       : " -NoNewline; Write-Host $output.Path
    Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $output.Resource
    Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $output."Scan date"
    Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $output.Positives -f $fore
    Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $output."Total Scans"
    Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $output.Permalink
    Write-Host -f Cyan "Percent     : " -NoNewline; Write-Host $output.Percent

    # Add output to $outputData array
    $outputData += $output

    # Add counter
    $filesScanned++

    # Check count
    if ($filesScanned -ge $maxFilesToScan) {
        Write-Host "Scanned $maxFilesToScan files. Exiting."
        break  # Exit the loop
    }
# Check if the user wants to exit early
	if ([System.Console]::KeyAvailable) {
		$key = [System.Console]::ReadKey($true)
		if ($key.Key -eq 'Q') {
			Write-Host "User requested exit. Saving results..."
			break  # Exit the loop
		}
	}
    # Pause for the specified sleep time
    Start-Sleep -Seconds $sleepTime
}

# Stop the timer and calculate the elapsed time
$stopwatch.Stop()
$elapsedTime = $stopwatch.Elapsed.ToString()

# Export the data to Excel file
if (Test-Path $excelFilePath) {
    # Append the data to the existing Excel file
    $outputData | Export-Excel -Path $excelFilePath -WorksheetName "VirusTotal Results" -Append
    Write-Host "Data appended to $excelFilePath"
} else {
    # If the file doesn't exist ; create Excel file
    $outputData | Export-Excel -Path $excelFilePath -WorksheetName "VirusTotal Results"
    Write-Host "Data exported to $excelFilePath"
}

Write-Host "Elapsed Time: $elapsedTime"
