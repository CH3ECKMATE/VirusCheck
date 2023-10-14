# VirusCheck
Runs a VirusTotal scan on windows PE's. Set to run recursively + date added. 
Use to build your own Known Good file baseline in excel!

VirusTotal MD5 hash checker for exe files.
Runs recursive against most recent files in specified folder.
Credit to github.com/cbshearer/get-VTFileReport for the api functionality.

You need VirusTotal account for APIKEY.
CHANGE APIKEY : "XXXX".
CHANGE FOLDER : where you want to search. 
.XLSX file will be generated. Keep file with this one.
Appends + stores info on files checked against VirusTotal to VirusTotalResults.xlsx.
Checks against VirusTotalResults.xlsx to avoid duplicate scans.
Press "q" to save progress.

*Free VirusTotal limits 4 hash scans per minute / every 15 seconds
¯\_(ツ)_/¯

Scanned 100 files. Exiting.
Data appended to VirusTotalResults.xlsx
Elapsed Time: 00:25:17.1185026
