# VirusCheck
Runs a VirusTotal scan on windows PE's. Set to run recursively + date added. 

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


