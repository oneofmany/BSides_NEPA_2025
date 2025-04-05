## Detection template
This is the template to be used when you write a detection and place it in your repository and for detections in this repository. Detections are written as MD file with the details decribed in the template.

**Title of Detection:** 
(Example)T1110.003 - Brute Force: Password Spraying

ID:
(Example) T1110.003 (MITRE ATT&CK)

Last Modified:
Last time an update was made to the detection

Author:
Team or Engineer responsible of writign detection.

License:
for example BSD 3-Clause License

References:
Link to relevan documentation

ATT&CK Tags
Tactic:
Example: Initial Eccess

Technique:
Example: Brute Force: Password Spraying

Technical description of the attack
Example: The query searches for failed logins from a single source towards multiple different accounts and provides three parameters to tune the results for your specific environment. The full details of the working are described in the blog post linked above.

Permission required to execute the technique
Example: User

Detection description
For exmaple: A password spraying attack is detected, where a single machine has performed a large number of failed login attempts, with a large number of different accounts. For each account, the attacker uses just a few attempts to prevent account lockout. This query uses the Microsoft Defender for Identity (MDI) data as a datasource for the analysis. MDI has it's own password spraying detection, but that's not configurable. This implementation provides three variables to tune to your environment.

Utilized Data Source
Examples: Event ID Event Name Log Provider ATT&CK Data Source

IdentityLogonEvents MDI
Hunt details
Example: FQL, SQL, KQL

False Positive Rate:
Medium Source: MDE

Query:
Here is where you will place the body of the query in the defined language, for example:

let thresholdForUniqueFailedAccounts = 20; let upperBoundOfFailedLogonsPerAccount = 10; let ratioSuccessFailedLogons = 0.5; let timeframe = 1d; IdentityLogonEvents | where Timestamp >= ago(timeframe) | summarize SuccessLogonCount = countif(ActionType == "LogonSuccess"), FailedLogonCount = countif(ActionType == "LogonFailed"), UniqueAccountFailedLogons=dcountif(AccountUpn, ActionType == "LogonFailed"), FailedAccounts=make_set_if(AccountUpn, ActionType == "LogonFailed"), SuccessAccounts=make_set_if(AccountUpn, ActionType == "LogonSuccess"), FirstFailed=minif(Timestamp, ActionType == "LogonFailed"), LastFailed=maxif(Timestamp, ActionType == "LogonFailed"), LastTimestamp=arg_max(Timestamp, tostring(ReportId)) by IPAddress, DeviceName //IP address is here the "remote IP" , ie the source of the logon attempt | where UniqueAccountFailedLogons > thresholdForUniqueFailedAccounts and SuccessLogonCountratioSuccessFailedLogons < FailedLogonCount and UniqueAccountFailedLogonsupperBoundOfFailedLogonsPerAccount > FailedLogonCount

Considerations
Thing that are good to know, examlpe: This query needs tuning for your environment. A short guide is provided in the blog post linked above. MDI has a built-in detection for password spraying, which works differently and cannot be tuned for more or less sensitivity. False Positives

**Detection Blind Spots:**
Call them out if any

**Technical References:** 
Add links to references used to wirte detection
