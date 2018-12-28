# Get-UserRDPLogon
A PowerShell module that searches Windows RDP Logon events for a specified user, on a specified server, for a specified timeframe.

## Assumptions
Run as Administrator

## Requirements 
- *Audit Logon Success and Failure* must be enabled in Group Policy for Security-Auditing 4624 Events
- LocalSessionManager Events require no pre-requisites

## Example Events
    The categories below describe which Events withing which Providers are searched:
      
    =======================================================================
    Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    =======================================================================
     Provider Name: Microsoft-Windows-TerminalServices-LocalSessionManager
          Event ID: 21
        Event Type: Logon
          Log Size: 1028KB (~14 days of events for a terminal server)
       Description: Remote Desktop Services: Session logon succeeded:

                    User: GLOBALDYNAMICS\jcarter
                    Session ID: 46
                    Source Network Address: 192.168.0.123 
    -----------------------------------------------------------------------

    =======================================================================
    Microsoft-Windows-Security-Auditing
    =======================================================================
    *WARNING: Searching 4624 events can take a while, especially if 
    querying multiple days*
     
     Provider Name: Microsoft-Windows-Security-Auditing 
          Event ID: 4624
        Event Type: Type 7 (Reconnection) & 10 (Remote Interactive) 
          Log Size: 20480KB (~6 days of events for a terminal server)
       Description: An account was successfully logged on.

                       Subject:
                          Security ID:		SYSTEM
                         Account Name:		SARAH$
                       Account Domain:		GLOBALDYNAMICS
                             Logon ID:		0x6A9

                   Logon Type:			    10

          Impersonation Level:	            Impersonation

                    New Logon:
                          Security ID:		GLOBALDYNAMICS\jcarter
                         Account Name:		jcarter
                       Account Domain:		GLOBALDYNAMICS
                             Logon ID:		0x3G7C926C1
                           Logon GUID:		{123a45c7-8901-d2e3-4cdb-d2e3af58d2e3}

           Process Information: 
                           Process ID:		0x652c
                         Process Name:		C:\Windows\System32\winlogon.exe

           Network Information:
                     Workstation Name:	    SARAH
               Source Network Address:	    192.168.0.123
                          Source Port:		0

    -----------------------------------------------------------------------

    =======================================================================
    Microsoft-Windows-Security-Auditing
    ======================================================================= 
     Provider Name: Microsoft-Windows-Security-Auditing 
          Event ID: 4801
        Event Type: Windows Unlock 
          Log Size: 20480KB (~6 days of events for a terminal server)
       Description: The workstation was unlocked.

                    Subject:
                      Security ID:		GLOBALDYNAMICS\jcarter
                     Account Name:		jcarter
                   Account Domain:		GLOBALDYNAMICS
                         Logon ID:		0x3AC282179
                       Session ID:	    22
    -----------------------------------------------------------------------
    
# Parameters
**BOLD** = Mandatory 

**User** - This is the user you want to search logon events for.

**Server** - This is the system (workstation or server) that you want to search.

**Days** - This is the number of days prior to today you want to search.

Max - This is the maximum number of events you want to search through.
 
# Example Usage
To import module, use:  
```PowerShell
PS C:\>. .\Get-UserRDPLogon.ps1
PS C:\>Get-UserRDPLogon -User jcarter -Server sarah -Days 5
```

## Resources Used
Thank you to Jonathon Poling for his extremely detailed write-up on Windows RDP-Related Event Logs. 
His blog post provided very insightful information that made it much easier to pick out the specific 
events I was looking for.
https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
