<#
  .SYNOPSIS
	A PowerShell module that searches Windows RDP Logon events for a specified user, on a specified serve, for a specified timeframe.

           Name: Get-UserRDPLogon
         Author: Spencer Alessi (@techspence)
        License: MIT License
    Assumptions: Run as Administrator. 
   Requirements: 'Audit Logon Success and Failure' must be enabled in Group Policy for Security-Auditing 4624 Events.
                 *LocalSessionManager Events require no pre-requisites.

    To import module, use:  PS C:\>. .\Get-UserRDPLogon.ps1

  
  .DESCRIPTION
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
    
  .PARAMETER User
   This is the user you want to search logon events for.

  
  .PARAMETER Server
   This is the system (workstation or server) that you want to search.

  
  .PARAMETER Days
   This is the number of days prior to today you want to search.

  
  .PARAMETER Max
   This is the maximum number of events you want to search through.

  
  .EXAMPLE
	Get-UserRDPLogon -User jcarter -Server sarah -Days 5

  .LINK
    https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/
#>

function Get-UserRDPLogon {

    param (
         [Parameter(Mandatory = $true)]
         [string]$User,

         [Parameter(Mandatory = $true)]
         [string]$Server,

         [Parameter(Mandatory = $true)]
         [int32]$Days,

         [Parameter(Mandatory = $false)]
         [int32]$Max = 100
    )

    $Output = @()
    $SecOutput = @()
    $UnlockOutput = @()
    $Date = (Get-Date).AddDays(-$Days)

#########################################################################
#### PROVIDER: Microsoft-Windows-TerminalServices-LocalSessionManager ###
#### EVENT ID: 21                                                     ###
####     TYPE: Logon                                                  ###
#########################################################################
    try {
        $LocalSessionEvents = Get-WinEvent -FilterHashtable @{logname='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; id=21; starttime=$Date;} -ComputerName $Server -MaxEvents $Max -ErrorAction Stop
    }

    catch {
        Write-Warning "Error obtaining LocalSessionManager events. There may be no results that match your criteria. Bummer.. :O("
    }

    Foreach ($Event in $LocalSessionEvents){
        [array]$EventUser = $Event.Message | select-String "$User"
        $Username = $EventUser.Matches.Value

        [array]$MessageArray = $Event.message.split("`n")
        $Message = $MessageArray[0]
        $SessionID = $MessageArray[3].Split(':')[1].trim()
        $IP = $MessageArray[4].Split(':')[1].trim()
        $EventID = $Event.Id
        $EventDate = $Event.TimeCreated  
            
        if ($Username -eq $User) {              
            $Eventobj = New-Object -TypeName PSObject -Property @{                   
                 "User"      = $Username
                 "Server"    = $Server
                 "Date"      = $EventDate  
                 "SourceIP"  = $IP
                 "Message"   = $Message
                 "SessionID" = $SessionID
                 "EventID"   = $EventID                    
            }  
            $Output += $Eventobj
        } else {
        }
    }

#########################################################################
### PROVIDER: Microsoft-Windows-Security-Auditing                     ###
### EVENT ID: 4624                                                    ###
###     TYPE: 7 (Reconnection) & 10 (Remote Interactive)              ###
#########################################################################
    try {
        $SecurityEvents = Get-WinEvent -FilterHashtable @{logname='Security'; id=4624; starttime=$Date;} -ComputerName $Server -MaxEvents $Max -ErrorAction Stop
    }

    catch {
        Write-Warning "Error obtaining Security events. There may be no results that match your criteria. Bummer.. :O("
    }

    Foreach ($SecurityEvent in $SecurityEvents){
        $LogonTypeString = "Logon Type:"
        $idx = $SecurityEvent.Message.IndexOf($LogonTypeString)
        $LogonType = $SecurityEvent.Message.Substring( $idx + 	$LogonTypeString.length, 7).trim()
        [array]$MessageArray = $SecurityEvent.message.split("`n")
        $Secusername = $MessageArray[14].Split(":")[1].trim()

	    if($Secusername -eq $User) {
            $IP = $MessageArray[25].Split(':')[1].trim()
            $EventID = $SecurityEvent.ID
            $Message = $MessageArray[0]
            $EventDate = $SecurityEvent.TimeCreated
        
            if ($LogonType -eq 7 -or $LogonType -eq 10) {            
                $SecEventobj = New-Object -TypeName PSObject -Property @{                   
                    "User"      = $User
                    "Server"    = $Server
                    "Date"      = $EventDate  
                    "SourceIP"  = $IP
                    "Message"   = $Message
                    "EventID"   = $EventID
                    "LogonType" = $LogonType                                     
                }
                $SecOutput += $SecEventobj
            } else {
            }
        } else {}
    }


#########################################################################
### PROVIDER: Microsoft-Windows-Security-Auditing                     ###
### EVENT ID: 4801                                                    ###
###     TYPE: Unlock                                                  ###
#########################################################################
    try {
        $UnlockEvents = Get-WinEvent -FilterHashtable @{logname='Security'; id=4801; starttime=$Date;} -ComputerName $Server -MaxEvents $Max -ErrorAction Stop
    }

    catch {
        Write-Warning "Error obtaining Unlock events. There may be no results that match your criteria. Bummer.. :O("
    }

    Foreach ($UnlockEvent in $UnlockEvents){
        [array]$MessageArray = $UnlockEvents.message.split("`n")
        $Username = $MessageArray[4].Split(':')[1].trim()

        $Message = $MessageArray[0]
        $SessionID = $MessageArray[7].Split(':')[1].trim()
        $EventID = $UnlockEvent.Id
        $EventDate = $UnlockEvent.TimeCreated
        
        if($Username -eq $User) {            
            $UnlockEventobj = New-Object -TypeName PSObject -Property @{                   
                "User"      = $User
                "Server"    = $Server
                "Date"      = $EventDate  
                "SourceIP"  = $IP
                "Message"   = $Message
                "EventID"   = $EventID                                   
            }
            $UnlockOutput += $UnlockEventobj
        } else {
        }
    }

#################
### FUNCTIONS ###
#################

function Display-LocalSession {
"`n#########################################################################"
  "#### PROVIDER: Microsoft-Windows-TerminalServices-LocalSessionManager ###"
  "#### EVENT ID: 21                                                     ###"
  "####     TYPE: Logon                                                  ###"
  "#########################################################################"

    ($Output | FT -Wrap `
            @{Name = "User";      Expression = {$_.User};      Alignment = "Left"},
            @{Name = "Server";    Expression = {$_.Server};    Alignment = "Left"},
            @{Name = "SourceIP";  Expression = {$_.SourceIP};  Alignment = "Left"},
            @{Name = "SessionID"; Expression = {$_.SessionID}; Alignment = "center"},
            @{Name = "EventID";   Expression = {$_.EventID};   Alignment = "center"},
            @{Name = "Date";      Expression = {$_.Date};      Alignment = "Left"},
            @{Name = "Message";   Expression = {$_.Message};   Alignment = "Left"} `
    | Out-String).Trim()
}

function Display-SecurityAuditing {
"`n#########################################################################"
  "### PROVIDER: Microsoft-Windows-Security-Auditing                     ###"
  "###  EventID: 4624                                                    ###"
  "###     TYPE: 7 (Reconnection) & 10 (Remote Interactive)              ###"
  "#########################################################################"

    ($SecOutput | FT -Wrap `
            @{Name = "User";      Expression = {$_.User};      Alignment = "Left"},
            @{Name = "Server";    Expression = {$_.Server};    Alignment = "Left"},
            @{Name = "SourceIP";  Expression = {$_.SourceIP};  Alignment = "Left"},
            @{Name = "EventID";   Expression = {$_.EventID};   Alignment = "center"},
            @{Name = "LogonType"; Expression = {$_.LogonType}; Alignment = "center"},
            @{Name = "Date";      Expression = {$_.Date};      Alignment = "Left"},
            @{Name = "Message";   Expression = {$_.Message};   Alignment = "Left"} `
    | Out-String).Trim()
}

function Display-WindowsUnlock {
"`n#########################################################################"
  "### PROVIDER: Microsoft-Windows-Security-Auditing                     ###"
  "###  EventID: 4801                                                    ###"
  "###     TYPE: Unlock                                                  ###"
  "#########################################################################"

    ($UnlockOutput | FT -Wrap `
            @{Name = "User";      Expression = {$_.User};      Alignment = "Left"},
            @{Name = "Server";    Expression = {$_.Server};    Alignment = "Left"},
            @{Name = "EventID";   Expression = {$_.EventID};   Alignment = "center"},
            @{Name = "Date";      Expression = {$_.Date};      Alignment = "Left"},
            @{Name = "Message";   Expression = {$_.Message};   Alignment = "Left"} `
    | Out-String).Trim()
}

#################
###  DISPLAY  ###
#################

Display-LocalSession
Display-SecurityAuditing
Display-WindowsUnlock

}