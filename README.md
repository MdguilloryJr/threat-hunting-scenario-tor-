<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MdguilloryJr/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and
discovered user “mdguser” downloaded a tor installer, did something that resulted in many
tor-related files being copied to the desktop and the creation of the file called
“tor-shopping-list.txt” on the desktop at 2025-08-05T00:19:46.4196784Z. These events began at: 2025-08-04T23:17:42.7657163Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "thl-mdg2"
| where InitiatingProcessAccountName == "mdguser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-04T23:17:42.7657163Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName
```
<img width="2372" height="714" alt="image" src="https://github.com/user-attachments/assets/27f72779-7e98-4cf2-83ee-57979c6bf094" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the
string “tor-browser-windows-x86_64-portable-14.5.5.exe”. Based on the logs returned at
6:17:42pm on August 4, 2025, an employee on the “mdguser” device ran the file
tor-browser-windows-x86_64-portable-14.5.5.exe from their downloads folder using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "thl-mdg2"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents for any indication that user “thl-mdg2” actually opened the
“tor” browser. There was evidence that they did open it at 2025-08-04T22:37:58.7500051Z.
There were several other instances where firefox.exe(Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thl-mdg2"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents for any indication that the “tor” browser was used to
establish a connection using any of the known “tor” ports:
On August 4, 2025, at 2025-08-04T23:33:53.571299Z, a user named "mdguser" on the
device "thl-mdg2" successfully established a connection from the Firefox browser to the IP
address 127.0.0.1 on port 9150. The Firefox executable is located at
"c:\users\mdguser\desktop\tor browser\browser\firefox.exe". There were a few other
connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "thl-mdg2"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe", "tor-browser.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 
## This report details the sequence of events related to the download, installation, and usage of the Tor browser by the user mdguser on the device thl-mdg2.

## Installation and Initial Process Creation

2025-08-04 17:21:36: A process named tor-browser-windows-x86 64-portable-14.5.5.exe was created from the downloads folder. This is the initial execution of the installer.

2025-08-04 17:27:55 - 17:33:38: The Tor installer process was run multiple times.

2025-08-04 17:37:58 - 17:38:17: Multiple instances of the firefox.exe process were created from the Tor Browser folder on the desktop. This indicates the browser was being opened and initialized.

2025-08-04 17:38:07: The tor.exe process was created, which is the core component of the Tor network client.

2025-08-04 17:39:18 - 17:55:45: The Tor installer process was run repeatedly.

2025-08-04 18:20:38 - 18:30:32: The Tor installer file was renamed and then deleted from the downloads folder, suggesting the user was cleaning up installation files.

2025-08-04 18:31:34: The user ran the tor-browser-windows-x86 64-portable-14.5.5.exe installer with the /S flag, which indicates a silent installation. This is a critical finding from a threat-hunting perspective.

2025-08-04 18:31:58: Numerous Tor-related files were created, including tor.txt, Torbutton.txt, and Tor-Launcher.txt.

2025-08-04 18:31:58: The tor.exe executable was created on the desktop.

## Browser Usage and Network Connections

2025-08-04 18:33:23: The user created a shortcut named Tor Browser.lnk on the desktop.

2025-08-04 18:33:23 - 18:33:30: Multiple instances of firefox.exe were created, indicating the Tor browser was opened and actively being used.

2025-08-04 18:33:28: The tor.exe process was created, initiating the connection to the Tor network.

2025-08-04 18:33:47: A network connection was successfully established from tor.exe to a remote IP address, 160.119.253.114, on port 443 with the URL https://www.w3q73dtmefysjw6hdpe.com.

2025-08-04 18:33:53: Another network connection from tor.exe was made to 66.206.0.82 on port 9001 with the URL https://www.qcx3.com. Port 9001 is a known Tor relay port.

2025-08-04 18:33:56: A network connection was established from firefox.exe to the local IP address 127.0.0.1 on port 9150. This is the Tor browser proxy port used for internal communication.

2025-08-04 18:34:16 - 18:34:17: A connection from tor.exe was made to 185.147.35.74 on port 443, with the URL https://www.rvtjhzr2ijv.com.

2025-08-04 18:34:22 - 18:39:47: Many more instances of firefox.exe were created, suggesting continued use of the browser.

2025-08-04 19:19:46: A text file named tor-shopping-list.txt was created on the desktop, along with a shortcut to it. This file's name suggests it might be related to activities performed using the Tor browser.

2025-08-04 19:22:04: A file named webappsstore.sqlite was created, which is a Tor browser-specific file used for storing web application data.

## Summary

The threat hunt revealed a clear sequence of events indicating the intentional and repeated use of the Tor
browser by the user mdguser. The user downloaded the Tor browser installer, and after several attempts,
successfully performed a silent installation as indicated by the /S flag. This action led to the creation of
various Tor-related files and the executables (tor.exe and firefox.exe) on the desktop. The logs further show
that the user launched the Tor browser, which resulted in network connections being established to known Tor
network ports (9001 and 9150) as well as to several remote websites over a standard encrypted port (443).
The creation of a file named tor-shopping-list.txt on the desktop coincides with the browser's usage, suggesting
a potential link between the user's activities and the new files.

## Response Taken

TOR usage was confirmed on the endpoint THL-MDG2 the user mdguser. The device was isolated and the user's direct manager was notified.

---# threat-hunting-scenario-tor-
