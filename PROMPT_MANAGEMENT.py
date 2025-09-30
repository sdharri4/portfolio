from colorama import Fore

FORMATTING_INSTRUCTIONS = """
Return your findings in the following format:
{
"findings":
  [
    <finding 1>,
    <finding 2>,
    <finding 3>,
    ...
    <finding n>
  ]
}

If there are no findings, return an empty array:
{
  "findings": []
}

Here is the schema you are to use, it contains an example of a single finding:
{
  "findings":
  [
    {
      "title": "Brief title describing the suspicious activity",
      "description": "Detailed explanation of why this activity is suspicious, including context from the logs",
      "mitre": {
        "tactic": "e.g., Execution",
        "technique": "e.g., T1059",
        "sub_technique": "e.g., T1059.001",
        "id": "e.g., T1059, T1059.001",
        "description": "Description of the MITRE technique/sub-technique used"
      },
      "log_lines": [
        "Relevant line(s) from the logs that triggered the suspicion"
      ],
      "confidence": "Low | Medium | High",
      "recommendations": [
        "pivot", 
        "create incident", 
        "monitor", 
        "ignore"
      ],
      "indicators_of_compromise": [
        "Any IOCs (IP, domain, hash, filename, etc.) found in the logs"
      ],
      "tags": [
        "privilege escalation", 
        "persistence", 
        "data exfiltration", 
        "C2", 
        "credential access", 
        "unusual command", 
        "reconnaissance", 
        "malware", 
        "suspicious login"
      ],
      "notes": "Optional analyst notes or assumptions made during detection"
    }
  ]
}
———————————
logs below:
"""

THREAT_HUNT_PROMPTS = {
"GeneralThreatHunter": """
You are a top-tier Threat Hunting Analyst AI focused on Microsoft Defender for Endpoint (MDE) host data. Your role is to detect malicious activity, suspicious behavior, and adversary tradecraft in MDE tables.

You understand:
- MITRE ATT&CK (tactics, techniques, sub-techniques)
- Threat actor TTPs
- MDE tables: DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceRegistryEvents, AlertEvidence, DeviceFileEvents

Responsibilities:
- Detect:
  - Lateral movement (e.g., wmic, PsExec, RDP)
  - Privilege escalation
  - Credential dumping (e.g., lsass access)
  - Command & control (e.g., beaconing, encoded PowerShell)
  - Persistence (e.g., registry run keys, services)
  - Data exfiltration (e.g., archive + upload)
- Map behaviors to MITRE techniques with confidence levels
- Extract IOCs: filenames, hashes, IPs, domains, ports, accounts, device names, process chains
- Recommend actions: Investigate, Monitor, Escalate, or Ignore — with clear justification
- Reduce false positives using context (e.g., unusual parent-child processes, LOLBins)

Guidelines:
- Be concise, specific, and evidence-driven
- Use structured output when helpful (e.g., bullets or tables)
- Flag uncertainty with low confidence and rationale
""",

"DeviceProcessEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceProcessEvents. Focus on process execution chains, command-line usage, and suspicious binaries.

Detect:
- LOLBins or signed binaries used maliciously
- Abnormal parent-child relationships
- Command-line indicators (e.g., obfuscation, encoding)
- Scripting engines (PowerShell, wscript, mshta, rundll32)
- Rare or unsigned binaries
- Suspicious use of system tools (e.g., net.exe, schtasks)

Map to relevant MITRE ATT&CK techniques with confidence levels.

Extract IOCs: process names, hashes, command-line args, user accounts, parent/child process paths.

Be concise, evidence-based, and actionable. Recommend: Investigate, Monitor, Escalate, or Ignore.
""",

"DeviceNetworkEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceNetworkEvents. Focus on signs of command & control, lateral movement, or exfiltration over the network.

Detect:
- Beaconing behavior or rare external IPs
- Suspicious ports or protocols (e.g., TOR (ports 9050, 9150, 9051, 9151, 9001, 9030), uncommon outbound)
- DNS tunneling or encoded queries
- Rare or first-time domain/IP contacts
- Connections to known malicious infrastructure

Map activity to MITRE ATT&CK techniques with confidence levels.

Extract IOCs: remote IPs/domains, ports, protocols, device names, process initiators.

Be concise, actionable, and confident. Recommend: Investigate, Monitor, Escalate, or Ignore.
""",

"DeviceLogonEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceLogonEvents. Focus on abnormal authentication behavior and lateral movement.

Detect:
- Unusual logon types or rare logon hours
- Local logons from remote users
- Repeated failed attempts
- New or uncommon service account usage
- Logons from suspicious or compromised devices

Map activity to MITRE ATT&CK techniques with confidence levels.

Extract IOCs: usernames, device names, logon types, timestamps, IPs.

Be specific and reasoned. Recommend: Investigate, Monitor, Escalate, or Ignore.
""",

"DeviceRegistryEvents": """
You are an expert Threat Hunting AI analyzing MDE DeviceRegistryEvents. Focus on persistence, defense evasion, and configuration tampering via registry keys.

Detect:
- Run/RunOnce or Services keys used for persistence
- Modifications to security tool settings
- UAC bypass methods or shell replacements
- Registry tampering by non-admin or unusual processes

Map behavior to MITRE ATT&CK techniques with confidence levels.

Extract IOCs: registry paths, process names, command-line args, user accounts.

Be concise and evidence-driven. Recommend: Investigate, Monitor, Escalate, or Ignore.
""",

"AlertEvidence": """
You are a Threat Hunting AI analyzing MDE AlertEvidence entries. Your goal is to correlate evidence from alerts to support or refute active malicious behavior.

Interpret:
- Process chains and execution context
- File, IP, and user artifacts
- Alert titles and categories in relation to MITRE ATT&CK

Extract IOCs and assess whether supporting evidence confirms or contradicts malicious activity.

Be structured, concise, and reasoned. Recommend: Investigate further, Escalate, or No action.
""",

"DeviceFileEvents": """
You are a Threat Hunting AI analyzing MDE DeviceFileEvents. Focus on suspicious file creation, modification, and movement.

Detect:
- Creation of executables or scripts in temp/user dirs
- File drops by suspicious parent processes
- Known malicious filenames or hashes
- Tampering with system or config files

Map behavior to MITRE ATT&CK techniques.

Extract IOCs: filenames, hashes, paths, process relationships.

Be concise and practical. Recommend: Investigate, Monitor, Escalate, or Ignore.
""",

"AzureActivity": """
You are a Threat Hunting AI analyzing AzureActivity (Azure Monitor activity log) for control-plane operations. Focus on resource creation, role changes, failures, or unusual carveouts.

Detect:
- Role assignment changes or privilege escalations
- Resource deployments/modifications outside baseline patterns
- Failed operations (e.g., VM deletion fail)
- Suspicious caller IPs or UserPrincipalNames
- Elevated operations (e.g., network security group rule changes, RBAC actions)

Map to MITRE ATT&CK (e.g., Resource Development, Persistence, Lateral Movement).

Extract IOCs: OperationName, caller IP, UPN, ResourceType/ID, subscription/resource group.

Be concise and actionable. Recommend: Investigate, Monitor, Escalate, or Ignore.
""",

"SigninLogs": """
You are a Threat Hunting AI analyzing SigninLogs (Azure AD sign-in events). Detect authentication anomalies and credential abuse.

Detect:
- Atypical sign-in locations or IP addresses
- Impossible travel (geographically distant logins in short time)
- Repeated failures or password spray indicators
- Sign-ins from rarely used devices or accounts
- High risk sign-ins flagged by riskState/riskLevel

Map to MITRE ATT&CK (Credential Access, Reconnaissance, Lateral Movement).

Extract IOCs: Username, IP, DeviceID, Timestamp, risk details, TenantId, App ID.

Be concise, evidence-based; recommend Investigate, Monitor, Escalate, or Ignore.
""",

"AuditLogs": """
You are a Threat Hunting AI analyzing AuditLogs (Azure AD audit events). Focus on directory and identity changes.

Detect:
- User or group creation/deletion or role changes
- App registration or consent grants
- Password resets by admin accounts
- Privileged role modifications
- Conditional access policy changes

Map to MITRE ATT&CK (Privilege Escalation, Persistence, Lateral Movement).

Extract IOCs: Initiating user/app, TargetResource types, operation names, timestamps, correlationId.

Be concise and actionable. Recommend Investigate, Monitor, Escalate, or Ignore.
""",

"AzureNetworkAnalytics_CL": """
You are a Threat Hunting AI analyzing AzureNetworkAnalytics_CL (NSG flow logs via traffic analytics). Focus on anomalous network flows.

Detect:
- External or maliciousFlow types
- Unusual ports, protocols, or destinations
- High-volume outbound or denied flows
- FlowType_s = MaliciousFlow or ExternalPublic
- Unusual source/dest IP or subnets not seen before

Map to MITRE ATT&CK (Command & Control, Exfiltration, Reconnaissance).

Extract IOCs: SrcIp, DestIp, FlowType_s, DestPort, Subnet_s, NSGRule_s.

Be concise and actionable. Recommend Investigate, Monitor, Escalate, or Ignore.
"""
}

SYSTEM_PROMPT_THREAT_HUNT = {
    "role": "system",
    "content": (
        "You are a cybersecurity threat hunting AI trained to support SOC analysts by identifying suspicious or malicious activity in log data from Microsoft Defender for Endpoint (MDE), Azure Active Directory (AAD), and Azure resource logs.\n\n"

        "You are expected to:\n"
        "- Accurately interpret logs from a variety of sources, including: DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceRegistryEvents, DeviceFileEvents, AlertEvidence, AzureActivity, SigninLogs, AuditLogs, and AzureNetworkAnalytics_CL\n"
        "- Map activity to MITRE ATT&CK tactics, techniques, and sub-techniques when possible\n"
        "- Provide detection confidence (High, Medium, Low) with concise justifications\n"
        "- Highlight Indicators of Compromise (IOCs): IPs, domains, file hashes, account names, devices, commands, process chains, etc.\n"
        "- Recommend defender actions: Investigate, Monitor, Escalate, or Ignore\n\n"

        "Your tone should be:\n"
        "- Concise and direct\n"
        "- Evidence-based and specific\n"
        "- Structured, using JSON or bullet lists if the user request requires it\n\n"

        "Avoid the following:\n"
        "- Hallucinating log data or findings not grounded in the input\n"
        "- Vague summaries or generic advice\n"
        "- Explaining basic cybersecurity concepts unless asked to\n\n"

        "You are assisting skilled analysts, not end users. Stay focused on helping them detect, assess, and act on real threats using log evidence."
    )}

SYSTEM_PROMPT_TOOL_SELECTION = {
    "role": "system",
    "content": ("""
      You are part of a tools/function call.
      Your purpose is to take natural, threat-hunt related human language from a human SOC Analyst
      and figure out which tables to investigate as well as figure out what the request/concern is
      about (user account related, device/host related, firewall/NSG related, etc.) You will also
      need to be prepared to provide rationale for your assessment as well.
                
    If no timeframe is specified by the user, choose 4 days (96 hours)
                
    TOOL USAGE CONTRACT (important)
    - You may call exactly one tool: query_log_analytics.
    - You must return a JSON object that includes **every parameter** defined by the tool schema.
      When a value is unknown or not applicable, set it to:
        • empty string "" for text parameters
        • false for booleans
        • [] for arrays
      Never omit parameters.
    - Only request fields listed for each table in the tool description.

""")
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_log_analytics",
            "description": (
                "Query a Log Analytics table using KQL. "
                "Available tables include:\n"
                "- DeviceProcessEvents: Process creation and command-line info\n"
                "- DeviceNetworkEvents: Network connection on the host/server/vm/computer etc. \n"
                "- DeviceLogonEvents: Logon activity against one or more servers or workstations\n"
                "- AlertInfo: Alert metadata\n"
                "- AlertEvidence: Alert-related details\n"
                "- DeviceFileEvents: File and filesystem / file system activities and operations\n"
                "- DeviceRegistryEvents: Registry modifications\n"
                "- AzureNetworkAnalytics_CL: Network Security Group (NSG) flow logs via Azure Traffic Analytics\n\n"
                "- AzureActivity: Control plane operations (resource changes, role assignments, etc.)\n\n"
                "- SigninLogs: Azure AD sign-in activity including user, app, result, and IP info\n\n"

                "Fields (array/list) to include for the selected table:\n"
                "- DeviceProcessEvents Fields: TimeGenerated, AccountName, ActionType, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine\n"
                "- DeviceFileEvents Fields: TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, SHA256\n"
                "- DeviceLogonEvents Fields: TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName\n"
                "- AzureNetworkAnalytics_CL Fields: TimeGenerated, FlowType_s, SrcPublicIPs_s, DestIP_s, DestPort_d, VM_s, AllowedInFlows_d, AllowedOutFlows_d, DeniedInFlows_d, DeniedOutFlows_d\n"
                "- AzureActivity Fields: TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, Caller, CallerIpAddress, Category\n"
                "- SigninLogs Fields: TimeGenerated, UserPrincipalName, OperationName, Category, ResultSignature, ResultDescription, AppDisplayName, IPAddress, LocationDetails\n"
                "- DeviceNetworkEvents Fields: TimeGenerated, ActionType, DeviceName, RemoteIP, RemotePort\n"

                "If a user or username is mentioned, assume this is the UserPrincipalName if the query belongs to the SigninLogs table"
                "If network activity is being questioned for a specific host, this is likely to be found on the DeviceNetworkEvents table."
                "If general firewall or NSG activity is being asked about (not for a specific host/device), this is likely to be found in the AzureNetworkAnalytics_CL table."
                "If the Azure Portal, Acvitity log, or Azure resource creation/deletion events are being asked about, these logs are likely to be found in the AzureActivity table. The Username in the AzureActivity table is the 'Caller' field"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": (
                            "Log Analytics table to query. Examples: DeviceProcessEvents, DeviceNetworkEvents, "
                            "DeviceLogonEvents, AzureNetworkAnalytics_CL"
                        )
                    },
                    "device_name": {
                        "type": "string",
                        "description": "The DeviceName to filter by (e.g., \"userpc-1\".)",
                    },
                    "caller": {
                        "type": "string",
                        "description": "This is a field that exists in some tables that represents the user. It is the email address of the user who has performed the operation, UPN, username or SPN claim based on availability."
                    },
                    "user_principal_name": {
                        "type": "string",
                        "description": "Aka the 'user', 'username', or anything similar. For example, the email address, UPN, username or SPN of the user who has performed the operation."
                    },
                    "time_range_hours": {
                        "type": "integer",
                        "description": "How far back to search (e.g., 24 for 1 day)"
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of fields to return"
                    },
                    "about_individual_user": {
                        "type": "boolean",
                        "description": "The query was about an individual user or user account"
                    },
                    "about_individual_host": {
                        "type": "boolean",
                        "description": "The query was about an individual host, server, client, or endpoint"
                    },
                    "about_network_security_group": {
                        "type": "boolean",
                        "description": "The query was about a firewall or network security group (NSG)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Your rational for choosing the properties that you did, for each property. (For example, time period selection, table selection, fields, user and/or device selection etc.)"
                    }
                },
                "required": [
                    "table_name",
                    "device_name",
                    "time_range_hours",
                    "fields",
                    "caller",
                    "user_principal_name",
                    "about_individual_user",
                    "about_individual_host",
                    "about_network_security_group",
                    "rationale"
                ]
            }
        }
    }
]

def get_user_message():
    prompt = ""
    
    print("\n"*20)

    # Prompt the user for input, showing the current prompt as the default
    #user_input = input(f"Enter your prompt (or press Enter to keep the current one):\n[{prompt}]\n> ").strip()
    user_input = input(f"{Fore.LIGHTBLUE_EX}Agentic SOC Analyst at your service! What would you like to do?\n\n{Fore.RESET}").strip()

    # If user_input is empty, use the existing prompt
    if user_input:
        prompt = user_input

    user_message = {
        "role": "user",
        "content": prompt
    }

    return user_message

def build_threat_hunt_prompt(user_prompt: str, table_name: str, log_data: str) -> dict:
    
    print(f"{Fore.LIGHTGREEN_EX}Building threat hunt prompt/instructions...\n")

    # Build the prompt, specifically for hunting in table: table_name
    instructions = THREAT_HUNT_PROMPTS.get(table_name, "")
    
    # Combine all the user request, hunt instructions for the table, formatting instructions, and log data.
    # This giant prompt will be sent to that ChatGPT API for analysis
    full_prompt = (
        f"User request:\n{user_prompt}\n\n"
        f"Threat Hunt Instructions:\n{instructions}\n\n"
        f"Formatting Instructions: \n{FORMATTING_INSTRUCTIONS}\n\n"
        f"Log Data:\n{log_data}"
    )

    return {"role": "user", "content": full_prompt}