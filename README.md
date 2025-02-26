# 🚨 Threat Hunting Scenario: Unusual Network Slowdown Caused by Rox Threat Lab Port Scanning Activity 🚨

---

## 🕒 Timeline Summary & Findings

A suspicious virtual machine, **rox-threatlab-** (`10.0.0.95`), was observed making multiple **failed connection attempts** to two servers (`10.0.0.4` and `10.0.0.5`). This behavior suggests **potential reconnaissance** or unauthorized access attempts.

### 🔍 Query Used:
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

![image](https://github.com/user-attachments/assets/b3765ba3-292b-4bf7-b150-b66c4a7780a3)

---

## 🔺 Attack Escalation

Shortly after, a **new host**, **rox-threat-lab-1**, emerged, attempting **over 200% more connection attempts** than the original VM.  
This **aggressive increase** suggests an **attacker adapting their approach** after initial failures.

### 🔍 Query Used:
```kusto
let IPInQuestion = "10.0.0.95";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```

![image](https://github.com/user-attachments/assets/05b740fa-1dbe-40d4-875d-c09769b675ad)


---

## 🔎 Evidence of Port Scanning

Analysis of failed connection logs revealed a **high volume of attempts across multiple ports**, a strong indication of **port scanning activity**.

### 🔍 Query Used:
```kusto
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/17ab2b53-6f74-4af6-b820-5f7f6b080f74)


---

## 🖥️ Process Investigation

To further investigate, I examined **process execution logs** approximately **10 minutes before the port scan started** (`2025-01-29T00:37:27.546255Z`).  
While **rox-threat-lab-1** returned no relevant logs, **rox-threat-lab** showed **PowerShell activity**, indicating an automated attack.

![image](https://github.com/user-attachments/assets/42d59757-b0f9-4860-9c29-d3f555af24e4)

### 🔍 Query Used:
```kusto
let VMName = "rox-threat-lab";
let specificTime = datetime(2025-01-29T00:37:27.546255Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

![image](https://github.com/user-attachments/assets/79dab5e0-b632-4396-b522-2807753bf4f0)


### 🔎 Key Finding:
✔️ **PowerShell was used to download and execute a port scan script**, confirming attacker automation.  

![image](https://github.com/user-attachments/assets/d665a6c9-b76b-4bd6-890f-62e16e9be780)

---

## 🚧 Containment & Mitigation

After further analysis, it was discovered that the **port scan script was executed by the SYSTEM account**, which is highly unusual.  
Since this **was not an administrator-configured task**, immediate action was taken:

### **✅ Actions Taken:**
- **🛑 Isolated the VM** in Microsoft Defender for Endpoint (MDE).
- **🔍 Conducted a full malware scan** on the system.

### **📌 Scan Results:**
- ✅ **No malware detected.**
- 🚨 **Out of caution, the VM remained isolated** and a ticket was created for **reimaging/rebuilding** the machine.

![image](https://github.com/user-attachments/assets/51f6860f-1324-449c-911e-95221489b371)

---

## 🎯 MITRE ATT&CK Framework Mapping

The attack tactics align with the following **MITRE ATT&CK Techniques**:

| TTP ID      | Technique Name                     | Description |
|------------|--------------------------------|-------------|
| **T1595**  | Active Scanning               | Indications of port scanning activity. |
| **T1071**  | Application Layer Protocol    | Potential C2 communication via PowerShell. |
| **T1059.001** | PowerShell Execution        | Use of PowerShell to download and execute a script. |
| **T1202**  | Indirect Command Execution   | Execution of a script via PowerShell. |
| **T1036**  | Masquerading                  | Port scan script executed under the SYSTEM account. |
| **T1562.001** | Impair Defenses            | Potential evasion attempt by modifying security tools. |
| **T1078**  | Valid Accounts (Potential)   | Possible use of stolen credentials. |

---

## 🔧 Response & Mitigation Plan

### **🎯 Incident Response Goal:**
**Contain and mitigate confirmed threats while preventing further compromise.**

### **🚀 Mitigation Steps Taken:**
✔️ **Isolated the compromised VMs** to prevent lateral movement.  
✔️ **Blocked suspicious IPs** at the firewall and NSG level.  
✔️ **Terminated malicious PowerShell processes** running under the SYSTEM account.  
✔️ **Investigated PowerShell logs** for additional signs of compromise.  
✔️ **Reviewed access logs** for unauthorized logins and revoked any compromised credentials.  
✔️ **Reimaged affected VMs** to restore a clean state.  
✔️ **Implemented detection rules** for port scanning and unusual PowerShell execution.  
✔️ **Increased monitoring** for persistent threats or reattempted attacks.  

---

## 🔮 Next Steps & Recommendations

### **🔐 Enhance Security Controls**
- 🔸 **Enforce PowerShell execution restrictions** to prevent unauthorized script execution.
- 🔸 **Restrict SYSTEM account privileges** where applicable.

### **📡 Improve Detection & Monitoring**
- 🔸 **Enable network anomaly detection** to identify abnormal port scanning activity.
- 🔸 **Configure SIEM rules** to trigger alerts for excessive failed connection attempts.

### **📚 Security Awareness & Training**
- 🔸 **Conduct user security awareness training** to recognize and report suspicious activities.
- 🔸 **Implement regular red team exercises** to simulate and prepare for real-world attacks.

---

## 🏁 Conclusion

This investigation revealed an attempted **reconnaissance attack** using **unauthorized PowerShell execution** for **port scanning**.  
Proactive **threat hunting, containment, and mitigation measures** were successfully executed to **neutralize the threat** before further escalation.

🚨 **Final Status:**

✔️ **Threat Contained**  
✔️ **VM Reimaged**  
✔️ **Security Policies Reinforced**  

---
