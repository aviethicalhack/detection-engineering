# Detection Engineering Lab

A practical cybersecurity detection engineering lab focused on developing, testing, validating, and documenting threat detections.

This repository contains hands-on work covering Sigma rules, YARA rules, Windows and Linux detection logic, SIEM queries, Sysmon telemetry, MITRE ATT&CK mapping, investigation workflows, and detection validation.

---

## Objectives

The main objectives of this lab are to:

- Develop practical threat detection capabilities
- Write and document Sigma detection rules
- Develop YARA rules for malware and suspicious artifacts
- Build SIEM detection queries
- Analyze Windows and Linux telemetry
- Use Sysmon telemetry for endpoint detection
- Map detections to MITRE ATT&CK techniques
- Validate detection logic using controlled test cases
- Document investigation workflows
- Improve detection quality through testing and refinement

---

## Repository Structure

```text
detection-engineering/
│
├── attack-mapping/
│   └── MITRE ATT&CK technique mappings
│
├── datasets/
│   └── Detection-related datasets and test data
│
├── docs/
│   └── Documentation and detection engineering notes
│
├── investigations/
│   └── Investigation case studies
│
├── queries/
│   ├── kql/
│   │   └── KQL detection queries
│   │
│   └── qradar-aql/
│       └── IBM QRadar AQL queries
│
├── scripts/
│   └── Detection and analysis helper scripts
│
├── sigma/
│   ├── linux/
│   │   └── Linux Sigma rules
│   │
│   └── windows/
│       └── Windows Sigma rules
│
├── sysmon/
│   └── configs/
│       └── Sysmon configuration files
│
├── validation/
│   └── Detection testing and validation
│
├── yara/
│   └── rules/
│       └── YARA detection rules
│
├── .gitignore
└── README.md

---

## Detection Engineering Workflow

The detection development process used in this repository follows a structured workflow:

```text
Threat / Attack Behavior
          │
          ▼
   Telemetry Analysis
          │
          ▼
   Detection Hypothesis
          │
          ▼
    Detection Rule
          │
          ▼
     MITRE Mapping
          │
          ▼
       Testing
          │
          ▼
      Validation
          │
          ▼
   False Positive Review
          │
          ▼
     Documentation