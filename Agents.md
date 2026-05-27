# AI Agent — Behavioral Ransomware Detection

## Objective

Refactor and improve a behavioral ransomware detection pipeline using Machine Learning with:

- Python
- pandas
- scikit-learn
- RandomForestClassifier
- Sysmon
- SHAP
- LIME

The main goal is to build a robust, reusable behavioral analysis architecture that is less dependent on specific telemetry tools such as Sysmon.

---

# Project Context

The project uses:

- LMD-2023 dataset for initial training
- Real logs collected from a controlled Sysmon-monitored environment
- Real ransomware execution inside an isolated virtual machine

Executed ransomware samples:
- WannaCry
- Cerber
- TeslaCrypt
- Locky
- Petya

Collected benign logs:
- Avast installation
- CredentialWindowsViewer

---

# Current Problem

The current pipeline depends too heavily on:
- raw Sysmon Event IDs
- simplistic features
- raw telemetry

This reduces:
- generalization
- portability
- robustness

The LMD-2023 dataset contains logs from:
- multiple environments
- different sandboxes
- multiple telemetry sources

Therefore:
- DO NOT use raw Event IDs as primary features
- DO NOT tightly couple the model to Sysmon-specific telemetry

---

# Main Goal

Transform raw telemetry into:
- abstract behavioral features
- generalized malicious behavior indicators

The AI model should learn:
- behavioral patterns
- frequency
- context
- temporal correlation

Instead of learning:
- specific event numbers

---

# Important Rules

## DO NOT

- Do not use raw Event IDs as the primary feature
- Do not rely exclusively on Sysmon
- Do not assume all environments expose the same telemetry
- Do not create highly environment-specific features

---

## DO

- Create generalized behavioral features
- Work with aggregated features
- Use contextual event information
- Build reusable pipelines
- Implement feature engineering
- Separate parsing, training, and inference logic

---

# Expected Architecture

```text
EVTX/XML
↓
Parser
↓
Normalized DataFrame
↓
Feature Engineering
↓
Aggregated Behavioral Features
↓
Training / Inference
↓
SHAP / LIME
```

---

# Expected Behavioral Features

## Processes

- number of created processes
- number of child processes
- number of unique processes
- process creation frequency
- high-privilege execution
- ParentImage → Image relationships

---

## Filesystem

- number of created files
- number of modified files
- number of suspicious extensions
- file modification rate
- mass filesystem access behavior

---

## Registry

- number of registry modifications
- critical registry key changes
- Run/RunOnce persistence
- registry write frequency

---

## Network

- number of network connections
- number of unique IPs
- number of unique ports
- external connections
- DNS activity
- number of DNS queries

---

## Temporal Features

- events per second
- burst behavior
- filesystem bursts
- process bursts

---

# Compatibility Requirements

The behavioral features must work with:
- Sysmon logs
- LMD-2023
- multiple telemetry sources

The AI should learn:
- behavior
instead of:
- tool-specific identifiers

---

# Log Parser

Build a Python parser for:
- XML exported from EVTX/Event Viewer
- robust XML parsing
- missing field handling
- column normalization
- IP conversion
- DataFrame generation

Use:
- xml.etree.ElementTree
or
- lxml

---

# Machine Learning Pipeline

Use:
- sklearn Pipeline
- ColumnTransformer
- OneHotEncoder
- missing value handling
- RandomForestClassifier

Persist:
- model.joblib
- preprocessor.joblib
- metadata.json

---

# Inference

Build an inference pipeline that:
- loads trained artifacts
- normalizes data
- aligns columns automatically
- performs:
  - predict()
  - predict_proba()
  - risk scoring

Outputs:
- prediction CSV
- ransomware probability score

---

# Explainable AI (XAI)

Integrate:
- SHAP
- LIME

Fix common issues:
- dimensionality mismatches
- multiclass handling
- expected_value issues
- incompatibility between arrays and features

---

# Expected Project Structure

```text
/data
/models
/parser
/train
/inference
/xai
/logs
/notebooks
```

---

# Code Quality Requirements

The implementation must include:
- modular architecture
- type hints
- logging
- exception handling
- clear comments
- reusable functions
- large dataset compatibility
- memory-efficient processing

---

# Scientific Objective

The proposal should demonstrate:
- behavioral ransomware detection
- cross-environment generalization
- partial independence from telemetry tooling
- extraction of real malicious behavior patterns

---

# Experimental Observations

During testing:
- some samples generated rich telemetry
- some partially failed
- Petya compromised the VM bootloader

These observations should be treated as:
- valid experimental limitations
- expected challenges of local dynamic malware analysis

---

# Expected Final Result

A professional behavioral detection pipeline capable of:
- processing real logs
- generating behavioral features
- training RandomForest models
- detecting ransomware behavior
- explaining decisions via SHAP/LIME
- operating across multiple telemetry sources