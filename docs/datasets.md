
# Dataset Selection

## 1. Dataset Comparison

| Dataset | Content | Format | Size | Labeled | License / Usage Conditions |
|---|---|---|---|---|---|
| **OTRF Security-Datasets** | Benign and malicious security telemetry from different platforms, including Windows, cloud environments, and Linux. Datasets are associated with simulated adversary techniques and security scenarios. | Mainly JSON; formats vary depending on the sub-dataset (including EVTX and other telemetry formats). | Varies by sub-dataset. | Yes, for many datasets, with mappings to MITRE ATT&CK techniques and scenarios. | Conflicting license information: the repository README indicates GPL-3.0, while its introduction and repository metadata indicate MIT. Verify the LICENSE file for the exact version and data used. |
| **CICIDS2017** | Benign and malicious network traffic captured over five days (July 3–7, 2017). Includes FTP/SSH brute force, DoS, DDoS, Heartbleed, web attacks, infiltration, botnet, and port scanning. | PCAP and labeled CSV network flows generated using CICFlowMeter. | Approximately 51.1 GB of captured data (11 + 11 + 13 + 7.8 + 8.3 GB). | Yes, network flows labeled using timestamps, source/destination IPs, ports, protocols, and attack categories. | Publicly available for research purposes. Citation of Sharafaldin et al. (2018) is required. No standard open-source license is specified on the official dataset page. |
| **Loghub** | Collection of system and application logs from HDFS, Hadoop, Spark, OpenStack, BGL, Thunderbird, Linux, Windows, Apache, OpenSSH, and other systems. | Raw text logs. | Varies by sub-dataset, from a few MB to tens of GB. | Partially labeled. Labeled subsets include HDFS_v1, HDFS_v3, OpenStack, BGL, and Thunderbird. Hadoop has a labeling reference that requires further verification. Most other subsets are unlabeled. | Freely available for research and academic work. Citation of the relevant Loghub publications is required. |

## 2. Selected Primary Dataset: OTRF Security-Datasets

**Reason for selection:**

OTRF Security-Datasets is selected as the primary dataset because it provides security telemetry associated with benign and simulated malicious activities.

Its main advantages include:

- **Security-focused data:** Provides events from different platforms and security scenarios.
- **MITRE ATT&CK mapping:** Many datasets are associated with adversary techniques, supporting attack analysis and threat investigation.
- **SOC relevance:** Suitable for developing and evaluating security event analysis and incident investigation capabilities.
- **Project compatibility:** Its security telemetry can be used to complement our normalized Wazuh alert format and MITRE ATT&CK Knowledge Graph.

**License consideration:**

The repository contains conflicting license information (MIT and GPL-3.0). The license of the exact repository version and selected data must be verified before redistribution or reuse.

## 3. Selected Complementary Dataset: CICIDS2017

**Reason for selection:**

CICIDS2017 complements OTRF Security-Datasets by providing labeled network traffic data, allowing the project to extend its analysis beyond host-based security events.

It enables us to:

- Extend threat detection to network-level attacks.
- Evaluate detection capabilities against multiple attack categories.
- Analyze network flow features and identify suspicious traffic patterns.
- Complement host-based security events with network-level telemetry.

**Important considerations:**

- The dataset contains approximately 51.1 GB of captured traffic.
- The traffic was collected in a controlled laboratory environment with simulated attacks and realistic benign activity.
- Downloading all PCAP files may be impractical in resource-constrained environments.
- We recommend using the labeled CSV files from `MachineLearningCSV.zip` for machine learning experiments.
- Citation of Sharafaldin et al. (2018) is required.

## 4. Non-Selected Dataset: Loghub

**Reason for exclusion:**

Loghub was not selected as a primary dataset because its main focus is general system and application log analysis rather than security attack scenarios mapped to MITRE ATT&CK.

Although some subsets provide anomaly or alert labels, most datasets are not directly aligned with the project's current objectives.

However, Loghub remains a potential complementary resource for future experiments involving:

- Log parsing and preprocessing.
- System log anomaly detection.
- General log analysis and event classification.

Therefore, it is not included in the initial dataset selection, but it may be considered in future project extensions.

## 5. References

- OTRF Security-Datasets: https://github.com/OTRF/Security-Datasets
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- Loghub: https://github.com/logpai/loghub

**CICIDS2017 Research Paper:**

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP, 2018.

**Loghub Research Paper:**

Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, and Michael R. Lyu, "Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics", ISSRE, 2023.

un SOC assistant axé cybersécurité.

## Licences
- OTRF Security-Datasets : MIT (libre, y compris usage commercial)
- CICIDS2017 : usage recherche, citation de l'article obligatoire
- Loghub : usage recherche, citation du papier obligatoire
