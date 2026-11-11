# Choix des datasets

## Comparaison
[tableau ci-dessus]

## Dataset principal : OTRF Security-Datasets
Raison : licence MIT (la plus permissive des trois, confirmée en
inspectant le fichier LICENSE du dépôt), étiquetage natif par
technique MITRE ATT&CK, cohérent avec le Knowledge Graph et notre
format d'alerte normalisée.

## Dataset complémentaire : CICIDS2017
Raison : apporte du trafic réseau réel et volumineux, absent de nos
propres alertes Wazuh et de OTRF. Citation obligatoire de
Sharafaldin et al. (2018) en cas d'usage.
Attention : volume important (~51 Go au total) — prévoir de ne
télécharger que les CSV (MachineLearningCSV.zip) plutôt que les PCAP
complets, pour rester compatible avec Colab/Kaggle.

## Écarté : Loghub
Raison : logs système généraux (Hadoop, HDFS, Spark...), peu liés
à des scénarios d'attaque ou à MITRE ATT&CK, moins pertinent pour
un SOC assistant axé cybersécurité.

## Licences
- OTRF Security-Datasets : MIT (libre, y compris usage commercial)
- CICIDS2017 : usage recherche, citation de l'article obligatoire
- Loghub : usage recherche, citation du papier obligatoire
