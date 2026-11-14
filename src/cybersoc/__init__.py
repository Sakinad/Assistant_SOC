"""CyberSOC AI — intelligent cybersecurity SOC assistant.

Package layout
--------------
``cybersoc.config``     centralised settings (``.env`` driven)
``cybersoc.rag``        chunking, embeddings, vector store, ingestion  (Maroua)
``cybersoc.kg``         Neo4j knowledge graph                          (Karima)
``cybersoc.agents``     LangGraph SOC agents                           (Chayma)
``cybersoc.ingestion``  Wazuh -> normalised alerts                     (Sakina)
``cybersoc.api``        FastAPI backend                               (Sakina)
``cybersoc.security``   LLM security controls                         (Sakina)
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
