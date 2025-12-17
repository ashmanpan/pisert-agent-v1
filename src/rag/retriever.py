"""RAG retriever for PSIRT documents."""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..storage.qdrant_store import QdrantStore, get_qdrant_store
from ..storage.embeddings import EmbeddingService, get_embedding_service


@dataclass
class RetrievedDocument:
    """Represents a retrieved document with score."""
    id: str
    advisory_id: str
    title: str
    severity: str
    risk_score: float
    priority_level: str
    text_content: str
    full_document: Dict[str, Any]
    similarity_score: float

    def to_context_string(self) -> str:
        """Convert to a string suitable for LLM context."""
        return f"""
---
Advisory: {self.advisory_id}
Title: {self.title}
Severity: {self.severity} (Risk Score: {self.risk_score}/10)
Priority: {self.priority_level}

{self.text_content[:3000]}
---
"""


class PSIRTRetriever:
    """
    Retriever for PSIRT security documents.

    Supports:
    - Semantic search
    - Metadata filtering
    - Hybrid retrieval (semantic + keyword)
    """

    def __init__(
        self,
        store: Optional[QdrantStore] = None,
        embedding_service: Optional[EmbeddingService] = None,
        default_limit: int = 5,
        score_threshold: float = 0.4
    ):
        """
        Initialize the retriever.

        Args:
            store: Qdrant store instance
            embedding_service: Embedding service instance
            default_limit: Default number of documents to retrieve
            score_threshold: Minimum similarity score threshold
        """
        self.store = store or get_qdrant_store()
        self.embedding_service = embedding_service or get_embedding_service()
        self.default_limit = default_limit
        self.score_threshold = score_threshold

    def retrieve(
        self,
        query: str,
        limit: Optional[int] = None,
        severity_filter: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        include_full_document: bool = True
    ) -> List[RetrievedDocument]:
        """
        Retrieve relevant documents for a query.

        Args:
            query: Search query
            limit: Maximum number of results
            severity_filter: Filter by severity (Critical, High, Medium, Low)
            min_risk_score: Minimum risk score filter
            include_full_document: Whether to include full document data

        Returns:
            List of RetrievedDocument objects
        """
        limit = limit or self.default_limit

        # Search in vector store
        results = self.store.search(
            query=query,
            limit=limit,
            score_threshold=self.score_threshold,
            filter_severity=severity_filter,
            filter_min_risk_score=min_risk_score
        )

        # Convert to RetrievedDocument objects
        documents = []
        for result in results:
            doc = RetrievedDocument(
                id=result.get("id", ""),
                advisory_id=result.get("advisory_id", ""),
                title=result.get("title", ""),
                severity=result.get("severity", "Unknown"),
                risk_score=result.get("risk_score", 0),
                priority_level=result.get("priority_level", ""),
                text_content=result.get("text_content", ""),
                full_document=result.get("full_document", {}) if include_full_document else {},
                similarity_score=result.get("score", 0)
            )
            documents.append(doc)

        return documents

    def retrieve_by_cve(self, cve_id: str, limit: int = 5) -> List[RetrievedDocument]:
        """
        Retrieve documents related to a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            limit: Maximum number of results

        Returns:
            List of RetrievedDocument objects
        """
        # Use the CVE as the search query
        query = f"CVE {cve_id} vulnerability security advisory"
        return self.retrieve(query, limit=limit)

    def retrieve_by_product(
        self,
        product: str,
        limit: int = 10,
        severity_filter: Optional[str] = None
    ) -> List[RetrievedDocument]:
        """
        Retrieve documents related to a specific product.

        Args:
            product: Product name (e.g., "IOS XR", "ASR9K")
            limit: Maximum number of results
            severity_filter: Optional severity filter

        Returns:
            List of RetrievedDocument objects
        """
        query = f"{product} vulnerability security advisory affected"
        return self.retrieve(query, limit=limit, severity_filter=severity_filter)

    def retrieve_critical(self, limit: int = 10) -> List[RetrievedDocument]:
        """
        Retrieve critical severity documents.

        Args:
            limit: Maximum number of results

        Returns:
            List of critical RetrievedDocument objects
        """
        return self.retrieve(
            query="critical security vulnerability urgent patch required",
            limit=limit,
            severity_filter="Critical"
        )

    def retrieve_high_risk(
        self,
        min_score: float = 7.0,
        limit: int = 10
    ) -> List[RetrievedDocument]:
        """
        Retrieve high-risk documents based on composite risk score.

        Args:
            min_score: Minimum risk score (1-10)
            limit: Maximum number of results

        Returns:
            List of high-risk RetrievedDocument objects
        """
        return self.retrieve(
            query="high risk vulnerability security impact",
            limit=limit,
            min_risk_score=min_score
        )

    def build_context(
        self,
        documents: List[RetrievedDocument],
        max_tokens: int = 8000
    ) -> str:
        """
        Build context string from retrieved documents.

        Args:
            documents: List of retrieved documents
            max_tokens: Approximate maximum context size

        Returns:
            Formatted context string for LLM
        """
        context_parts = []
        current_size = 0
        char_limit = max_tokens * 4  # Approximate chars per token

        for doc in documents:
            doc_context = doc.to_context_string()
            doc_size = len(doc_context)

            if current_size + doc_size > char_limit:
                # Truncate if needed
                remaining = char_limit - current_size
                if remaining > 500:
                    context_parts.append(doc_context[:remaining] + "\n[Truncated...]")
                break

            context_parts.append(doc_context)
            current_size += doc_size

        return "\n".join(context_parts)

    def get_relevant_context(
        self,
        query: str,
        limit: int = 5,
        max_tokens: int = 8000
    ) -> tuple:
        """
        Get relevant context for a query.

        Args:
            query: User query
            limit: Number of documents to retrieve
            max_tokens: Maximum context size

        Returns:
            Tuple of (context_string, retrieved_documents)
        """
        documents = self.retrieve(query, limit=limit)
        context = self.build_context(documents, max_tokens=max_tokens)
        return context, documents


# Convenience function
def get_retriever() -> PSIRTRetriever:
    """Get a retriever instance."""
    return PSIRTRetriever()
