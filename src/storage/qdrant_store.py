"""Qdrant vector store for PSIRT documents."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.models import (
    Distance,
    VectorParams,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
    Range
)

from ..config import settings
from .embeddings import EmbeddingService, get_embedding_service


class QdrantStore:
    """Vector store using Qdrant for PSIRT documents."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        collection_name: Optional[str] = None,
        embedding_service: Optional[EmbeddingService] = None
    ):
        """
        Initialize Qdrant store.

        Args:
            host: Qdrant host
            port: Qdrant port
            collection_name: Name of the collection
            embedding_service: Embedding service instance
        """
        self.host = host or settings.qdrant_host
        self.port = port or settings.qdrant_port
        self.collection_name = collection_name or settings.qdrant_collection
        self.embedding_service = embedding_service or get_embedding_service()

        # Initialize client
        self._client: Optional[QdrantClient] = None

    @property
    def client(self) -> QdrantClient:
        """Lazy initialize Qdrant client."""
        if self._client is None:
            self._client = QdrantClient(host=self.host, port=self.port)
        return self._client

    def initialize_collection(self, recreate: bool = False) -> None:
        """
        Initialize the vector collection.

        Args:
            recreate: If True, delete existing collection and recreate
        """
        collections = self.client.get_collections().collections
        exists = any(c.name == self.collection_name for c in collections)

        if exists and recreate:
            self.client.delete_collection(self.collection_name)
            exists = False

        if not exists:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(
                    size=self.embedding_service.dimension,
                    distance=Distance.COSINE
                )
            )

            # Create payload indexes for filtering
            self.client.create_payload_index(
                collection_name=self.collection_name,
                field_name="advisory_id",
                field_schema=models.PayloadSchemaType.KEYWORD
            )
            self.client.create_payload_index(
                collection_name=self.collection_name,
                field_name="severity",
                field_schema=models.PayloadSchemaType.KEYWORD
            )
            self.client.create_payload_index(
                collection_name=self.collection_name,
                field_name="risk_score",
                field_schema=models.PayloadSchemaType.FLOAT
            )
            self.client.create_payload_index(
                collection_name=self.collection_name,
                field_name="document_type",
                field_schema=models.PayloadSchemaType.KEYWORD
            )

    def add_document(self, document: Dict[str, Any]) -> str:
        """
        Add a single document to the store.

        Args:
            document: Document dictionary

        Returns:
            Document ID
        """
        doc_id = document.get("id") or str(uuid.uuid4())

        # Generate embedding
        embedding = self.embedding_service.embed_document(document)

        # Prepare payload (exclude large text content)
        payload = {
            "id": doc_id,
            "advisory_id": document.get("advisory_id", ""),
            "title": document.get("title", ""),
            "cve_ids": document.get("cve_ids", []),
            "severity": document.get("risk_assessment", {}).get("severity", "Unknown"),
            "risk_score": document.get("risk_assessment", {}).get("composite_risk_score", 0),
            "priority_level": document.get("risk_assessment", {}).get("priority_level", ""),
            "affected_inventory_count": document.get("inventory_count", 0),
            "document_type": document.get("type", "advisory"),
            "created_at": document.get("created_at", datetime.now().isoformat()),
            "url": document.get("metadata", {}).get("url", ""),
            # Store text for retrieval
            "text_content": document.get("text_content", "")[:10000],  # Limit size
            "full_document": document  # Store full document for retrieval
        }

        # Upsert to Qdrant
        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                PointStruct(
                    id=doc_id,
                    vector=embedding,
                    payload=payload
                )
            ]
        )

        return doc_id

    def add_documents(self, documents: List[Dict[str, Any]], batch_size: int = 100) -> List[str]:
        """
        Add multiple documents to the store.

        Args:
            documents: List of document dictionaries
            batch_size: Batch size for processing

        Returns:
            List of document IDs
        """
        doc_ids = []

        # Process in batches
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]

            # Generate embeddings
            embeddings = self.embedding_service.embed_documents(batch)

            points = []
            for doc, embedding in zip(batch, embeddings):
                doc_id = doc.get("id") or str(uuid.uuid4())
                doc_ids.append(doc_id)

                payload = {
                    "id": doc_id,
                    "advisory_id": doc.get("advisory_id", ""),
                    "title": doc.get("title", ""),
                    "cve_ids": doc.get("cve_ids", []),
                    "severity": doc.get("risk_assessment", {}).get("severity", "Unknown"),
                    "risk_score": doc.get("risk_assessment", {}).get("composite_risk_score", 0),
                    "priority_level": doc.get("risk_assessment", {}).get("priority_level", ""),
                    "affected_inventory_count": doc.get("inventory_count", 0),
                    "document_type": doc.get("type", "advisory"),
                    "created_at": doc.get("created_at", datetime.now().isoformat()),
                    "url": doc.get("metadata", {}).get("url", ""),
                    "text_content": doc.get("text_content", "")[:10000],
                    "full_document": doc
                }

                points.append(PointStruct(
                    id=doc_id,
                    vector=embedding,
                    payload=payload
                ))

            self.client.upsert(
                collection_name=self.collection_name,
                points=points
            )

        return doc_ids

    def search(
        self,
        query: str,
        limit: int = 10,
        score_threshold: float = 0.5,
        filter_severity: Optional[str] = None,
        filter_min_risk_score: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar documents.

        Args:
            query: Search query text
            limit: Maximum number of results
            score_threshold: Minimum similarity score
            filter_severity: Filter by severity level
            filter_min_risk_score: Filter by minimum risk score

        Returns:
            List of matching documents with scores
        """
        # Generate query embedding
        query_embedding = self.embedding_service.embed_text(query)

        # Build filter
        filter_conditions = []

        if filter_severity:
            filter_conditions.append(
                FieldCondition(
                    key="severity",
                    match=MatchValue(value=filter_severity)
                )
            )

        if filter_min_risk_score is not None:
            filter_conditions.append(
                FieldCondition(
                    key="risk_score",
                    range=Range(gte=filter_min_risk_score)
                )
            )

        search_filter = Filter(must=filter_conditions) if filter_conditions else None

        # Search
        results = self.client.search(
            collection_name=self.collection_name,
            query_vector=query_embedding,
            limit=limit,
            score_threshold=score_threshold,
            query_filter=search_filter
        )

        # Format results
        documents = []
        for result in results:
            doc = {
                "id": result.id,
                "score": result.score,
                "advisory_id": result.payload.get("advisory_id"),
                "title": result.payload.get("title"),
                "severity": result.payload.get("severity"),
                "risk_score": result.payload.get("risk_score"),
                "priority_level": result.payload.get("priority_level"),
                "text_content": result.payload.get("text_content"),
                "full_document": result.payload.get("full_document")
            }
            documents.append(doc)

        return documents

    def get_by_advisory_id(self, advisory_id: str) -> Optional[Dict[str, Any]]:
        """Get a document by advisory ID."""
        results = self.client.scroll(
            collection_name=self.collection_name,
            scroll_filter=Filter(
                must=[
                    FieldCondition(
                        key="advisory_id",
                        match=MatchValue(value=advisory_id)
                    )
                ]
            ),
            limit=1
        )

        if results[0]:
            point = results[0][0]
            return point.payload.get("full_document")

        return None

    def get_all_advisories(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all advisories with optional filtering.

        Args:
            limit: Maximum number of results
            offset: Offset for pagination
            severity: Filter by severity

        Returns:
            List of advisory summaries
        """
        filter_conditions = []

        if severity:
            filter_conditions.append(
                FieldCondition(
                    key="severity",
                    match=MatchValue(value=severity)
                )
            )

        search_filter = Filter(must=filter_conditions) if filter_conditions else None

        results = self.client.scroll(
            collection_name=self.collection_name,
            scroll_filter=search_filter,
            limit=limit,
            offset=offset,
            with_payload=True
        )

        advisories = []
        for point in results[0]:
            advisories.append({
                "id": point.id,
                "advisory_id": point.payload.get("advisory_id"),
                "title": point.payload.get("title"),
                "severity": point.payload.get("severity"),
                "risk_score": point.payload.get("risk_score"),
                "priority_level": point.payload.get("priority_level"),
                "cve_ids": point.payload.get("cve_ids"),
                "created_at": point.payload.get("created_at")
            })

        return advisories

    def delete_advisory(self, advisory_id: str) -> bool:
        """Delete an advisory by ID."""
        try:
            self.client.delete(
                collection_name=self.collection_name,
                points_selector=models.FilterSelector(
                    filter=Filter(
                        must=[
                            FieldCondition(
                                key="advisory_id",
                                match=MatchValue(value=advisory_id)
                            )
                        ]
                    )
                )
            )
            return True
        except Exception:
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics."""
        try:
            info = self.client.get_collection(self.collection_name)

            # Count by severity
            severity_counts = {}
            for severity in ["Critical", "High", "Medium", "Low"]:
                results = self.client.count(
                    collection_name=self.collection_name,
                    count_filter=Filter(
                        must=[
                            FieldCondition(
                                key="severity",
                                match=MatchValue(value=severity)
                            )
                        ]
                    )
                )
                severity_counts[severity] = results.count

            return {
                "total_documents": info.points_count,
                "vectors_count": info.vectors_count,
                "severity_distribution": severity_counts,
                "collection_status": info.status
            }
        except Exception as e:
            return {"error": str(e)}


# Global store instance
_qdrant_store: Optional[QdrantStore] = None


def get_qdrant_store() -> QdrantStore:
    """Get or create the global Qdrant store."""
    global _qdrant_store
    if _qdrant_store is None:
        _qdrant_store = QdrantStore()
        _qdrant_store.initialize_collection()
    return _qdrant_store
