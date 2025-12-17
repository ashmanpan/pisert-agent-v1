"""Embedding service for generating document embeddings."""

from typing import List, Optional
from sentence_transformers import SentenceTransformer
import numpy as np

from ..config import settings


class EmbeddingService:
    """Service for generating text embeddings."""

    def __init__(self, model_name: Optional[str] = None):
        """
        Initialize the embedding service.

        Args:
            model_name: Name of the sentence-transformers model to use
        """
        self.model_name = model_name or settings.embedding_model
        self._model: Optional[SentenceTransformer] = None

    @property
    def model(self) -> SentenceTransformer:
        """Lazy load the embedding model."""
        if self._model is None:
            self._model = SentenceTransformer(self.model_name)
        return self._model

    @property
    def dimension(self) -> int:
        """Get the embedding dimension."""
        return self.model.get_sentence_embedding_dimension()

    def embed_text(self, text: str) -> List[float]:
        """
        Generate embedding for a single text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector as list of floats
        """
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def embed_texts(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Generate embeddings for multiple texts.

        Args:
            texts: List of texts to embed
            batch_size: Batch size for encoding

        Returns:
            List of embedding vectors
        """
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=True
        )
        return embeddings.tolist()

    def embed_document(self, document: dict) -> List[float]:
        """
        Generate embedding for a document.

        Uses the text_content field if available, otherwise
        combines title, summary, and other key fields.

        Args:
            document: Document dictionary

        Returns:
            Embedding vector
        """
        # Try to use pre-generated text content
        text = document.get("text_content", "")

        if not text:
            # Build text from document fields
            parts = []

            if document.get("title"):
                parts.append(f"Title: {document['title']}")

            if document.get("advisory_id"):
                parts.append(f"Advisory: {document['advisory_id']}")

            if document.get("cve_ids"):
                parts.append(f"CVEs: {', '.join(document['cve_ids'])}")

            analysis = document.get("analysis", {})
            if analysis.get("when_is_this_a_problem"):
                parts.append(f"Problem: {analysis['when_is_this_a_problem']}")

            if analysis.get("technical_summary"):
                parts.append(f"Technical: {analysis['technical_summary']}")

            risk = document.get("risk_assessment", {})
            if risk.get("impact_description"):
                parts.append(f"Impact: {risk['impact_description']}")

            mitigation = document.get("mitigation", {})
            if mitigation.get("recommended_actions"):
                parts.append(f"Actions: {'; '.join(mitigation['recommended_actions'])}")

            if document.get("recommendation_summary"):
                parts.append(f"Recommendations: {document['recommendation_summary']}")

            text = "\n".join(parts)

        return self.embed_text(text)

    def embed_documents(
        self,
        documents: List[dict],
        batch_size: int = 32
    ) -> List[List[float]]:
        """
        Generate embeddings for multiple documents.

        Args:
            documents: List of document dictionaries
            batch_size: Batch size for encoding

        Returns:
            List of embedding vectors
        """
        texts = []
        for doc in documents:
            text = doc.get("text_content", "")
            if not text:
                text = f"{doc.get('title', '')} {doc.get('advisory_id', '')} {doc.get('recommendation_summary', '')}"
            texts.append(text)

        return self.embed_texts(texts, batch_size=batch_size)

    def similarity(self, embedding1: List[float], embedding2: List[float]) -> float:
        """
        Calculate cosine similarity between two embeddings.

        Args:
            embedding1: First embedding
            embedding2: Second embedding

        Returns:
            Similarity score between 0 and 1
        """
        a = np.array(embedding1)
        b = np.array(embedding2)

        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    def find_most_similar(
        self,
        query_embedding: List[float],
        embeddings: List[List[float]],
        top_k: int = 5
    ) -> List[tuple]:
        """
        Find the most similar embeddings to a query.

        Args:
            query_embedding: Query embedding
            embeddings: List of embeddings to search
            top_k: Number of results to return

        Returns:
            List of (index, similarity_score) tuples
        """
        similarities = []
        for i, emb in enumerate(embeddings):
            sim = self.similarity(query_embedding, emb)
            similarities.append((i, sim))

        # Sort by similarity descending
        similarities.sort(key=lambda x: x[1], reverse=True)

        return similarities[:top_k]


# Global instance
_embedding_service: Optional[EmbeddingService] = None


def get_embedding_service() -> EmbeddingService:
    """Get or create the global embedding service."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service
