"""Question-Answering chain for PSIRT queries."""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.language_models.chat_models import BaseChatModel

from .retriever import PSIRTRetriever, RetrievedDocument, get_retriever
from ..storage.settings_store import get_settings


@dataclass
class QAResponse:
    """Response from the QA chain."""
    answer: str
    sources: List[Dict[str, Any]]
    query: str
    confidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "answer": self.answer,
            "sources": self.sources,
            "query": self.query,
            "confidence": self.confidence
        }


QA_SYSTEM_PROMPT = """You are a cybersecurity expert assistant specializing in Cisco network security advisories and PSIRT (Product Security Incident Response Team) analysis.

Your role is to:
1. Answer questions about security vulnerabilities accurately and thoroughly
2. Provide specific technical details when available
3. Recommend actionable mitigation steps
4. Cite sources by advisory ID when referencing specific vulnerabilities
5. Be clear when information is not available in the provided context

Guidelines:
- Always base your answers on the provided context
- If the context doesn't contain relevant information, say so clearly
- Provide specific advisory IDs and CVE numbers when available
- Prioritize actionable recommendations
- Consider the risk level and urgency when answering
- Use technical language appropriate for security professionals

When discussing vulnerabilities, structure your response to include (when applicable):
- What the vulnerability is
- Who/what is affected
- Risk level and potential impact
- Recommended actions
- References to specific advisories"""

QA_PROMPT = ChatPromptTemplate.from_messages([
    ("system", QA_SYSTEM_PROMPT),
    ("human", """Based on the following security advisory context, please answer the question.

CONTEXT:
{context}

QUESTION: {question}

Please provide a comprehensive answer based on the context. Include relevant advisory IDs and specific recommendations where applicable. If the context doesn't contain sufficient information to answer the question, clearly state what information is missing.""")
])


def create_llm(provider: str = None, api_key: str = None, temperature: float = 0.1) -> BaseChatModel:
    """
    Create an LLM instance based on provider and API key.

    Args:
        provider: 'anthropic', 'openai', or 'bedrock'. If None, uses settings.
        api_key: API key. If None, uses settings (not needed for bedrock).
        temperature: LLM temperature

    Returns:
        LLM instance
    """
    settings = get_settings()
    config = settings.get_active_llm_config()

    if provider is None:
        provider = config.get("provider")

    if not provider:
        raise ValueError("No LLM provider configured. Please configure in Admin settings.")

    if provider == "bedrock":
        from langchain_aws import ChatBedrock
        import boto3

        # Use IAM role credentials (automatic in ECS)
        bedrock_client = boto3.client(
            "bedrock-runtime",
            region_name=config.get("region", settings.aws_region)
        )

        return ChatBedrock(
            client=bedrock_client,
            model_id=config.get("model_id", settings.bedrock_model_id),
            model_kwargs={
                "temperature": temperature,
                "max_tokens": 4096
            }
        )
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        key = api_key or config.get("api_key")
        if not key:
            raise ValueError("Anthropic API key not configured.")
        return ChatAnthropic(
            model="claude-sonnet-4-20250514",
            anthropic_api_key=key,
            temperature=temperature,
            max_tokens=4096
        )
    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        key = api_key or config.get("api_key")
        if not key:
            raise ValueError("OpenAI API key not configured.")
        return ChatOpenAI(
            model="gpt-4o",
            openai_api_key=key,
            temperature=temperature,
            max_tokens=4096
        )
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


class PSIRTQAChain:
    """
    Question-Answering chain for PSIRT security queries.

    Uses RAG (Retrieval-Augmented Generation) to answer questions
    about security advisories using Claude or OpenAI.
    """

    def __init__(
        self,
        retriever: Optional[PSIRTRetriever] = None,
        temperature: float = 0.1
    ):
        """
        Initialize the QA chain.

        Args:
            retriever: PSIRT retriever instance
            temperature: LLM temperature
        """
        self.retriever = retriever or get_retriever()
        self.temperature = temperature
        self._llm: Optional[BaseChatModel] = None

    @property
    def llm(self) -> BaseChatModel:
        """Get or create the LLM instance."""
        # Always create fresh to pick up settings changes
        return create_llm(temperature=self.temperature)

    def _extract_sources(self, documents: List[RetrievedDocument]) -> List[Dict[str, Any]]:
        """Extract source information from retrieved documents."""
        sources = []
        for doc in documents:
            sources.append({
                "advisory_id": doc.advisory_id,
                "title": doc.title,
                "severity": doc.severity,
                "risk_score": doc.risk_score,
                "similarity_score": round(doc.similarity_score, 3),
                "url": doc.full_document.get("metadata", {}).get("url", "")
            })
        return sources

    def _assess_confidence(self, documents: List[RetrievedDocument]) -> str:
        """Assess confidence based on retrieved documents."""
        if not documents:
            return "low"

        avg_score = sum(d.similarity_score for d in documents) / len(documents)

        if avg_score >= 0.75 and len(documents) >= 3:
            return "high"
        elif avg_score >= 0.5 and len(documents) >= 2:
            return "medium"
        else:
            return "low"

    def query(
        self,
        question: str,
        limit: int = 5,
        severity_filter: Optional[str] = None,
        min_risk_score: Optional[float] = None
    ) -> QAResponse:
        """
        Answer a question about PSIRT advisories.

        Args:
            question: User question
            limit: Number of documents to retrieve
            severity_filter: Optional severity filter
            min_risk_score: Optional minimum risk score filter

        Returns:
            QAResponse with answer and sources
        """
        # Retrieve relevant documents
        documents = self.retriever.retrieve(
            query=question,
            limit=limit,
            severity_filter=severity_filter,
            min_risk_score=min_risk_score
        )

        # Build context
        context = self.retriever.build_context(documents)

        if not context.strip():
            return QAResponse(
                answer="I don't have any relevant security advisory information to answer this question. Please ensure the PSIRT database has been populated with advisories by running an analysis first.",
                sources=[],
                query=question,
                confidence="none"
            )

        # Generate answer
        try:
            chain = QA_PROMPT | self.llm | StrOutputParser()

            answer = chain.invoke({
                "context": context,
                "question": question
            })
        except ValueError as e:
            return QAResponse(
                answer=str(e),
                sources=[],
                query=question,
                confidence="none"
            )
        except Exception as e:
            return QAResponse(
                answer=f"Error generating response: {str(e)}",
                sources=[],
                query=question,
                confidence="none"
            )

        # Extract sources and assess confidence
        sources = self._extract_sources(documents)
        confidence = self._assess_confidence(documents)

        return QAResponse(
            answer=answer,
            sources=sources,
            query=question,
            confidence=confidence
        )

    async def aquery(
        self,
        question: str,
        limit: int = 5,
        severity_filter: Optional[str] = None,
        min_risk_score: Optional[float] = None
    ) -> QAResponse:
        """Async version of query."""
        documents = self.retriever.retrieve(
            query=question,
            limit=limit,
            severity_filter=severity_filter,
            min_risk_score=min_risk_score
        )

        context = self.retriever.build_context(documents)

        if not context.strip():
            return QAResponse(
                answer="I don't have any relevant security advisory information to answer this question.",
                sources=[],
                query=question,
                confidence="none"
            )

        try:
            chain = QA_PROMPT | self.llm | StrOutputParser()

            answer = await chain.ainvoke({
                "context": context,
                "question": question
            })
        except ValueError as e:
            return QAResponse(
                answer=str(e),
                sources=[],
                query=question,
                confidence="none"
            )
        except Exception as e:
            return QAResponse(
                answer=f"Error generating response: {str(e)}",
                sources=[],
                query=question,
                confidence="none"
            )

        sources = self._extract_sources(documents)
        confidence = self._assess_confidence(documents)

        return QAResponse(
            answer=answer,
            sources=sources,
            query=question,
            confidence=confidence
        )

    def query_about_cve(self, cve_id: str) -> QAResponse:
        """
        Get information about a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            QAResponse with CVE information
        """
        question = f"What information do you have about {cve_id}? Include affected products, risk level, and recommended mitigations."
        return self.query(question, limit=5)

    def query_about_product(
        self,
        product: str,
        severity: Optional[str] = None
    ) -> QAResponse:
        """
        Get vulnerabilities affecting a specific product.

        Args:
            product: Product name
            severity: Optional severity filter

        Returns:
            QAResponse with product vulnerabilities
        """
        severity_text = f" {severity} severity" if severity else ""
        question = f"What{severity_text} vulnerabilities affect {product}? List the advisories and recommended actions."
        return self.query(question, limit=10, severity_filter=severity)

    def get_mitigation_recommendations(
        self,
        advisory_id: str
    ) -> QAResponse:
        """
        Get mitigation recommendations for a specific advisory.

        Args:
            advisory_id: Cisco advisory ID

        Returns:
            QAResponse with mitigation steps
        """
        question = f"What are the mitigation steps and recommended actions for advisory {advisory_id}? Include workarounds if patches are not available."
        return self.query(question, limit=3)

    def get_risk_summary(self) -> QAResponse:
        """
        Get a summary of high-risk vulnerabilities.

        Returns:
            QAResponse with risk summary
        """
        question = "Summarize the critical and high severity vulnerabilities. What are the most urgent security issues that need immediate attention?"
        return self.query(question, limit=10, severity_filter="Critical")


# Convenience function
def get_qa_chain() -> PSIRTQAChain:
    """Get a QA chain instance."""
    return PSIRTQAChain()


# Simple interface for quick queries
def ask_psirt(question: str) -> str:
    """
    Quick interface to ask PSIRT questions.

    Args:
        question: Security question

    Returns:
        Answer string
    """
    qa = get_qa_chain()
    response = qa.query(question)
    return response.answer
