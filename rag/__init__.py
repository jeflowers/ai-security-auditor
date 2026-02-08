"""
RAG Pipeline for AI-Powered Security Auditor

Components:
- DocumentProcessor: Chunks compliance documents
- EmbeddingService: Generates embeddings (OpenAI/local)
- ComplianceVectorStore: ChromaDB-based storage
- ComplianceRAGPipeline: Main orchestration layer
"""

from .document_processor import (
    DocumentProcessor,
    DocumentChunk,
    DocumentType,
)

from .embeddings import (
    EmbeddingService,
    EmbeddingResult,
    EmbeddingCache,
    OpenAIEmbeddingService,
    LocalEmbeddingService,
    create_embedding_service,
)

from .vector_store import (
    ComplianceVectorStore,
    SearchResult,
)

from .pipeline import (
    ComplianceRAGPipeline,
    RetrievalContext,
    create_pipeline,
)

__all__ = [
    # Document Processing
    "DocumentProcessor",
    "DocumentChunk",
    "DocumentType",
    
    # Embeddings
    "EmbeddingService",
    "EmbeddingResult",
    "EmbeddingCache",
    "OpenAIEmbeddingService",
    "LocalEmbeddingService",
    "create_embedding_service",
    
    # Vector Store
    "ComplianceVectorStore",
    "SearchResult",
    
    # Pipeline
    "ComplianceRAGPipeline",
    "RetrievalContext",
    "create_pipeline",
]
