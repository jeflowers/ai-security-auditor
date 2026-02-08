"""
Vector Store for RAG Pipeline

ChromaDB-based vector store with:
- Metadata filtering (control_id, evidence_id, document_type)
- Hybrid search (semantic + keyword)
- Collection management
- Persistence to disk

Optimized for compliance document retrieval.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import asyncio

import chromadb
from chromadb.config import Settings

from .document_processor import DocumentChunk, DocumentType
from .embeddings import EmbeddingService


@dataclass
class SearchResult:
    """Result from vector search."""
    chunk_id: str
    content: str
    score: float  # Similarity score (higher = more similar)
    metadata: dict[str, Any]
    
    # Extracted for convenience
    control_ids: list[str] = None
    evidence_ids: list[str] = None
    document_type: str = None
    
    def __post_init__(self):
        self.control_ids = self.metadata.get("control_ids", [])
        self.evidence_ids = self.metadata.get("evidence_ids", [])
        self.document_type = self.metadata.get("document_type", "")


class ComplianceVectorStore:
    """
    Vector store optimized for compliance documents.
    
    Features:
    - Separate collections for different document types
    - Metadata filtering for precise retrieval
    - Hybrid search combining semantic and keyword matching
    - Automatic chunking and embedding
    """
    
    # Collection names for different document types
    COLLECTIONS = {
        "controls": "compliance_controls",
        "evidence": "compliance_evidence",
        "policies": "compliance_policies",
        "rubrics": "compliance_rubrics",
    }
    
    def __init__(
        self,
        embedding_service: EmbeddingService,
        persist_dir: Path = None,
        collection_prefix: str = ""
    ):
        self.embedding_service = embedding_service
        self.persist_dir = Path(persist_dir) if persist_dir else None
        self.collection_prefix = collection_prefix
        
        # Initialize ChromaDB
        if self.persist_dir:
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True
                )
            )
        else:
            self.client = chromadb.Client(
                settings=Settings(anonymized_telemetry=False)
            )
        
        self._collections = {}
    
    def _get_collection_name(self, name: str) -> str:
        """Get full collection name with prefix."""
        base_name = self.COLLECTIONS.get(name, name)
        if self.collection_prefix:
            return f"{self.collection_prefix}_{base_name}"
        return base_name
    
    def _get_or_create_collection(self, name: str):
        """Get or create a ChromaDB collection."""
        full_name = self._get_collection_name(name)
        
        if full_name not in self._collections:
            self._collections[full_name] = self.client.get_or_create_collection(
                name=full_name,
                metadata={
                    "hnsw:space": "cosine",
                    "embedding_model": self.embedding_service.model_name,
                    "dimensions": self.embedding_service.dimensions
                }
            )
        
        return self._collections[full_name]
    
    def _chunk_to_metadata(self, chunk: DocumentChunk) -> dict:
        """Convert chunk to ChromaDB metadata format."""
        # ChromaDB metadata must be str, int, float, or bool
        # Lists need to be serialized to strings
        return {
            "chunk_id": chunk.chunk_id,
            "document_id": chunk.document_id,
            "sequence": chunk.sequence,
            "document_type": chunk.document_type.value,
            "framework": chunk.framework,
            "control_ids": json.dumps(chunk.control_ids),  # Serialize list
            "evidence_ids": json.dumps(chunk.evidence_ids),  # Serialize list
            "source_file": chunk.source_file,
            "source_section": chunk.source_section,
            "content_hash": chunk.content_hash,
            "created_at": chunk.created_at.isoformat(),
        }
    
    def _metadata_to_dict(self, metadata: dict) -> dict:
        """Convert ChromaDB metadata back to dict with lists."""
        result = dict(metadata)
        # Deserialize lists
        if "control_ids" in result:
            result["control_ids"] = json.loads(result["control_ids"])
        if "evidence_ids" in result:
            result["evidence_ids"] = json.loads(result["evidence_ids"])
        return result
    
    async def add_chunks(
        self,
        chunks: list[DocumentChunk],
        collection_name: str = "controls"
    ) -> int:
        """
        Add document chunks to the vector store.
        
        Returns number of chunks added.
        """
        if not chunks:
            return 0
        
        collection = self._get_or_create_collection(collection_name)
        
        # Generate embeddings for all chunks
        texts = [chunk.content for chunk in chunks]
        embeddings = await self.embedding_service.embed_batch(texts)
        
        # Prepare data for ChromaDB
        ids = [chunk.chunk_id for chunk in chunks]
        documents = texts
        metadatas = [self._chunk_to_metadata(chunk) for chunk in chunks]
        
        # Add to collection
        collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas
        )
        
        return len(chunks)
    
    async def search(
        self,
        query: str,
        collection_name: str = "controls",
        n_results: int = 5,
        filter_control_id: str = None,
        filter_evidence_id: str = None,
        filter_document_type: DocumentType = None,
        filter_framework: str = None,
        min_score: float = 0.0
    ) -> list[SearchResult]:
        """
        Search for relevant chunks.
        
        Args:
            query: Search query text
            collection_name: Which collection to search
            n_results: Maximum number of results
            filter_control_id: Filter to specific control
            filter_evidence_id: Filter to specific evidence
            filter_document_type: Filter by document type
            filter_framework: Filter by framework
            min_score: Minimum similarity score (0-1)
        
        Returns:
            List of SearchResult objects sorted by relevance
        """
        collection = self._get_or_create_collection(collection_name)
        
        # Generate query embedding
        query_embedding = await self.embedding_service.embed_text(query)
        
        # Build where filter
        where_filter = {}
        if filter_framework:
            where_filter["framework"] = filter_framework
        if filter_document_type:
            where_filter["document_type"] = filter_document_type.value
        
        # ChromaDB doesn't support filtering on serialized lists directly
        # We'll filter those in post-processing
        
        # Execute search
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results * 2 if filter_control_id or filter_evidence_id else n_results,
            where=where_filter if where_filter else None,
            include=["documents", "metadatas", "distances"]
        )
        
        # Process results
        search_results = []
        
        if results["ids"] and results["ids"][0]:
            for i, chunk_id in enumerate(results["ids"][0]):
                # ChromaDB returns distances, convert to similarity score
                # For cosine distance: similarity = 1 - distance
                distance = results["distances"][0][i]
                score = 1 - distance
                
                if score < min_score:
                    continue
                
                metadata = self._metadata_to_dict(results["metadatas"][0][i])
                
                # Apply post-filters
                if filter_control_id:
                    if filter_control_id not in metadata.get("control_ids", []):
                        continue
                
                if filter_evidence_id:
                    if filter_evidence_id not in metadata.get("evidence_ids", []):
                        continue
                
                search_results.append(SearchResult(
                    chunk_id=chunk_id,
                    content=results["documents"][0][i],
                    score=score,
                    metadata=metadata
                ))
        
        # Sort by score and limit
        search_results.sort(key=lambda x: x.score, reverse=True)
        return search_results[:n_results]
    
    async def search_by_control(
        self,
        control_id: str,
        query: str = None,
        n_results: int = 10
    ) -> list[SearchResult]:
        """
        Search for all chunks related to a specific control.
        
        If query is provided, results are ranked by relevance.
        Otherwise, returns all chunks for the control.
        """
        if query:
            return await self.search(
                query=query,
                filter_control_id=control_id,
                n_results=n_results
            )
        else:
            # Get all chunks for this control
            return await self.search(
                query=f"Control {control_id}",  # Use control ID as query
                filter_control_id=control_id,
                n_results=n_results,
                min_score=0.0  # Get all matches
            )
    
    async def search_by_evidence(
        self,
        evidence_id: str,
        query: str = None,
        n_results: int = 10
    ) -> list[SearchResult]:
        """
        Search for chunks related to specific evidence.
        """
        if query:
            return await self.search(
                query=query,
                filter_evidence_id=evidence_id,
                n_results=n_results
            )
        else:
            return await self.search(
                query=f"Evidence {evidence_id}",
                filter_evidence_id=evidence_id,
                n_results=n_results,
                min_score=0.0
            )
    
    async def hybrid_search(
        self,
        query: str,
        collection_name: str = "controls",
        n_results: int = 5,
        keyword_weight: float = 0.3,
        **filters
    ) -> list[SearchResult]:
        """
        Hybrid search combining semantic and keyword matching.
        
        Args:
            query: Search query
            collection_name: Collection to search
            n_results: Number of results
            keyword_weight: Weight for keyword matching (0-1)
            **filters: Additional filters
        
        Returns:
            Combined and re-ranked results
        """
        # Semantic search
        semantic_results = await self.search(
            query=query,
            collection_name=collection_name,
            n_results=n_results * 2,
            **filters
        )
        
        # Simple keyword matching on results
        query_terms = set(query.lower().split())
        
        for result in semantic_results:
            content_lower = result.content.lower()
            
            # Count keyword matches
            keyword_matches = sum(1 for term in query_terms if term in content_lower)
            keyword_score = keyword_matches / len(query_terms) if query_terms else 0
            
            # Combine scores
            result.score = (
                (1 - keyword_weight) * result.score +
                keyword_weight * keyword_score
            )
        
        # Re-sort and return
        semantic_results.sort(key=lambda x: x.score, reverse=True)
        return semantic_results[:n_results]
    
    def get_collection_stats(self, collection_name: str = "controls") -> dict:
        """Get statistics about a collection."""
        collection = self._get_or_create_collection(collection_name)
        count = collection.count()
        
        return {
            "collection_name": self._get_collection_name(collection_name),
            "document_count": count,
            "embedding_model": self.embedding_service.model_name,
            "embedding_dimensions": self.embedding_service.dimensions
        }
    
    def delete_collection(self, collection_name: str):
        """Delete a collection."""
        full_name = self._get_collection_name(collection_name)
        try:
            self.client.delete_collection(full_name)
            if full_name in self._collections:
                del self._collections[full_name]
        except ValueError:
            pass  # Collection doesn't exist
    
    def reset(self):
        """Delete all collections and reset the store."""
        for name in list(self._collections.keys()):
            try:
                self.client.delete_collection(name)
            except ValueError:
                pass
        self._collections.clear()
