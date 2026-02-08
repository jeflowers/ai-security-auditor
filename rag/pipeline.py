"""
RAG Pipeline for Compliance Checker

This is the main orchestration layer that:
1. Indexes compliance documents (controls, rubrics, evidence)
2. Retrieves relevant context for queries
3. Generates prompts for the LLM with anti-hallucination guardrails
4. Provides the ComplianceChecker agent with retrieved context

The pipeline enforces the core principle:
"If you can't prove it, you can't claim it"
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import yaml

from .document_processor import DocumentProcessor, DocumentChunk, DocumentType
from .embeddings import EmbeddingService, create_embedding_service
from .vector_store import ComplianceVectorStore, SearchResult


@dataclass
class RetrievalContext:
    """
    Context retrieved for a compliance query.
    
    Contains all relevant information the LLM needs to make
    an evidence-based assessment.
    """
    query: str
    control_id: Optional[str] = None
    evidence_id: Optional[str] = None
    
    # Retrieved chunks organized by type
    control_chunks: list[SearchResult] = field(default_factory=list)
    evidence_chunks: list[SearchResult] = field(default_factory=list)
    rubric_chunks: list[SearchResult] = field(default_factory=list)
    policy_chunks: list[SearchResult] = field(default_factory=list)
    
    # Metadata
    retrieved_at: datetime = field(default_factory=datetime.utcnow)
    total_chunks: int = 0
    
    def to_prompt_context(self) -> str:
        """
        Format context for LLM prompt.
        
        Structures the information to guide evidence-based reasoning.
        """
        sections = []
        
        # Control definition
        if self.control_chunks:
            sections.append("## CONTROL DEFINITION")
            for chunk in self.control_chunks:
                sections.append(f"[Source: {chunk.metadata.get('source_section', 'unknown')}]")
                sections.append(chunk.content)
                sections.append("")
        
        # Evidence information
        if self.evidence_chunks:
            sections.append("## EVIDENCE INFORMATION")
            for chunk in self.evidence_chunks:
                sections.append(f"[Evidence: {chunk.evidence_ids}]")
                sections.append(chunk.content)
                sections.append("")
        
        # Scoring rules (critical for anti-hallucination)
        if self.rubric_chunks:
            sections.append("## SCORING RULES (MUST FOLLOW)")
            for chunk in self.rubric_chunks:
                sections.append(chunk.content)
                sections.append("")
        
        # Policy context
        if self.policy_chunks:
            sections.append("## POLICY CONTEXT")
            for chunk in self.policy_chunks[:3]:  # Limit policy chunks
                sections.append(chunk.content)
                sections.append("")
        
        return "\n".join(sections)
    
    def get_evidence_ids(self) -> list[str]:
        """Get all evidence IDs mentioned in context."""
        ids = set()
        for chunk in self.evidence_chunks + self.control_chunks:
            ids.update(chunk.evidence_ids or [])
        return list(ids)
    
    def get_control_ids(self) -> list[str]:
        """Get all control IDs mentioned in context."""
        ids = set()
        for chunk in self.control_chunks + self.evidence_chunks:
            ids.update(chunk.control_ids or [])
        return list(ids)


class ComplianceRAGPipeline:
    """
    RAG Pipeline for compliance document retrieval.
    
    Handles:
    - Indexing compliance documents
    - Semantic search with filtering
    - Context assembly for LLM prompts
    - Anti-hallucination guardrails
    """
    
    def __init__(
        self,
        persist_dir: Path,
        embedding_provider: str = "openai",
        embedding_model: str = None,
        **embedding_kwargs
    ):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize embedding service
        cache_dir = self.persist_dir / "embedding_cache"
        self.embedding_service = create_embedding_service(
            provider=embedding_provider,
            model=embedding_model,
            cache_dir=cache_dir,
            **embedding_kwargs
        )
        
        # Initialize vector store
        vector_dir = self.persist_dir / "vector_store"
        self.vector_store = ComplianceVectorStore(
            embedding_service=self.embedding_service,
            persist_dir=vector_dir
        )
        
        # Document processor
        self.doc_processor = DocumentProcessor(
            chunk_size=1000,
            chunk_overlap=200
        )
        
        # Track indexed documents
        self.index_manifest_path = self.persist_dir / "index_manifest.json"
        self.index_manifest = self._load_index_manifest()
    
    def _load_index_manifest(self) -> dict:
        """Load manifest of indexed documents."""
        if self.index_manifest_path.exists():
            with open(self.index_manifest_path, 'r') as f:
                return json.load(f)
        return {"indexed_documents": {}, "last_updated": None}
    
    def _save_index_manifest(self):
        """Save index manifest."""
        self.index_manifest["last_updated"] = datetime.utcnow().isoformat()
        with open(self.index_manifest_path, 'w') as f:
            json.dump(self.index_manifest, f, indent=2)
    
    async def index_controls(
        self,
        controls_path: Path,
        framework: str = "SOC2",
        force_reindex: bool = False
    ) -> int:
        """
        Index SOC 2 control definitions.
        
        Returns number of chunks indexed.
        """
        doc_key = f"controls_{framework}"
        
        # Check if already indexed
        if not force_reindex and doc_key in self.index_manifest["indexed_documents"]:
            existing = self.index_manifest["indexed_documents"][doc_key]
            # Check if file has changed
            file_stat = controls_path.stat()
            if existing.get("mtime") == file_stat.st_mtime:
                return 0  # Already indexed
        
        # Process and index
        chunks = list(self.doc_processor.process_control_definitions(
            controls_path,
            framework=framework
        ))
        
        count = await self.vector_store.add_chunks(chunks, collection_name="controls")
        
        # Update manifest
        self.index_manifest["indexed_documents"][doc_key] = {
            "path": str(controls_path),
            "framework": framework,
            "chunks": count,
            "mtime": controls_path.stat().st_mtime,
            "indexed_at": datetime.utcnow().isoformat()
        }
        self._save_index_manifest()
        
        return count
    
    async def index_scoring_rubric(
        self,
        rubric_path: Path,
        framework: str = "SOC2",
        force_reindex: bool = False
    ) -> int:
        """
        Index scoring rubric with anti-hallucination rules.
        
        This is critical - the LLM must retrieve these rules
        to prevent hallucination in assessments.
        """
        doc_key = f"rubric_{framework}"
        
        if not force_reindex and doc_key in self.index_manifest["indexed_documents"]:
            existing = self.index_manifest["indexed_documents"][doc_key]
            file_stat = rubric_path.stat()
            if existing.get("mtime") == file_stat.st_mtime:
                return 0
        
        chunks = list(self.doc_processor.process_scoring_rubric(
            rubric_path,
            framework=framework
        ))
        
        count = await self.vector_store.add_chunks(chunks, collection_name="rubrics")
        
        self.index_manifest["indexed_documents"][doc_key] = {
            "path": str(rubric_path),
            "framework": framework,
            "chunks": count,
            "mtime": rubric_path.stat().st_mtime,
            "indexed_at": datetime.utcnow().isoformat()
        }
        self._save_index_manifest()
        
        return count
    
    async def index_evidence_manifest(
        self,
        manifest_path: Path,
        framework: str = "SOC2",
        force_reindex: bool = False
    ) -> int:
        """Index evidence manifest for retrieval."""
        doc_key = f"evidence_{framework}"
        
        if not force_reindex and doc_key in self.index_manifest["indexed_documents"]:
            existing = self.index_manifest["indexed_documents"][doc_key]
            file_stat = manifest_path.stat()
            if existing.get("mtime") == file_stat.st_mtime:
                return 0
        
        chunks = list(self.doc_processor.process_evidence_manifest(
            manifest_path,
            framework=framework
        ))
        
        count = await self.vector_store.add_chunks(chunks, collection_name="evidence")
        
        self.index_manifest["indexed_documents"][doc_key] = {
            "path": str(manifest_path),
            "framework": framework,
            "chunks": count,
            "mtime": manifest_path.stat().st_mtime,
            "indexed_at": datetime.utcnow().isoformat()
        }
        self._save_index_manifest()
        
        return count
    
    async def index_all(
        self,
        frameworks_dir: Path,
        evidence_dir: Path = None,
        framework: str = "SOC2"
    ) -> dict:
        """
        Index all compliance documents.
        
        Returns summary of indexing operation.
        """
        results = {}
        
        # Index controls
        controls_path = frameworks_dir / framework.lower() / "controls.yaml"
        if controls_path.exists():
            results["controls"] = await self.index_controls(controls_path, framework)
        
        # Index scoring rubric
        rubric_path = frameworks_dir / framework.lower() / "scoring_rubric.yaml"
        if rubric_path.exists():
            results["rubric"] = await self.index_scoring_rubric(rubric_path, framework)
        
        # Index evidence manifest if exists
        if evidence_dir:
            manifest_path = evidence_dir / "manifest.json"
            if manifest_path.exists():
                results["evidence"] = await self.index_evidence_manifest(manifest_path, framework)
        
        return results
    
    async def retrieve_for_control(
        self,
        control_id: str,
        query: str = None,
        include_rubric: bool = True,
        n_results: int = 5
    ) -> RetrievalContext:
        """
        Retrieve context for assessing a specific control.
        
        Args:
            control_id: SOC 2 control ID (e.g., "CC6.1")
            query: Optional specific query
            include_rubric: Whether to include scoring rules
            n_results: Number of results per category
        
        Returns:
            RetrievalContext with all relevant chunks
        """
        context = RetrievalContext(
            query=query or f"Assessment of {control_id}",
            control_id=control_id
        )
        
        # Get control definition
        control_results = await self.vector_store.search(
            query=f"Control {control_id} requirements evidence",
            collection_name="controls",
            filter_control_id=control_id,
            n_results=n_results
        )
        context.control_chunks = control_results
        
        # Get related evidence
        evidence_results = await self.vector_store.search(
            query=f"Evidence for {control_id}",
            collection_name="evidence",
            filter_control_id=control_id,
            n_results=n_results
        )
        context.evidence_chunks = evidence_results
        
        # Get scoring rules (always include for anti-hallucination)
        if include_rubric:
            rubric_results = await self.vector_store.search(
                query="evidence required claims assessment rules forbidden patterns",
                collection_name="rubrics",
                n_results=3
            )
            context.rubric_chunks = rubric_results
        
        context.total_chunks = (
            len(context.control_chunks) +
            len(context.evidence_chunks) +
            len(context.rubric_chunks)
        )
        
        return context
    
    async def retrieve_for_query(
        self,
        query: str,
        n_results: int = 5,
        include_rubric: bool = True
    ) -> RetrievalContext:
        """
        Retrieve context for a general compliance query.
        """
        context = RetrievalContext(query=query)
        
        # Search controls
        context.control_chunks = await self.vector_store.hybrid_search(
            query=query,
            collection_name="controls",
            n_results=n_results
        )
        
        # Search evidence
        context.evidence_chunks = await self.vector_store.search(
            query=query,
            collection_name="evidence",
            n_results=n_results
        )
        
        # Include rubric rules
        if include_rubric:
            context.rubric_chunks = await self.vector_store.search(
                query="assessment rules evidence requirements",
                collection_name="rubrics",
                n_results=3
            )
        
        context.total_chunks = (
            len(context.control_chunks) +
            len(context.evidence_chunks) +
            len(context.rubric_chunks)
        )
        
        return context
    
    async def retrieve_anti_hallucination_rules(self) -> list[SearchResult]:
        """
        Retrieve all anti-hallucination rules.
        
        These should be included in every assessment prompt.
        """
        return await self.vector_store.search(
            query="forbidden patterns required evidence claims hallucination rules",
            collection_name="rubrics",
            n_results=10,
            min_score=0.0
        )
    
    def build_assessment_prompt(
        self,
        control_id: str,
        context: RetrievalContext,
        evidence_summary: str = None
    ) -> str:
        """
        Build a prompt for LLM assessment with anti-hallucination guardrails.
        
        This prompt structure ensures the LLM follows evidence-based reasoning.
        """
        prompt_parts = [
            "# COMPLIANCE ASSESSMENT TASK",
            "",
            f"You are assessing control {control_id} for SOC 2 compliance.",
            "",
            "## CRITICAL RULES - YOU MUST FOLLOW THESE",
            "1. Every claim MUST cite specific evidence by ID",
            "2. If evidence is missing, state 'EVIDENCE_GAP' - do NOT assume compliance",
            "3. Use ONLY these status values: PASS, FAIL, INSUFFICIENT_EVIDENCE, EVIDENCE_GAP, CONFLICTING_EVIDENCE, NEEDS_MANUAL_REVIEW",
            "4. NEVER use words like 'likely', 'probably', 'seems to'",
            "5. NEVER make inferences - only state what evidence shows",
            "",
            "## RETRIEVED CONTEXT",
            context.to_prompt_context(),
            "",
        ]
        
        if evidence_summary:
            prompt_parts.extend([
                "## COLLECTED EVIDENCE SUMMARY",
                evidence_summary,
                ""
            ])
        
        prompt_parts.extend([
            "## YOUR TASK",
            f"Assess control {control_id} based ONLY on the evidence provided.",
            "",
            "Respond with:",
            "1. STATUS: One of the valid status values",
            "2. EVIDENCE_REFS: List of evidence IDs that support your assessment",
            "3. GAPS: List any evidence that was required but not provided",
            "4. REASONING: Explanation citing specific evidence",
            "5. FINDINGS: Any specific compliance findings",
            "",
            "Remember: If you cannot prove compliance with evidence, the status MUST be EVIDENCE_GAP or INSUFFICIENT_EVIDENCE.",
        ])
        
        return "\n".join(prompt_parts)
    
    def get_stats(self) -> dict:
        """Get pipeline statistics."""
        stats = {
            "persist_dir": str(self.persist_dir),
            "embedding_model": self.embedding_service.model_name,
            "embedding_dimensions": self.embedding_service.dimensions,
            "indexed_documents": len(self.index_manifest.get("indexed_documents", {})),
            "last_updated": self.index_manifest.get("last_updated"),
            "collections": {}
        }
        
        for name in ["controls", "evidence", "rubrics", "policies"]:
            try:
                stats["collections"][name] = self.vector_store.get_collection_stats(name)
            except Exception:
                stats["collections"][name] = {"status": "not_created"}
        
        return stats


async def create_pipeline(
    base_dir: Path,
    embedding_provider: str = "openai",
    embedding_model: str = None,
    api_key: str = None
) -> ComplianceRAGPipeline:
    """
    Factory function to create and initialize a RAG pipeline.
    
    Args:
        base_dir: Base directory for the project
        embedding_provider: "openai" or "local"
        embedding_model: Model name
        api_key: API key for OpenAI (if using)
    
    Returns:
        Initialized ComplianceRAGPipeline
    """
    persist_dir = base_dir / "rag_data"
    
    kwargs = {}
    if api_key:
        kwargs["api_key"] = api_key
    
    pipeline = ComplianceRAGPipeline(
        persist_dir=persist_dir,
        embedding_provider=embedding_provider,
        embedding_model=embedding_model,
        **kwargs
    )
    
    # Index default documents
    frameworks_dir = base_dir / "frameworks"
    evidence_dir = base_dir / "evidence"
    
    if frameworks_dir.exists():
        await pipeline.index_all(
            frameworks_dir=frameworks_dir,
            evidence_dir=evidence_dir if evidence_dir.exists() else None
        )
    
    return pipeline
