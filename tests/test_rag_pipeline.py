"""
Tests for RAG Pipeline Components

Tests cover:
- Document processing and chunking
- Embedding generation
- Vector store operations
- Full pipeline integration
"""

import pytest
import asyncio
from pathlib import Path
from datetime import datetime
import tempfile
import json
import yaml

# Import components
from rag.document_processor import (
    DocumentProcessor,
    DocumentChunk,
    DocumentType
)
from rag.vector_store import ComplianceVectorStore, SearchResult
from rag.pipeline import ComplianceRAGPipeline, RetrievalContext


class TestDocumentProcessor:
    """Tests for document chunking and processing."""
    
    @pytest.fixture
    def processor(self):
        return DocumentProcessor(
            chunk_size=500,
            chunk_overlap=100,
            min_chunk_size=50
        )
    
    @pytest.fixture
    def sample_controls_yaml(self, tmp_path):
        """Create a sample controls YAML file."""
        controls = {
            "metadata": {
                "framework": "SOC 2",
                "version": "2017"
            },
            "controls": {
                "CC6.1": {
                    "title": "Logical Access Security",
                    "description": "The entity implements logical access security.",
                    "category": "CC",
                    "subcategory": "Logical Access",
                    "evidence_plan": {
                        "required_evidence": [
                            {
                                "evidence_id": "CC6.1-E1",
                                "name": "Access Control Policy",
                                "type": "policy_document",
                                "description": "Documented access control policy",
                                "validation_rules": ["document_exists", "approval_present"]
                            },
                            {
                                "evidence_id": "CC6.1-E2",
                                "name": "User Access List",
                                "type": "system_extract",
                                "description": "Current user access list"
                            }
                        ]
                    },
                    "scoring_rubric": {
                        "score_thresholds": {
                            "pass": 0.80,
                            "pass_with_exceptions": 0.60,
                            "fail": 0.59
                        }
                    }
                },
                "CC6.2": {
                    "title": "User Registration",
                    "description": "User registration and authorization.",
                    "category": "CC",
                    "subcategory": "Logical Access",
                    "evidence_plan": {
                        "required_evidence": [
                            {
                                "evidence_id": "CC6.2-E1",
                                "name": "Provisioning Procedure",
                                "type": "policy_document",
                                "description": "User provisioning procedures"
                            }
                        ]
                    },
                    "scoring_rubric": {
                        "score_thresholds": {
                            "pass": 0.85,
                            "pass_with_exceptions": 0.70,
                            "fail": 0.69
                        }
                    }
                }
            }
        }
        
        yaml_path = tmp_path / "controls.yaml"
        with open(yaml_path, 'w') as f:
            yaml.dump(controls, f)
        
        return yaml_path
    
    def test_processor_initialization(self, processor):
        """Test processor initializes with correct parameters."""
        assert processor.chunk_size == 500
        assert processor.chunk_overlap == 100
        assert processor.min_chunk_size == 50
    
    def test_extract_control_ids(self, processor):
        """Test control ID extraction from text."""
        text = "This relates to CC6.1 and CC7.2 controls, as well as A1.1"
        control_ids = processor._extract_control_ids(text)
        
        assert "CC6.1" in control_ids
        assert "CC7.2" in control_ids
        assert "A1.1" in control_ids
    
    def test_extract_evidence_ids(self, processor):
        """Test evidence ID extraction from text."""
        text = "Evidence CC6.1-E1 and CC6.1-E2 were collected"
        evidence_ids = processor._extract_evidence_ids(text)
        
        assert "CC6.1-E1" in evidence_ids
        assert "CC6.1-E2" in evidence_ids
    
    def test_process_control_definitions(self, processor, sample_controls_yaml):
        """Test processing control definitions YAML."""
        chunks = list(processor.process_control_definitions(sample_controls_yaml))
        
        # Should have 2 chunks (one per control)
        assert len(chunks) == 2
        
        # Check first chunk
        cc61_chunk = next(c for c in chunks if "CC6.1" in c.control_ids)
        assert cc61_chunk.document_type == DocumentType.CONTROL_DEFINITION
        assert cc61_chunk.framework == "SOC2"
        assert "Logical Access Security" in cc61_chunk.content
        assert "CC6.1-E1" in cc61_chunk.evidence_ids
        assert "CC6.1-E2" in cc61_chunk.evidence_ids
    
    def test_chunk_has_required_fields(self, processor, sample_controls_yaml):
        """Test that chunks have all required fields."""
        chunks = list(processor.process_control_definitions(sample_controls_yaml))
        
        for chunk in chunks:
            assert chunk.chunk_id is not None
            assert chunk.document_id is not None
            assert chunk.content is not None
            assert chunk.content_hash is not None
            assert chunk.document_type is not None
            assert chunk.framework is not None
    
    def test_process_text_document(self, processor):
        """Test processing generic text documents."""
        content = """
        This is the first paragraph about CC6.1 compliance.
        It discusses access control requirements.
        
        This is the second paragraph about evidence CC6.1-E1.
        It explains what documentation is needed.
        
        This is the third paragraph with more details.
        """
        
        chunks = list(processor.process_text_document(
            content=content,
            document_id="test_doc",
            document_type=DocumentType.POLICY_DOCUMENT,
            framework="SOC2"
        ))
        
        assert len(chunks) >= 1
        # Should extract control and evidence IDs
        all_control_ids = []
        all_evidence_ids = []
        for chunk in chunks:
            all_control_ids.extend(chunk.control_ids)
            all_evidence_ids.extend(chunk.evidence_ids)
        
        assert "CC6.1" in all_control_ids
        assert "CC6.1-E1" in all_evidence_ids


class TestDocumentChunk:
    """Tests for DocumentChunk dataclass."""
    
    def test_chunk_creation(self):
        """Test creating a document chunk."""
        chunk = DocumentChunk(
            chunk_id="test_001",
            document_id="doc_001",
            sequence=0,
            content="Test content",
            content_hash="abc123",
            document_type=DocumentType.CONTROL_DEFINITION,
            framework="SOC2",
            control_ids=["CC6.1"],
            evidence_ids=["CC6.1-E1"]
        )
        
        assert chunk.chunk_id == "test_001"
        assert chunk.control_ids == ["CC6.1"]
    
    def test_chunk_to_dict(self):
        """Test converting chunk to dictionary."""
        chunk = DocumentChunk(
            chunk_id="test_001",
            document_id="doc_001",
            sequence=0,
            content="Test content",
            content_hash="abc123",
            document_type=DocumentType.CONTROL_DEFINITION,
            framework="SOC2"
        )
        
        data = chunk.to_dict()
        
        assert data["chunk_id"] == "test_001"
        assert data["document_type"] == "control_definition"
        assert "created_at" in data


class TestMockEmbeddingService:
    """Tests using mock embeddings (no API calls)."""
    
    @pytest.fixture
    def mock_embedding_service(self):
        """Create a mock embedding service for testing."""
        class MockEmbeddingService:
            @property
            def model_name(self):
                return "mock-model"
            
            @property
            def dimensions(self):
                return 384
            
            async def embed_text(self, text: str) -> list[float]:
                # Generate deterministic mock embedding based on text hash
                import hashlib
                hash_val = int(hashlib.md5(text.encode()).hexdigest(), 16)
                # Create a simple embedding
                embedding = [(hash_val >> i) % 1000 / 1000 for i in range(384)]
                return embedding
            
            async def embed_batch(self, texts: list[str]) -> list[list[float]]:
                return [await self.embed_text(t) for t in texts]
        
        return MockEmbeddingService()
    
    @pytest.mark.asyncio
    async def test_mock_embed_text(self, mock_embedding_service):
        """Test mock embedding generation."""
        embedding = await mock_embedding_service.embed_text("test text")
        
        assert len(embedding) == 384
        assert all(isinstance(v, float) for v in embedding)
    
    @pytest.mark.asyncio
    async def test_mock_embed_batch(self, mock_embedding_service):
        """Test mock batch embedding."""
        embeddings = await mock_embedding_service.embed_batch(["text 1", "text 2"])
        
        assert len(embeddings) == 2
        assert len(embeddings[0]) == 384


class TestVectorStore:
    """Tests for vector store operations."""
    
    @pytest.fixture
    def mock_embedding_service(self):
        """Create mock embedding service."""
        class MockEmbeddingService:
            @property
            def model_name(self):
                return "mock-model"
            
            @property
            def dimensions(self):
                return 384
            
            async def embed_text(self, text: str) -> list[float]:
                import hashlib
                hash_val = int(hashlib.md5(text.encode()).hexdigest(), 16)
                return [(hash_val >> i) % 1000 / 1000 for i in range(384)]
            
            async def embed_batch(self, texts: list[str]) -> list[list[float]]:
                return [await self.embed_text(t) for t in texts]
        
        return MockEmbeddingService()
    
    @pytest.fixture
    def vector_store(self, mock_embedding_service, tmp_path):
        """Create vector store with temp directory."""
        return ComplianceVectorStore(
            embedding_service=mock_embedding_service,
            persist_dir=tmp_path / "vector_store"
        )
    
    @pytest.fixture
    def sample_chunks(self):
        """Create sample chunks for testing."""
        return [
            DocumentChunk(
                chunk_id="chunk_001",
                document_id="doc_001",
                sequence=0,
                content="Access control policy for CC6.1 compliance",
                content_hash="hash1",
                document_type=DocumentType.CONTROL_DEFINITION,
                framework="SOC2",
                control_ids=["CC6.1"],
                evidence_ids=["CC6.1-E1"]
            ),
            DocumentChunk(
                chunk_id="chunk_002",
                document_id="doc_001",
                sequence=1,
                content="User registration process for CC6.2",
                content_hash="hash2",
                document_type=DocumentType.CONTROL_DEFINITION,
                framework="SOC2",
                control_ids=["CC6.2"],
                evidence_ids=["CC6.2-E1"]
            ),
            DocumentChunk(
                chunk_id="chunk_003",
                document_id="doc_002",
                sequence=0,
                content="Evidence requirements for logical access security",
                content_hash="hash3",
                document_type=DocumentType.REGULATORY_FRAMEWORK,
                framework="SOC2",
                control_ids=["CC6.1", "CC6.2"],
                evidence_ids=[]
            )
        ]
    
    @pytest.mark.asyncio
    async def test_add_chunks(self, vector_store, sample_chunks):
        """Test adding chunks to vector store."""
        count = await vector_store.add_chunks(sample_chunks, collection_name="controls")
        
        assert count == 3
    
    @pytest.mark.asyncio
    async def test_search_basic(self, vector_store, sample_chunks):
        """Test basic search functionality."""
        await vector_store.add_chunks(sample_chunks, collection_name="controls")
        
        results = await vector_store.search(
            query="access control policy",
            collection_name="controls",
            n_results=5
        )
        
        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)
    
    @pytest.mark.asyncio
    async def test_search_with_control_filter(self, vector_store, sample_chunks):
        """Test search with control ID filter."""
        await vector_store.add_chunks(sample_chunks, collection_name="controls")
        
        results = await vector_store.search(
            query="compliance requirements",
            collection_name="controls",
            filter_control_id="CC6.1",
            n_results=5
        )
        
        # All results should have CC6.1 in control_ids
        for result in results:
            assert "CC6.1" in result.control_ids
    
    @pytest.mark.asyncio
    async def test_collection_stats(self, vector_store, sample_chunks):
        """Test getting collection statistics."""
        await vector_store.add_chunks(sample_chunks, collection_name="controls")
        
        stats = vector_store.get_collection_stats("controls")
        
        assert stats["document_count"] == 3
        assert stats["embedding_model"] == "mock-model"


class TestRetrievalContext:
    """Tests for RetrievalContext."""
    
    def test_context_creation(self):
        """Test creating retrieval context."""
        context = RetrievalContext(
            query="Test query",
            control_id="CC6.1"
        )
        
        assert context.query == "Test query"
        assert context.control_id == "CC6.1"
        assert context.total_chunks == 0
    
    def test_context_to_prompt(self):
        """Test converting context to prompt format."""
        context = RetrievalContext(
            query="Test query",
            control_id="CC6.1"
        )
        
        # Add mock search results
        context.control_chunks = [
            SearchResult(
                chunk_id="c1",
                content="Control definition content",
                score=0.9,
                metadata={"source_section": "CC6.1"}
            )
        ]
        
        prompt = context.to_prompt_context()
        
        assert "CONTROL DEFINITION" in prompt
        assert "Control definition content" in prompt
    
    def test_get_evidence_ids(self):
        """Test extracting evidence IDs from context."""
        context = RetrievalContext(query="test")
        context.evidence_chunks = [
            SearchResult(
                chunk_id="e1",
                content="Evidence",
                score=0.9,
                metadata={"evidence_ids": ["CC6.1-E1", "CC6.1-E2"]}
            )
        ]
        
        evidence_ids = context.get_evidence_ids()
        
        assert "CC6.1-E1" in evidence_ids
        assert "CC6.1-E2" in evidence_ids


class TestPipelineIntegration:
    """Integration tests for the full RAG pipeline."""
    
    @pytest.fixture
    def sample_framework_dir(self, tmp_path):
        """Create sample framework directory with files."""
        soc2_dir = tmp_path / "frameworks" / "soc2"
        soc2_dir.mkdir(parents=True)
        
        # Create controls.yaml
        controls = {
            "metadata": {"framework": "SOC 2"},
            "controls": {
                "CC6.1": {
                    "title": "Logical Access Security",
                    "description": "Access control implementation",
                    "category": "CC",
                    "evidence_plan": {
                        "required_evidence": [
                            {"evidence_id": "CC6.1-E1", "name": "Policy", "type": "policy_document"}
                        ]
                    },
                    "scoring_rubric": {"score_thresholds": {"pass": 0.80}}
                }
            }
        }
        with open(soc2_dir / "controls.yaml", 'w') as f:
            yaml.dump(controls, f)
        
        # Create scoring_rubric.yaml
        rubric = {
            "metadata": {"version": "1.0"},
            "fundamental_rules": {
                "rule_1_evidence_required": {
                    "name": "Evidence Required",
                    "description": "Every claim must cite evidence",
                    "forbidden_patterns": ["likely compliant"],
                    "required_patterns": ["Evidence [ID] shows"]
                }
            },
            "prohibited_behaviors": [
                {"id": "PB001", "name": "Assuming compliance", "severity": "critical"}
            ]
        }
        with open(soc2_dir / "scoring_rubric.yaml", 'w') as f:
            yaml.dump(rubric, f)
        
        return tmp_path
    
    @pytest.mark.asyncio
    async def test_pipeline_index_all(self, sample_framework_dir, tmp_path):
        """Test indexing all framework documents."""
        # Create mock embedding service
        class MockEmbedding:
            @property
            def model_name(self):
                return "mock"
            
            @property
            def dimensions(self):
                return 384
            
            async def embed_text(self, text):
                import hashlib
                h = int(hashlib.md5(text.encode()).hexdigest(), 16)
                return [(h >> i) % 1000 / 1000 for i in range(384)]
            
            async def embed_batch(self, texts):
                return [await self.embed_text(t) for t in texts]
        
        # Create pipeline with mock embeddings
        from rag.vector_store import ComplianceVectorStore
        from rag.pipeline import ComplianceRAGPipeline
        
        pipeline = ComplianceRAGPipeline.__new__(ComplianceRAGPipeline)
        pipeline.persist_dir = tmp_path / "rag_data"
        pipeline.persist_dir.mkdir(parents=True)
        pipeline.embedding_service = MockEmbedding()
        pipeline.vector_store = ComplianceVectorStore(
            embedding_service=pipeline.embedding_service,
            persist_dir=pipeline.persist_dir / "vector_store"
        )
        pipeline.doc_processor = DocumentProcessor()
        pipeline.index_manifest_path = pipeline.persist_dir / "index_manifest.json"
        pipeline.index_manifest = {"indexed_documents": {}, "last_updated": None}
        
        # Index documents
        results = await pipeline.index_all(
            frameworks_dir=sample_framework_dir / "frameworks"
        )
        
        assert "controls" in results
        assert results["controls"] > 0


class TestAntiHallucination:
    """Tests ensuring anti-hallucination rules are properly indexed."""
    
    @pytest.fixture
    def processor(self):
        return DocumentProcessor()
    
    @pytest.fixture
    def rubric_yaml(self, tmp_path):
        """Create scoring rubric with anti-hallucination rules."""
        rubric = {
            "fundamental_rules": {
                "rule_1_evidence_required": {
                    "name": "Evidence Required for Every Claim",
                    "description": "Every compliance claim MUST cite specific evidence",
                    "forbidden_patterns": [
                        "Based on general practices, likely compliant",
                        "Industry standards suggest compliance",
                        "It's reasonable to assume"
                    ],
                    "required_patterns": [
                        "Evidence artifact [ID] shows...",
                        "According to evidence [ID] dated [DATE]..."
                    ],
                    "examples": {
                        "wrong": "Based on the organization's size, they likely have a policy",
                        "right": "Evidence [CC6.1-E1-001.pdf] dated 2024-03-15 shows approved policy"
                    }
                }
            },
            "prohibited_behaviors": [
                {
                    "id": "PB001",
                    "name": "Assuming compliance without evidence",
                    "description": "Making positive compliance statements without evidence",
                    "severity": "critical"
                },
                {
                    "id": "PB006",
                    "name": "Using weasel words",
                    "description": "Using uncertain language",
                    "severity": "high",
                    "forbidden_words": ["likely", "probably", "seems to", "appears to"]
                }
            ]
        }
        
        path = tmp_path / "scoring_rubric.yaml"
        with open(path, 'w') as f:
            yaml.dump(rubric, f)
        
        return path
    
    def test_rubric_chunks_contain_forbidden_patterns(self, processor, rubric_yaml):
        """Test that rubric chunks contain forbidden patterns."""
        chunks = list(processor.process_scoring_rubric(rubric_yaml))
        
        # Should have chunks for rules and behaviors
        assert len(chunks) >= 2
        
        # Check that forbidden patterns are in chunks
        all_content = " ".join(c.content for c in chunks)
        assert "likely compliant" in all_content.lower()
        assert "forbidden" in all_content.lower()
    
    def test_rubric_chunks_contain_examples(self, processor, rubric_yaml):
        """Test that rubric chunks contain examples."""
        chunks = list(processor.process_scoring_rubric(rubric_yaml))
        
        all_content = " ".join(c.content for c in chunks)
        assert "wrong" in all_content.lower()
        assert "right" in all_content.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
