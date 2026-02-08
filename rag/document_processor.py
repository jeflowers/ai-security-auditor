"""
Document Processor for RAG Pipeline

Handles chunking and preprocessing of compliance documents:
- SOC 2 control definitions
- Policy documents
- Evidence artifacts
- Regulatory frameworks

Chunking strategy optimized for compliance content:
- Preserve control boundaries
- Maintain evidence references
- Keep regulatory citations intact
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator
import json
import yaml


class DocumentType(Enum):
    """Types of documents in the compliance domain."""
    CONTROL_DEFINITION = "control_definition"
    POLICY_DOCUMENT = "policy_document"
    EVIDENCE_ARTIFACT = "evidence_artifact"
    REGULATORY_FRAMEWORK = "regulatory_framework"
    AUDIT_REPORT = "audit_report"
    PROCEDURE_DOCUMENT = "procedure_document"


@dataclass
class DocumentChunk:
    """
    A chunk of a document with metadata for retrieval.
    
    Each chunk maintains provenance back to its source document
    and includes metadata for filtering and ranking.
    """
    # Identity
    chunk_id: str
    document_id: str
    sequence: int  # Position in original document
    
    # Content
    content: str
    content_hash: str
    
    # Metadata for filtering
    document_type: DocumentType
    framework: str  # e.g., "SOC2", "HIPAA"
    control_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    
    # Source tracking
    source_file: str = ""
    source_section: str = ""
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for vector store."""
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "sequence": self.sequence,
            "content": self.content,
            "content_hash": self.content_hash,
            "document_type": self.document_type.value,
            "framework": self.framework,
            "control_ids": self.control_ids,
            "evidence_ids": self.evidence_ids,
            "source_file": self.source_file,
            "source_section": self.source_section,
            "created_at": self.created_at.isoformat(),
            **self.metadata
        }


class DocumentProcessor:
    """
    Process documents into chunks optimized for compliance RAG.
    
    Chunking strategies:
    - Control-aware: Keep control definitions intact
    - Evidence-preserving: Maintain evidence ID references
    - Semantic boundaries: Split on meaningful boundaries
    """
    
    def __init__(
        self,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
        min_chunk_size: int = 100
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.min_chunk_size = min_chunk_size
    
    def _generate_chunk_id(self, document_id: str, sequence: int) -> str:
        """Generate unique chunk ID."""
        return f"{document_id}_chunk_{sequence:04d}"
    
    def _compute_hash(self, content: str) -> str:
        """Compute content hash for deduplication."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _extract_control_ids(self, text: str) -> list[str]:
        """Extract SOC 2 control IDs from text."""
        # Pattern matches CC6.1, CC7.2, A1.1, etc.
        pattern = r'\b(CC[0-9]+\.[0-9]+|A[0-9]+\.[0-9]+|PI[0-9]+\.[0-9]+|C[0-9]+\.[0-9]+|P[0-9]+\.[0-9]+)\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return list(set(match.upper() for match in matches))
    
    def _extract_evidence_ids(self, text: str) -> list[str]:
        """Extract evidence IDs from text."""
        # Pattern matches CC6.1-E1, CC7.2-E3, etc.
        pattern = r'\b(CC[0-9]+\.[0-9]+-E[0-9]+|[A-Z]+[0-9]+\.[0-9]+-E[0-9]+)\b'
        matches = re.findall(pattern, text, re.IGNORECASE)
        return list(set(match.upper() for match in matches))
    
    def process_control_definitions(
        self,
        controls_path: Path,
        framework: str = "SOC2"
    ) -> Iterator[DocumentChunk]:
        """
        Process SOC 2 control definitions YAML into chunks.
        
        Each control becomes its own chunk to preserve semantic boundaries.
        """
        with open(controls_path, 'r') as f:
            data = yaml.safe_load(f)
        
        document_id = f"{framework}_controls"
        sequence = 0
        
        # Process each control as a separate chunk
        for control_id, control in data.get("controls", {}).items():
            # Build comprehensive control text
            content_parts = [
                f"Control: {control_id}",
                f"Title: {control.get('title', '')}",
                f"Category: {control.get('category', '')}",
                f"Description: {control.get('description', '')}",
            ]
            
            # Add evidence requirements
            evidence_plan = control.get("evidence_plan", {})
            required_evidence = evidence_plan.get("required_evidence", [])
            
            if required_evidence:
                content_parts.append("\nRequired Evidence:")
                for ev in required_evidence:
                    content_parts.append(f"  - {ev.get('evidence_id')}: {ev.get('name')}")
                    content_parts.append(f"    Type: {ev.get('type')}")
                    content_parts.append(f"    Description: {ev.get('description', '')}")
                    
                    # Add validation rules
                    rules = ev.get('validation_rules', [])
                    if rules:
                        content_parts.append(f"    Validation Rules: {', '.join(rules)}")
            
            # Add scoring information
            rubric = control.get("scoring_rubric", {})
            thresholds = rubric.get("score_thresholds", {})
            if thresholds:
                content_parts.append(f"\nScoring Thresholds:")
                content_parts.append(f"  Pass: {thresholds.get('pass', 0.80)}")
                content_parts.append(f"  Pass with Exceptions: {thresholds.get('pass_with_exceptions', 0.60)}")
            
            content = "\n".join(content_parts)
            
            # Extract referenced IDs
            evidence_ids = [ev.get("evidence_id") for ev in required_evidence if ev.get("evidence_id")]
            
            yield DocumentChunk(
                chunk_id=self._generate_chunk_id(document_id, sequence),
                document_id=document_id,
                sequence=sequence,
                content=content,
                content_hash=self._compute_hash(content),
                document_type=DocumentType.CONTROL_DEFINITION,
                framework=framework,
                control_ids=[control_id],
                evidence_ids=evidence_ids,
                source_file=str(controls_path),
                source_section=control_id,
                metadata={
                    "control_title": control.get("title", ""),
                    "control_category": control.get("category", ""),
                    "subcategory": control.get("subcategory", "")
                }
            )
            sequence += 1
    
    def process_scoring_rubric(
        self,
        rubric_path: Path,
        framework: str = "SOC2"
    ) -> Iterator[DocumentChunk]:
        """
        Process scoring rubric into searchable chunks.
        
        Each fundamental rule and prohibited behavior becomes a chunk.
        """
        with open(rubric_path, 'r') as f:
            data = yaml.safe_load(f)
        
        document_id = f"{framework}_scoring_rubric"
        sequence = 0
        
        # Process fundamental rules
        for rule_key, rule in data.get("fundamental_rules", {}).items():
            content_parts = [
                f"Rule: {rule.get('name', rule_key)}",
                f"Description: {rule.get('description', '')}",
            ]
            
            # Add forbidden patterns
            forbidden = rule.get("forbidden_patterns", [])
            if forbidden:
                content_parts.append("\nForbidden Patterns (DO NOT USE):")
                for pattern in forbidden:
                    content_parts.append(f"  ❌ {pattern}")
            
            # Add required patterns
            required = rule.get("required_patterns", [])
            if required:
                content_parts.append("\nRequired Patterns (USE THESE):")
                for pattern in required:
                    content_parts.append(f"  ✓ {pattern}")
            
            # Add examples
            examples = rule.get("examples", {})
            if examples:
                content_parts.append("\nExamples:")
                if "wrong" in examples:
                    content_parts.append(f"  Wrong: {examples['wrong']}")
                if "right" in examples:
                    content_parts.append(f"  Right: {examples['right']}")
            
            content = "\n".join(content_parts)
            
            yield DocumentChunk(
                chunk_id=self._generate_chunk_id(document_id, sequence),
                document_id=document_id,
                sequence=sequence,
                content=content,
                content_hash=self._compute_hash(content),
                document_type=DocumentType.REGULATORY_FRAMEWORK,
                framework=framework,
                source_file=str(rubric_path),
                source_section=rule_key,
                metadata={
                    "rule_name": rule.get("name", ""),
                    "rule_type": "fundamental_rule"
                }
            )
            sequence += 1
        
        # Process prohibited behaviors
        for behavior in data.get("prohibited_behaviors", []):
            content = f"""Prohibited Behavior: {behavior.get('name', '')}
ID: {behavior.get('id', '')}
Severity: {behavior.get('severity', '')}
Description: {behavior.get('description', '')}"""
            
            if "example_wrong" in behavior:
                content += f"\n\nExample of Wrong Behavior:\n  {behavior['example_wrong']}"
            
            yield DocumentChunk(
                chunk_id=self._generate_chunk_id(document_id, sequence),
                document_id=document_id,
                sequence=sequence,
                content=content,
                content_hash=self._compute_hash(content),
                document_type=DocumentType.REGULATORY_FRAMEWORK,
                framework=framework,
                source_file=str(rubric_path),
                source_section=behavior.get("id", ""),
                metadata={
                    "behavior_id": behavior.get("id", ""),
                    "severity": behavior.get("severity", ""),
                    "rule_type": "prohibited_behavior"
                }
            )
            sequence += 1
    
    def process_text_document(
        self,
        content: str,
        document_id: str,
        document_type: DocumentType,
        framework: str,
        source_file: str = "",
        metadata: dict = None
    ) -> Iterator[DocumentChunk]:
        """
        Process a text document into overlapping chunks.
        
        Uses semantic-aware splitting that respects:
        - Paragraph boundaries
        - Section headers
        - List structures
        """
        metadata = metadata or {}
        
        # Split on paragraph boundaries first
        paragraphs = re.split(r'\n\s*\n', content)
        
        current_chunk = ""
        sequence = 0
        
        for para in paragraphs:
            para = para.strip()
            if not para:
                continue
            
            # If adding this paragraph exceeds chunk size, yield current chunk
            if len(current_chunk) + len(para) > self.chunk_size and current_chunk:
                if len(current_chunk) >= self.min_chunk_size:
                    yield DocumentChunk(
                        chunk_id=self._generate_chunk_id(document_id, sequence),
                        document_id=document_id,
                        sequence=sequence,
                        content=current_chunk.strip(),
                        content_hash=self._compute_hash(current_chunk),
                        document_type=document_type,
                        framework=framework,
                        control_ids=self._extract_control_ids(current_chunk),
                        evidence_ids=self._extract_evidence_ids(current_chunk),
                        source_file=source_file,
                        metadata=metadata
                    )
                    sequence += 1
                
                # Keep overlap from previous chunk
                overlap_start = max(0, len(current_chunk) - self.chunk_overlap)
                current_chunk = current_chunk[overlap_start:] + "\n\n" + para
            else:
                current_chunk = current_chunk + "\n\n" + para if current_chunk else para
        
        # Yield final chunk
        if current_chunk and len(current_chunk) >= self.min_chunk_size:
            yield DocumentChunk(
                chunk_id=self._generate_chunk_id(document_id, sequence),
                document_id=document_id,
                sequence=sequence,
                content=current_chunk.strip(),
                content_hash=self._compute_hash(current_chunk),
                document_type=document_type,
                framework=framework,
                control_ids=self._extract_control_ids(current_chunk),
                evidence_ids=self._extract_evidence_ids(current_chunk),
                source_file=source_file,
                metadata=metadata
            )
    
    def process_evidence_manifest(
        self,
        manifest_path: Path,
        framework: str = "SOC2"
    ) -> Iterator[DocumentChunk]:
        """
        Process evidence manifest into searchable chunks.
        
        Creates chunks that link evidence IDs to their metadata.
        """
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        document_id = "evidence_manifest"
        sequence = 0
        
        for evidence_id, entry in manifest.get("evidence", {}).items():
            content = f"""Evidence: {evidence_id}
Type: {entry.get('evidence_type', '')}
Path: {entry.get('path', '')}
Collected: {entry.get('collected_at', '')}
Controls: {', '.join(entry.get('control_ids', []))}
Content Hash: {entry.get('content_hash', '')}"""
            
            yield DocumentChunk(
                chunk_id=self._generate_chunk_id(document_id, sequence),
                document_id=document_id,
                sequence=sequence,
                content=content,
                content_hash=self._compute_hash(content),
                document_type=DocumentType.EVIDENCE_ARTIFACT,
                framework=framework,
                control_ids=entry.get("control_ids", []),
                evidence_ids=[evidence_id],
                source_file=str(manifest_path),
                metadata={
                    "evidence_type": entry.get("evidence_type", ""),
                    "collected_at": entry.get("collected_at", "")
                }
            )
            sequence += 1
