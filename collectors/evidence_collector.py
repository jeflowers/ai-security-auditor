"""
Evidence Collection Framework with Provenance Tracking

This module provides the foundation for collecting, storing, and tracking
evidence for compliance audits. Inspired by EMC's emcgrab pattern.

Core Principle: "If you can't prove it, you can't claim it"
Every piece of evidence must have complete provenance metadata.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import uuid


class EvidenceType(Enum):
    """Types of evidence that can be collected."""
    POLICY_DOCUMENT = "policy_document"
    SYSTEM_EXTRACT = "system_extract"
    REVIEW_RECORD = "review_record"
    CONFIG_SNAPSHOT = "config_snapshot"
    SAMPLE_RECORDS = "sample_records"
    SCAN_OUTPUT = "scan_output"
    LOG_EXTRACT = "log_extract"
    CROSS_REFERENCE = "cross_reference"
    TEST_RECORD = "test_record"


class SourceType(Enum):
    """How the evidence was obtained."""
    API_EXTRACT = "api_extract"
    MANUAL_UPLOAD = "manual_upload"
    AUTOMATED_SCAN = "automated_scan"
    SYSTEM_EXPORT = "system_export"
    SCREENSHOT = "screenshot"


@dataclass
class EvidenceProvenance:
    """
    Complete chain of custody metadata for evidence.
    
    This is the core of defensible auditing - every piece of evidence
    must have complete provenance to be trustworthy.
    """
    # Identity
    evidence_id: str
    evidence_type: EvidenceType
    title: str
    description: str
    
    # Source information
    source_system: str
    source_type: SourceType
    source_url: Optional[str] = None
    
    # Collection metadata
    collected_at: datetime = field(default_factory=datetime.utcnow)
    collection_method: str = ""
    collector_id: str = ""
    collector_version: str = "1.0.0"
    
    # Scope
    scope_systems: list[str] = field(default_factory=list)
    scope_start_date: Optional[datetime] = None
    scope_end_date: Optional[datetime] = None
    
    # Integrity
    content_hash: str = ""
    hash_algorithm: str = "sha256"
    
    # Control mapping
    control_ids: list[str] = field(default_factory=list)
    evidence_requirement_ids: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['evidence_type'] = self.evidence_type.value
        data['source_type'] = self.source_type.value
        data['collected_at'] = self.collected_at.isoformat()
        if self.scope_start_date:
            data['scope_start_date'] = self.scope_start_date.isoformat()
        if self.scope_end_date:
            data['scope_end_date'] = self.scope_end_date.isoformat()
        return data


@dataclass
class Evidence:
    """
    An evidence artifact with content and provenance.
    
    Evidence is immutable once created - any changes require
    creating a new evidence artifact with new provenance.
    """
    provenance: EvidenceProvenance
    content: bytes
    content_type: str  # MIME type
    filename: str
    
    def __post_init__(self):
        """Calculate content hash after initialization."""
        if not self.provenance.content_hash:
            self.provenance.content_hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of content."""
        return hashlib.sha256(self.content).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify content hasn't been tampered with."""
        return self._calculate_hash() == self.provenance.content_hash
    
    @property
    def evidence_id(self) -> str:
        return self.provenance.evidence_id


class EvidenceCollector(ABC):
    """
    Abstract base class for evidence collectors.
    
    Each collector is responsible for gathering evidence from a specific
    source type (API, file system, scanner, etc.)
    """
    
    def __init__(self, collector_id: str, version: str = "1.0.0"):
        self.collector_id = collector_id
        self.version = version
    
    @abstractmethod
    async def collect(
        self,
        evidence_requirement_id: str,
        control_ids: list[str],
        scope: dict[str, Any]
    ) -> Evidence:
        """
        Collect evidence for a specific requirement.
        
        Args:
            evidence_requirement_id: The evidence requirement being satisfied
            control_ids: Controls this evidence supports
            scope: Collection scope (systems, date range, etc.)
            
        Returns:
            Evidence artifact with full provenance
        """
        pass
    
    def _generate_evidence_id(self, requirement_id: str) -> str:
        """Generate unique evidence ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique = str(uuid.uuid4())[:8]
        return f"{requirement_id}-{timestamp}-{unique}"


class EvidenceStore:
    """
    Storage for evidence artifacts with manifest tracking.
    
    Follows the emcgrab pattern of organizing evidence by control
    with a manifest for quick lookup.
    """
    
    def __init__(self, base_path: Path):
        self.base_path = Path(base_path)
        self.raw_path = self.base_path / "raw"
        self.manifest_path = self.base_path / "manifest.json"
        self._ensure_directories()
        self.manifest: dict[str, dict] = self._load_manifest()
    
    def _ensure_directories(self):
        """Create directory structure if it doesn't exist."""
        self.raw_path.mkdir(parents=True, exist_ok=True)
    
    def _load_manifest(self) -> dict:
        """Load existing manifest or create empty one."""
        if self.manifest_path.exists():
            with open(self.manifest_path, 'r') as f:
                return json.load(f)
        return {
            "created_at": datetime.utcnow().isoformat(),
            "evidence": {}
        }
    
    def _save_manifest(self):
        """Persist manifest to disk."""
        self.manifest["updated_at"] = datetime.utcnow().isoformat()
        with open(self.manifest_path, 'w') as f:
            json.dump(self.manifest, f, indent=2)
    
    def store(self, evidence: Evidence) -> str:
        """
        Store evidence artifact and update manifest.
        
        Returns:
            Path to stored evidence file
        """
        # Determine storage path
        control_id = evidence.provenance.control_ids[0] if evidence.provenance.control_ids else "unassigned"
        evidence_type = evidence.provenance.evidence_type.value
        
        storage_dir = self.raw_path / control_id / evidence_type
        storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Store content
        storage_path = storage_dir / evidence.filename
        with open(storage_path, 'wb') as f:
            f.write(evidence.content)
        
        # Store provenance sidecar
        provenance_path = storage_dir / f"{evidence.filename}.provenance.json"
        with open(provenance_path, 'w') as f:
            json.dump(evidence.provenance.to_dict(), f, indent=2)
        
        # Update manifest
        self.manifest["evidence"][evidence.evidence_id] = {
            "path": str(storage_path.relative_to(self.base_path)),
            "provenance_path": str(provenance_path.relative_to(self.base_path)),
            "control_ids": evidence.provenance.control_ids,
            "evidence_type": evidence_type,
            "collected_at": evidence.provenance.collected_at.isoformat(),
            "content_hash": evidence.provenance.content_hash
        }
        self._save_manifest()
        
        return str(storage_path)
    
    def get(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence by ID."""
        if evidence_id not in self.manifest["evidence"]:
            return None
        
        entry = self.manifest["evidence"][evidence_id]
        content_path = self.base_path / entry["path"]
        provenance_path = self.base_path / entry["provenance_path"]
        
        with open(content_path, 'rb') as f:
            content = f.read()
        
        with open(provenance_path, 'r') as f:
            prov_data = json.load(f)
        
        # Reconstruct provenance
        provenance = EvidenceProvenance(
            evidence_id=prov_data["evidence_id"],
            evidence_type=EvidenceType(prov_data["evidence_type"]),
            title=prov_data["title"],
            description=prov_data["description"],
            source_system=prov_data["source_system"],
            source_type=SourceType(prov_data["source_type"]),
            source_url=prov_data.get("source_url"),
            collected_at=datetime.fromisoformat(prov_data["collected_at"]),
            collection_method=prov_data["collection_method"],
            collector_id=prov_data["collector_id"],
            collector_version=prov_data["collector_version"],
            scope_systems=prov_data.get("scope_systems", []),
            content_hash=prov_data["content_hash"],
            hash_algorithm=prov_data["hash_algorithm"],
            control_ids=prov_data.get("control_ids", []),
            evidence_requirement_ids=prov_data.get("evidence_requirement_ids", [])
        )
        
        return Evidence(
            provenance=provenance,
            content=content,
            content_type=content_path.suffix,
            filename=content_path.name
        )
    
    def list_by_control(self, control_id: str) -> list[str]:
        """List all evidence IDs for a control."""
        return [
            eid for eid, entry in self.manifest["evidence"].items()
            if control_id in entry.get("control_ids", [])
        ]
    
    def verify_all_integrity(self) -> dict[str, bool]:
        """Verify integrity of all stored evidence."""
        results = {}
        for evidence_id in self.manifest["evidence"]:
            evidence = self.get(evidence_id)
            if evidence:
                results[evidence_id] = evidence.verify_integrity()
            else:
                results[evidence_id] = False
        return results


class ManualEvidenceCollector(EvidenceCollector):
    """
    Collector for manually uploaded evidence (documents, screenshots, etc.)
    """
    
    def __init__(self):
        super().__init__(collector_id="manual_upload", version="1.0.0")
    
    async def collect(
        self,
        evidence_requirement_id: str,
        control_ids: list[str],
        scope: dict[str, Any],
        file_path: Path,
        title: str,
        description: str,
        source_system: str
    ) -> Evidence:
        """
        Create evidence from a manually provided file.
        """
        with open(file_path, 'rb') as f:
            content = f.read()
        
        provenance = EvidenceProvenance(
            evidence_id=self._generate_evidence_id(evidence_requirement_id),
            evidence_type=EvidenceType.POLICY_DOCUMENT,
            title=title,
            description=description,
            source_system=source_system,
            source_type=SourceType.MANUAL_UPLOAD,
            collection_method="manual_file_upload",
            collector_id=self.collector_id,
            collector_version=self.version,
            scope_systems=scope.get("systems", []),
            scope_start_date=scope.get("period_start"),
            scope_end_date=scope.get("period_end"),
            control_ids=control_ids,
            evidence_requirement_ids=[evidence_requirement_id]
        )
        
        return Evidence(
            provenance=provenance,
            content=content,
            content_type=file_path.suffix,
            filename=file_path.name
        )


class JSONAPICollector(EvidenceCollector):
    """
    Generic collector for JSON APIs (Okta, Jira, etc.)
    """
    
    def __init__(self, api_name: str, base_url: str):
        super().__init__(collector_id=f"api_{api_name}", version="1.0.0")
        self.api_name = api_name
        self.base_url = base_url
    
    async def collect(
        self,
        evidence_requirement_id: str,
        control_ids: list[str],
        scope: dict[str, Any],
        endpoint: str,
        response_data: dict,
        title: str,
        description: str
    ) -> Evidence:
        """
        Create evidence from API response data.
        """
        content = json.dumps(response_data, indent=2).encode('utf-8')
        timestamp = datetime.utcnow().strftime("%Y%m%d")
        
        provenance = EvidenceProvenance(
            evidence_id=self._generate_evidence_id(evidence_requirement_id),
            evidence_type=EvidenceType.SYSTEM_EXTRACT,
            title=title,
            description=description,
            source_system=self.api_name,
            source_type=SourceType.API_EXTRACT,
            source_url=f"{self.base_url}{endpoint}",
            collection_method=f"GET {endpoint}",
            collector_id=self.collector_id,
            collector_version=self.version,
            scope_systems=scope.get("systems", []),
            scope_start_date=scope.get("period_start"),
            scope_end_date=scope.get("period_end"),
            control_ids=control_ids,
            evidence_requirement_ids=[evidence_requirement_id]
        )
        
        return Evidence(
            provenance=provenance,
            content=content,
            content_type=".json",
            filename=f"{evidence_requirement_id}-{timestamp}.json"
        )
