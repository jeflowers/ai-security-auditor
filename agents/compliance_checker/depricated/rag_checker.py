"""
RAG-Enhanced Compliance Checker

Integrates the RAG pipeline with the compliance checker agent to:
1. Retrieve relevant control definitions before assessment
2. Include anti-hallucination rules in every prompt
3. Ground all assessments in retrieved evidence
4. Provide source citations for every claim

This is the bridge between the RAG pipeline and LLM-based assessment.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import yaml

from rag.pipeline import ComplianceRAGPipeline, RetrievalContext
from rag.vector_store import SearchResult


class AssessmentStatus(Enum):
    """Valid assessment statuses - no ambiguous states allowed."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class FindingSeverity(Enum):
    """Severity levels for compliance findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EvidenceReference:
    """Reference to a specific piece of evidence."""
    evidence_id: str
    source_file: str
    collected_at: datetime
    relevant_excerpt: str = ""
    confidence: float = 1.0


@dataclass
class Finding:
    """A compliance finding with full evidence chain."""
    finding_id: str
    control_id: str
    title: str
    description: str
    severity: FindingSeverity
    status: AssessmentStatus
    
    # Evidence chain - every finding MUST have references
    evidence_refs: list[EvidenceReference] = field(default_factory=list)
    
    # Reasoning that cites evidence
    reasoning: str = ""
    
    # Recommendations
    recommendations: list[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "evidence_refs": [
                {
                    "evidence_id": ref.evidence_id,
                    "source_file": ref.source_file,
                    "collected_at": ref.collected_at.isoformat(),
                    "relevant_excerpt": ref.relevant_excerpt
                }
                for ref in self.evidence_refs
            ],
            "reasoning": self.reasoning,
            "recommendations": self.recommendations,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class ControlAssessment:
    """Complete assessment for a single control."""
    control_id: str
    control_title: str
    status: AssessmentStatus
    score: float  # 0.0 to 1.0
    confidence: str  # HIGH, MEDIUM, LOW
    
    # Evidence tracking
    evidence_collected: list[str] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    
    # Findings
    findings: list[Finding] = field(default_factory=list)
    
    # RAG context used
    context_chunks_used: int = 0
    
    # Reasoning chain
    reasoning: str = ""
    
    # Timestamps
    assessed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass 
class LLMResponse:
    """Structured response from LLM assessment."""
    status: AssessmentStatus
    evidence_refs: list[str]
    gaps: list[str]
    reasoning: str
    findings: list[dict]
    raw_response: str = ""


class RAGComplianceChecker:
    """
    Compliance checker that uses RAG for grounded assessments.
    
    Key principles:
    1. Every assessment retrieves relevant context first
    2. Anti-hallucination rules are always included
    3. All claims must cite specific evidence
    4. Missing evidence = EVIDENCE_GAP, not assumptions
    """
    
    def __init__(
        self,
        rag_pipeline: ComplianceRAGPipeline,
        llm_client: Any = None,  # OpenAI client or similar
        framework: str = "SOC2"
    ):
        self.rag = rag_pipeline
        self.llm = llm_client
        self.framework = framework
        
        # Load control definitions for reference
        self.controls = {}
        self._load_controls()
    
    def _load_controls(self):
        """Load control definitions from framework files."""
        controls_path = self.rag.persist_dir.parent / "frameworks" / self.framework.lower() / "controls.yaml"
        if controls_path.exists():
            with open(controls_path, 'r') as f:
                data = yaml.safe_load(f)
                self.controls = data.get("controls", {})
    
    async def assess_control(
        self,
        control_id: str,
        evidence_summary: dict[str, Any] = None,
        collected_evidence: list[dict] = None
    ) -> ControlAssessment:
        """
        Assess a single control using RAG-enhanced prompting.
        
        Args:
            control_id: The control to assess (e.g., "CC6.1")
            evidence_summary: Summary of collected evidence
            collected_evidence: List of evidence artifacts
        
        Returns:
            ControlAssessment with grounded findings
        """
        # 1. Retrieve context for this control
        context = await self.rag.retrieve_for_control(
            control_id=control_id,
            include_rubric=True
        )
        
        # 2. Get control definition
        control_def = self.controls.get(control_id, {})
        control_title = control_def.get("title", f"Control {control_id}")
        
        # 3. Determine required evidence
        evidence_plan = control_def.get("evidence_plan", {})
        required_evidence = [
            e.get("evidence_id") 
            for e in evidence_plan.get("required_evidence", [])
        ]
        
        # 4. Check what evidence we have
        collected_ids = []
        if collected_evidence:
            collected_ids = [e.get("evidence_id") for e in collected_evidence]
        
        evidence_gaps = [eid for eid in required_evidence if eid not in collected_ids]
        
        # 5. If no LLM client, do rule-based assessment
        if not self.llm:
            return self._rule_based_assessment(
                control_id=control_id,
                control_title=control_title,
                context=context,
                collected_evidence=collected_evidence or [],
                evidence_gaps=evidence_gaps
            )
        
        # 6. Build prompt with RAG context
        prompt = self._build_assessment_prompt(
            control_id=control_id,
            context=context,
            evidence_summary=evidence_summary,
            collected_evidence=collected_evidence
        )
        
        # 7. Call LLM for assessment
        llm_response = await self._call_llm(prompt)
        
        # 8. Parse and validate response
        assessment = self._parse_llm_response(
            control_id=control_id,
            control_title=control_title,
            context=context,
            llm_response=llm_response,
            evidence_gaps=evidence_gaps
        )
        
        return assessment
    
    def _rule_based_assessment(
        self,
        control_id: str,
        control_title: str,
        context: RetrievalContext,
        collected_evidence: list[dict],
        evidence_gaps: list[str]
    ) -> ControlAssessment:
        """
        Perform rule-based assessment without LLM.
        
        Used when no LLM is configured or for testing.
        Strictly follows anti-hallucination rules.
        """
        findings = []
        
        # Rule 1: If no evidence collected, status is EVIDENCE_GAP
        if not collected_evidence:
            return ControlAssessment(
                control_id=control_id,
                control_title=control_title,
                status=AssessmentStatus.EVIDENCE_GAP,
                score=0.0,
                confidence="HIGH",
                evidence_collected=[],
                evidence_gaps=evidence_gaps,
                findings=[
                    Finding(
                        finding_id=f"{control_id}-F001",
                        control_id=control_id,
                        title="No Evidence Collected",
                        description="No evidence was provided for this control assessment.",
                        severity=FindingSeverity.HIGH,
                        status=AssessmentStatus.EVIDENCE_GAP,
                        reasoning="Cannot assess compliance without evidence. "
                                  "This is NOT an assumption of non-compliance, "
                                  "but an acknowledgment that evidence is required."
                    )
                ],
                context_chunks_used=context.total_chunks,
                reasoning="Assessment cannot proceed without evidence. "
                          f"Required evidence: {', '.join(evidence_gaps)}"
            )
        
        # Rule 2: Check evidence gaps
        if evidence_gaps:
            # Some evidence collected but gaps exist
            collected_ids = [e.get("evidence_id") for e in collected_evidence]
            
            findings.append(Finding(
                finding_id=f"{control_id}-F001",
                control_id=control_id,
                title="Evidence Gaps Identified",
                description=f"Missing required evidence: {', '.join(evidence_gaps)}",
                severity=FindingSeverity.MEDIUM,
                status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
                evidence_refs=[
                    EvidenceReference(
                        evidence_id=eid,
                        source_file=next(
                            (e.get("source_file", "") for e in collected_evidence 
                             if e.get("evidence_id") == eid),
                            ""
                        ),
                        collected_at=datetime.utcnow()
                    )
                    for eid in collected_ids
                ],
                reasoning=f"Evidence {', '.join(collected_ids)} was collected, "
                          f"but {', '.join(evidence_gaps)} are still required."
            ))
            
            # Calculate partial score
            total_required = len(evidence_gaps) + len(collected_ids)
            score = len(collected_ids) / total_required if total_required > 0 else 0
            
            return ControlAssessment(
                control_id=control_id,
                control_title=control_title,
                status=AssessmentStatus.INSUFFICIENT_EVIDENCE,
                score=score,
                confidence="MEDIUM",
                evidence_collected=collected_ids,
                evidence_gaps=evidence_gaps,
                findings=findings,
                context_chunks_used=context.total_chunks,
                reasoning=f"Partial evidence collected ({len(collected_ids)}/{total_required}). "
                          f"Cannot determine compliance status without complete evidence."
            )
        
        # Rule 3: All required evidence collected - can assess
        collected_ids = [e.get("evidence_id") for e in collected_evidence]
        
        # Basic validation of evidence
        valid_evidence = []
        for evidence in collected_evidence:
            # Check if evidence has required fields
            if evidence.get("content_hash") and evidence.get("collected_at"):
                valid_evidence.append(evidence)
            else:
                findings.append(Finding(
                    finding_id=f"{control_id}-F{len(findings)+1:03d}",
                    control_id=control_id,
                    title="Evidence Validation Issue",
                    description=f"Evidence {evidence.get('evidence_id')} missing required metadata",
                    severity=FindingSeverity.LOW,
                    status=AssessmentStatus.NEEDS_MANUAL_REVIEW,
                    reasoning="Evidence must have content_hash and collected_at for verification."
                ))
        
        # Determine status based on evidence validity
        if len(valid_evidence) == len(collected_evidence):
            status = AssessmentStatus.PASS
            score = 1.0
            confidence = "HIGH"
        elif len(valid_evidence) >= len(collected_evidence) * 0.8:
            status = AssessmentStatus.PASS
            score = len(valid_evidence) / len(collected_evidence)
            confidence = "MEDIUM"
        else:
            status = AssessmentStatus.NEEDS_MANUAL_REVIEW
            score = len(valid_evidence) / len(collected_evidence)
            confidence = "LOW"
        
        return ControlAssessment(
            control_id=control_id,
            control_title=control_title,
            status=status,
            score=score,
            confidence=confidence,
            evidence_collected=collected_ids,
            evidence_gaps=[],
            findings=findings,
            context_chunks_used=context.total_chunks,
            reasoning=f"All required evidence collected. "
                      f"{len(valid_evidence)}/{len(collected_evidence)} evidence items validated. "
                      f"Assessment based on evidence: {', '.join(collected_ids)}"
        )
    
    def _build_assessment_prompt(
        self,
        control_id: str,
        context: RetrievalContext,
        evidence_summary: dict = None,
        collected_evidence: list[dict] = None
    ) -> str:
        """Build a comprehensive assessment prompt with RAG context."""
        
        # Use the pipeline's prompt builder
        evidence_text = ""
        if collected_evidence:
            evidence_parts = []
            for ev in collected_evidence:
                evidence_parts.append(
                    f"- {ev.get('evidence_id')}: {ev.get('name', 'Unknown')}\n"
                    f"  Type: {ev.get('type', 'Unknown')}\n"
                    f"  Collected: {ev.get('collected_at', 'Unknown')}\n"
                    f"  Hash: {ev.get('content_hash', 'Unknown')[:16]}..."
                )
            evidence_text = "\n".join(evidence_parts)
        
        return self.rag.build_assessment_prompt(
            control_id=control_id,
            context=context,
            evidence_summary=evidence_text
        )
    
    async def _call_llm(self, prompt: str) -> LLMResponse:
        """Call LLM with the assessment prompt."""
        if not self.llm:
            raise ValueError("No LLM client configured")
        
        # Call OpenAI or similar
        response = await self.llm.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {
                    "role": "system",
                    "content": "You are a SOC 2 compliance auditor. "
                               "You MUST cite specific evidence for every claim. "
                               "You MUST NOT use words like 'likely', 'probably', 'seems'. "
                               "If evidence is missing, state EVIDENCE_GAP."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Low temperature for consistency
            max_tokens=2000
        )
        
        raw = response.choices[0].message.content
        
        # Parse structured response
        # (In production, use function calling or structured outputs)
        return self._parse_raw_llm_response(raw)
    
    def _parse_raw_llm_response(self, raw: str) -> LLMResponse:
        """Parse raw LLM response into structured format."""
        # Simple parsing - in production use JSON mode or function calling
        lines = raw.strip().split('\n')
        
        status = AssessmentStatus.NEEDS_MANUAL_REVIEW
        evidence_refs = []
        gaps = []
        reasoning = ""
        findings = []
        
        current_section = None
        
        for line in lines:
            line = line.strip()
            if line.startswith("STATUS:"):
                status_str = line.replace("STATUS:", "").strip()
                try:
                    status = AssessmentStatus(status_str)
                except ValueError:
                    status = AssessmentStatus.NEEDS_MANUAL_REVIEW
            elif line.startswith("EVIDENCE_REFS:"):
                refs_str = line.replace("EVIDENCE_REFS:", "").strip()
                evidence_refs = [r.strip() for r in refs_str.split(",") if r.strip()]
            elif line.startswith("GAPS:"):
                gaps_str = line.replace("GAPS:", "").strip()
                gaps = [g.strip() for g in gaps_str.split(",") if g.strip()]
            elif line.startswith("REASONING:"):
                reasoning = line.replace("REASONING:", "").strip()
                current_section = "reasoning"
            elif current_section == "reasoning" and not line.startswith(("STATUS:", "EVIDENCE_REFS:", "GAPS:", "FINDINGS:")):
                reasoning += " " + line
        
        return LLMResponse(
            status=status,
            evidence_refs=evidence_refs,
            gaps=gaps,
            reasoning=reasoning.strip(),
            findings=findings,
            raw_response=raw
        )
    
    def _parse_llm_response(
        self,
        control_id: str,
        control_title: str,
        context: RetrievalContext,
        llm_response: LLMResponse,
        evidence_gaps: list[str]
    ) -> ControlAssessment:
        """Parse LLM response into ControlAssessment."""
        
        # Validate: LLM cannot claim PASS without evidence
        if llm_response.status == AssessmentStatus.PASS and not llm_response.evidence_refs:
            # Anti-hallucination: Override invalid PASS
            llm_response.status = AssessmentStatus.EVIDENCE_GAP
            llm_response.reasoning = (
                "OVERRIDE: LLM claimed PASS without citing evidence. "
                "Original response did not meet evidence requirements."
            )
        
        # Calculate score
        total_evidence = len(llm_response.evidence_refs) + len(evidence_gaps)
        score = len(llm_response.evidence_refs) / total_evidence if total_evidence > 0 else 0
        
        # Determine confidence based on evidence coverage
        if len(evidence_gaps) == 0 and llm_response.evidence_refs:
            confidence = "HIGH"
        elif len(evidence_gaps) <= 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        return ControlAssessment(
            control_id=control_id,
            control_title=control_title,
            status=llm_response.status,
            score=score,
            confidence=confidence,
            evidence_collected=llm_response.evidence_refs,
            evidence_gaps=evidence_gaps,
            findings=[],  # Would parse from llm_response.findings
            context_chunks_used=context.total_chunks,
            reasoning=llm_response.reasoning
        )
    
    async def assess_all_controls(
        self,
        evidence_by_control: dict[str, list[dict]] = None
    ) -> dict[str, ControlAssessment]:
        """Assess all controls in the framework."""
        assessments = {}
        evidence_by_control = evidence_by_control or {}
        
        for control_id in self.controls:
            evidence = evidence_by_control.get(control_id, [])
            assessment = await self.assess_control(
                control_id=control_id,
                collected_evidence=evidence
            )
            assessments[control_id] = assessment
        
        return assessments
    
    def generate_report(
        self,
        assessments: dict[str, ControlAssessment]
    ) -> dict:
        """Generate a compliance report from assessments."""
        
        # Count by status
        status_counts = {}
        for assessment in assessments.values():
            status = assessment.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Calculate overall score
        total_score = sum(a.score for a in assessments.values())
        avg_score = total_score / len(assessments) if assessments else 0
        
        # Determine overall status
        if status_counts.get("FAIL", 0) > 0:
            overall_status = "FAIL"
        elif status_counts.get("EVIDENCE_GAP", 0) > len(assessments) * 0.2:
            overall_status = "INCOMPLETE"
        elif status_counts.get("PASS", 0) == len(assessments):
            overall_status = "PASS"
        else:
            overall_status = "PASS_WITH_EXCEPTIONS"
        
        # Collect all gaps
        all_gaps = []
        for control_id, assessment in assessments.items():
            for gap in assessment.evidence_gaps:
                all_gaps.append({
                    "control_id": control_id,
                    "evidence_id": gap
                })
        
        return {
            "report_id": f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "framework": self.framework,
            "generated_at": datetime.utcnow().isoformat(),
            "overall_status": overall_status,
            "overall_score": round(avg_score, 2),
            "status_summary": status_counts,
            "controls_assessed": len(assessments),
            "evidence_gaps": all_gaps,
            "assessments": {
                cid: {
                    "status": a.status.value,
                    "score": round(a.score, 2),
                    "confidence": a.confidence,
                    "evidence_collected": a.evidence_collected,
                    "evidence_gaps": a.evidence_gaps,
                    "reasoning": a.reasoning
                }
                for cid, a in assessments.items()
            }
        }
