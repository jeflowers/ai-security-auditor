"""
Tests for Anti-Hallucination Framework.

Covers all five fundamental rules:
1. CITE_OR_ABSTAIN - Every compliance claim must cite specific evidence
2. CONFIDENCE_SCORING - Evidence must be verifiable artifacts  
3. NO_WEASEL_WORDS - Assessment states must be bounded
4. SCOPE_BOUNDARY - No inference from missing evidence
5. PROVENANCE_CHAIN - Explicit mapping between findings and claims
"""

import pytest
from datetime import datetime, timezone
from agents.compliance_checker.anti_hallucination import (
    AssessmentState,
    ConfidenceLevel,
    EvidenceType,
    Evidence,
    EvidenceProvenance,
    ValidationResult,
    ComplianceClaim,
    WeaselWordDetector,
    EvidenceRequirementChecker,
    AntiHallucinationValidator,
    ComplianceStatementBuilder,
    ProvenanceTracker,
    create_evidence_provenance,
)


# ============================================================================
# Evidence Tests
# ============================================================================

class TestEvidence:
    """Test Evidence dataclass and factory methods."""
    
    def test_create_evidence_with_factory(self):
        """Evidence.create() should generate proper ID and hash."""
        evidence = Evidence.create(
            evidence_type=EvidenceType.LOG_ARTIFACT,
            source="/var/log/auth.log",
            content="2024-01-15 SSH login success for user admin",
            summary="Successful SSH authentication"
        )
        
        assert evidence.evidence_id.startswith("EVD-")
        assert len(evidence.content_hash) == 64  # SHA-256 hex length
        assert evidence.evidence_type == EvidenceType.LOG_ARTIFACT
        assert evidence.source == "/var/log/auth.log"
    
    def test_evidence_requires_id(self):
        """Evidence must have an ID."""
        with pytest.raises(ValueError, match="must have an ID"):
            Evidence(
                evidence_id="",
                evidence_type=EvidenceType.SCAN_RESULT,
                source="scanner",
                collected_at=datetime.now(timezone.utc),
                content_hash="abc123",
                summary="test"
            )
    
    def test_evidence_requires_source(self):
        """Evidence must have a source."""
        with pytest.raises(ValueError, match="must have a source"):
            Evidence(
                evidence_id="EVD-001",
                evidence_type=EvidenceType.SCAN_RESULT,
                source="",
                collected_at=datetime.now(timezone.utc),
                content_hash="abc123",
                summary="test"
            )
    
    def test_evidence_requires_hash(self):
        """Evidence must have a content hash."""
        with pytest.raises(ValueError, match="must have a content hash"):
            Evidence(
                evidence_id="EVD-001",
                evidence_type=EvidenceType.SCAN_RESULT,
                source="scanner",
                collected_at=datetime.now(timezone.utc),
                content_hash="",
                summary="test"
            )
    
    def test_evidence_hash_deterministic(self):
        """Same content should produce same hash."""
        content = "Test content for hashing"
        e1 = Evidence.create(EvidenceType.LOG_ARTIFACT, "src", content, "test")
        e2 = Evidence.create(EvidenceType.LOG_ARTIFACT, "src", content, "test")
        
        assert e1.content_hash == e2.content_hash
        assert e1.evidence_id == e2.evidence_id
    
    def test_evidence_hash_different_for_different_content(self):
        """Different content should produce different hash."""
        e1 = Evidence.create(EvidenceType.LOG_ARTIFACT, "src", "content1", "test")
        e2 = Evidence.create(EvidenceType.LOG_ARTIFACT, "src", "content2", "test")
        
        assert e1.content_hash != e2.content_hash
    
    def test_evidence_metadata_optional(self):
        """Evidence should work with or without metadata."""
        e1 = Evidence.create(EvidenceType.LOG_ARTIFACT, "src", "content", "test")
        e2 = Evidence.create(
            EvidenceType.LOG_ARTIFACT, "src", "content", "test",
            metadata={"key": "value"}
        )
        
        assert e1.metadata == {}
        assert e2.metadata == {"key": "value"}
    
    def test_all_evidence_types(self):
        """All evidence types should be valid."""
        for etype in EvidenceType:
            evidence = Evidence.create(etype, "source", "content", "summary")
            assert evidence.evidence_type == etype


# ============================================================================
# Evidence Provenance Tests
# ============================================================================

class TestEvidenceProvenance:
    """Test EvidenceProvenance and factory function."""
    
    def test_create_evidence_provenance(self):
        """Factory function should create valid provenance."""
        provenance = create_evidence_provenance(
            evidence_id="EVD-001",
            source="/var/log/auth.log",
            source_type="log_file",
            collector="log_analyzer",
            content="test content"
        )
        
        assert provenance.evidence_id == "EVD-001"
        assert provenance.source == "/var/log/auth.log"
        assert provenance.collector == "log_analyzer"
        assert len(provenance.content_hash) == 64
    
    def test_add_to_chain(self):
        """Should add steps to provenance chain."""
        provenance = create_evidence_provenance(
            evidence_id="EVD-001",
            source="test",
            source_type="test",
            collector="test",
            content="test"
        )
        
        provenance.add_to_chain("Collected from source")
        provenance.add_to_chain("Validated hash")
        
        assert len(provenance.chain) == 2


# ============================================================================
# Validation Result Tests
# ============================================================================

class TestValidationResult:
    """Test ValidationResult dataclass."""
    
    def test_add_error_sets_invalid(self):
        """Adding an error should set is_valid to False."""
        result = ValidationResult(is_valid=True)
        result.add_error("Test error")
        
        assert result.is_valid is False
        assert "Test error" in result.errors
    
    def test_add_warning_preserves_validity(self):
        """Adding a warning should not affect validity."""
        result = ValidationResult(is_valid=True)
        result.add_warning("Test warning")
        
        assert result.is_valid is True
        assert "Test warning" in result.warnings


# ============================================================================
# Compliance Claim Tests
# ============================================================================

class TestComplianceClaim:
    """Test ComplianceClaim validation."""
    
    def test_compliant_claim_valid_with_evidence(self):
        """COMPLIANT/PASS claims are valid when they have evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=["EVD-001"]
        )
        
        assert claim.is_valid() is True
    
    def test_compliant_claim_invalid_without_evidence(self):
        """COMPLIANT/PASS claims are invalid without evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[]
        )
        
        assert claim.is_valid() is False
    
    def test_non_compliant_claim_valid_with_evidence(self):
        """NON_COMPLIANT/FAIL claims are valid with evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is not implemented",
            assessment_state=AssessmentState.FAIL,
            evidence_ids=["EVD-001"]
        )
        
        assert claim.is_valid() is True
    
    def test_not_assessed_valid_without_evidence(self):
        """NOT_ASSESSED claims don't require evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control was not assessed",
            assessment_state=AssessmentState.NOT_ASSESSED,
            evidence_ids=[]
        )
        
        assert claim.is_valid() is True
    
    def test_insufficient_evidence_valid_without_evidence(self):
        """INSUFFICIENT_EVIDENCE claims don't require evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Additional evidence required",
            assessment_state=AssessmentState.INSUFFICIENT_EVIDENCE,
            evidence_ids=[]
        )
        
        assert claim.is_valid() is True


# ============================================================================
# Weasel Word Detection Tests
# ============================================================================

class TestWeaselWordDetector:
    """Test detection of hedging language."""
    
    @pytest.fixture
    def detector(self):
        return WeaselWordDetector()
    
    def test_detects_likely(self, detector):
        """Should detect 'likely'."""
        violations = detector.detect("The control is likely compliant")
        assert len(violations) == 1
        assert violations[0]["matched_text"].lower() == "likely"
    
    def test_detects_probably(self, detector):
        """Should detect 'probably'."""
        violations = detector.detect("This is probably secure")
        assert len(violations) == 1
        assert violations[0]["matched_text"].lower() == "probably"
    
    def test_detects_appears_to(self, detector):
        """Should detect 'appears to'."""
        violations = detector.detect("The system appears to be compliant")
        assert len(violations) == 1
        assert "appears to" in violations[0]["matched_text"].lower()
    
    def test_detects_seems_to(self, detector):
        """Should detect 'seems to'."""
        violations = detector.detect("Configuration seems to be correct")
        assert len(violations) == 1
        assert "seems to" in violations[0]["matched_text"].lower()
    
    def test_detects_might(self, detector):
        """Should detect 'might'."""
        violations = detector.detect("This might meet the requirement")
        assert len(violations) == 1
    
    def test_detects_could_be(self, detector):
        """Should detect 'could be'."""
        violations = detector.detect("This could be compliant")
        assert len(violations) == 1
    
    def test_detects_should_be(self, detector):
        """Should detect 'should be'."""
        violations = detector.detect("The control should be effective")
        assert len(violations) == 1
    
    def test_detects_assumed(self, detector):
        """Should detect 'assumed'."""
        violations = detector.detect("It is assumed the control works")
        assert len(violations) == 1
    
    def test_detects_generally(self, detector):
        """Should detect 'generally'."""
        violations = detector.detect("The system is generally secure")
        assert len(violations) == 1
    
    def test_detects_typically(self, detector):
        """Should detect 'typically'."""
        violations = detector.detect("This typically works")
        assert len(violations) == 1
    
    def test_detects_usually(self, detector):
        """Should detect 'usually'."""
        violations = detector.detect("Backups usually complete successfully")
        assert len(violations) == 1
    
    def test_detects_mostly(self, detector):
        """Should detect 'mostly'."""
        violations = detector.detect("The tests are mostly passing")
        assert len(violations) == 1
    
    def test_detects_partially(self, detector):
        """Should detect 'partially'."""
        violations = detector.detect("The control is partially implemented")
        assert len(violations) == 1
    
    def test_detects_approximately(self, detector):
        """Should detect 'approximately'."""
        violations = detector.detect("Approximately 90% compliant")
        assert len(violations) == 1
    
    def test_detects_multiple_weasel_words(self, detector):
        """Should detect multiple weasel words in one statement."""
        text = "The control is probably mostly compliant and likely secure"
        violations = detector.detect(text)
        assert len(violations) >= 3
    
    def test_clean_statement_passes(self, detector):
        """Clean statements should have no violations."""
        text = "Control CC6.1 is implemented. Evidence: scan results show all ports closed."
        assert detector.is_clean(text) is True
    
    def test_case_insensitive(self, detector):
        """Detection should be case insensitive."""
        assert len(detector.detect("LIKELY")) == 1
        assert len(detector.detect("Probably")) == 1
        assert len(detector.detect("APPEARS TO")) == 1
    
    def test_provides_context(self, detector):
        """Violations should include context."""
        violations = detector.detect("The system is likely secure based on our analysis")
        assert "context" in violations[0]
        assert len(violations[0]["context"]) > 0
    
    def test_provides_location(self, detector):
        """Violations should include start and end positions."""
        text = "This is likely compliant"
        violations = detector.detect(text)
        assert "start" in violations[0]
        assert "end" in violations[0]
        assert text[violations[0]["start"]:violations[0]["end"]].lower() == "likely"


# ============================================================================
# Evidence Requirement Checker Tests
# ============================================================================

class TestEvidenceRequirementChecker:
    """Test evidence requirement validation."""
    
    @pytest.fixture
    def checker(self):
        return EvidenceRequirementChecker()
    
    @pytest.fixture
    def sample_evidence(self):
        return Evidence.create(
            EvidenceType.SCAN_RESULT,
            "OWASP ZAP",
            "No vulnerabilities found",
            "Clean scan"
        )
    
    def test_compliant_requires_evidence(self, checker):
        """COMPLIANT/PASS claims must have at least one evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[],
            reasoning="Based on scan results"
        )
        
        is_valid, errors = checker.validate_claim(claim)
        assert is_valid is False
        assert any("at least 1 evidence" in e for e in errors)
    
    def test_non_compliant_requires_evidence(self, checker):
        """NON_COMPLIANT/FAIL claims must have at least one evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is not implemented",
            assessment_state=AssessmentState.FAIL,
            evidence_ids=[],
            reasoning="Vulnerability found"
        )
        
        is_valid, errors = checker.validate_claim(claim)
        assert is_valid is False
    
    def test_evidence_must_exist_in_registry(self, checker, sample_evidence):
        """Evidence IDs must reference registered evidence."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=["EVD-NONEXISTENT"],
            reasoning="Based on scan results"
        )
        
        is_valid, errors = checker.validate_claim(claim)
        assert is_valid is False
        assert any("not found in registry" in e for e in errors)
    
    def test_valid_with_registered_evidence(self, checker, sample_evidence):
        """Claims with registered evidence should pass."""
        checker.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning="Based on scan results showing no vulnerabilities"
        )
        
        is_valid, errors = checker.validate_claim(claim)
        assert is_valid is True
        assert len(errors) == 0
    
    def test_requires_substantive_reasoning(self, checker, sample_evidence):
        """Claims must have substantive reasoning."""
        checker.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning=""  # Empty reasoning
        )
        
        is_valid, errors = checker.validate_claim(claim)
        assert is_valid is False
        assert any("reasoning" in e for e in errors)


# ============================================================================
# Anti-Hallucination Validator Tests
# ============================================================================

class TestAntiHallucinationValidator:
    """Test full assessment validation."""
    
    @pytest.fixture
    def validator(self):
        return AntiHallucinationValidator()
    
    @pytest.fixture
    def sample_evidence(self):
        return Evidence.create(
            EvidenceType.SCAN_RESULT,
            "OWASP ZAP",
            "No XSS vulnerabilities found",
            "Clean XSS scan"
        )
    
    def test_rejects_claim_with_weasel_words(self, validator, sample_evidence):
        """Claims with weasel words should be rejected."""
        validator.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is probably compliant",  # Weasel word
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning="Scan shows no vulnerabilities"
        )
        
        result = validator.validate_claim(claim)
        assert result.is_valid is False
        assert any("Weasel word" in e for e in result.errors)
    
    def test_rejects_weasel_words_in_reasoning(self, validator, sample_evidence):
        """Weasel words in reasoning should be rejected."""
        validator.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning="This is likely due to good configuration"  # Weasel word
        )
        
        result = validator.validate_claim(claim)
        assert result.is_valid is False
        assert any("reasoning" in e.lower() for e in result.errors)
    
    def test_accepts_clean_claim(self, validator, sample_evidence):
        """Clean claims with evidence should pass."""
        validator.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control CC6.1 is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning="OWASP ZAP scan completed with zero vulnerabilities detected"
        )
        
        result = validator.validate_claim(claim)
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_validate_method_alias(self, validator, sample_evidence):
        """validate() should work as alias for validate_claim()."""
        validator.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning="Verified by scan results"
        )
        
        result = validator.validate(claim)
        assert result.is_valid is True
    
    def test_validate_full_report(self, validator, sample_evidence):
        """Should validate entire assessment report."""
        validator.register_evidence(sample_evidence)
        
        claims = [
            ComplianceClaim(
                claim_id="CLM-001",
                control_id="CC6.1",
                statement="Control is implemented",
                assessment_state=AssessmentState.PASS,
                evidence_ids=[sample_evidence.evidence_id],
                reasoning="Verified by scan results"
            ),
            ComplianceClaim(
                claim_id="CLM-002",
                control_id="CC6.2",
                statement="Control was not assessed",
                assessment_state=AssessmentState.NOT_ASSESSED,
                evidence_ids=[],
                reasoning="Out of scope"
            ),
        ]
        
        results = validator.validate_assessment_report(claims)
        assert results["total_claims"] == 2
        assert results["valid_claims"] == 2
        assert results["overall_valid"] is True
    
    def test_report_invalid_with_any_invalid_claim(self, validator):
        """Report should be invalid if any claim is invalid."""
        claims = [
            ComplianceClaim(
                claim_id="CLM-001",
                control_id="CC6.1",
                statement="Control is probably compliant",  # Invalid
                assessment_state=AssessmentState.PASS,
                evidence_ids=[],
                reasoning="Assumed to be true"
            ),
        ]
        
        results = validator.validate_assessment_report(claims)
        assert results["overall_valid"] is False
        assert results["invalid_claims"] == 1
    
    def test_sets_confidence_level(self, validator, sample_evidence):
        """Should set confidence level based on evidence count."""
        validator.register_evidence(sample_evidence)
        
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[sample_evidence.evidence_id],
            reasoning="Verified by scan results"
        )
        
        result = validator.validate_claim(claim)
        assert result.confidence == ConfidenceLevel.MEDIUM
    
    def test_stores_validation_errors(self, validator):
        """Validator should store errors for reporting."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Likely compliant",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[]
        )
        
        validator.validate_claim(claim)
        errors = validator.get_validation_errors()
        
        assert len(errors) > 0
        assert errors[0]["claim_id"] == "CLM-001"
    
    def test_clear_errors(self, validator):
        """Should be able to clear stored errors."""
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Likely compliant",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[]
        )
        
        validator.validate_claim(claim)
        assert len(validator.get_validation_errors()) > 0
        
        validator.clear_errors()
        assert len(validator.get_validation_errors()) == 0


# ============================================================================
# Statement Builder Tests
# ============================================================================

class TestComplianceStatementBuilder:
    """Test compliant statement generation."""
    
    @pytest.fixture
    def builder(self):
        return ComplianceStatementBuilder()
    
    def test_build_control_implemented(self, builder):
        """Should build control_implemented statement."""
        statement = builder.build_compliant_statement(
            "control_implemented",
            control_id="CC6.1",
            evidence_summary="OWASP ZAP scan showing zero vulnerabilities",
            verification_method="Automated security scan"
        )
        
        assert "CC6.1" in statement
        assert "implemented" in statement
        assert "Evidence:" in statement
    
    def test_build_control_not_implemented(self, builder):
        """Should build control_not_implemented statement."""
        statement = builder.build_compliant_statement(
            "control_not_implemented",
            control_id="CC6.2",
            finding="SQL injection vulnerability in login form",
            evidence_summary="ZAP scan result ID: ZAP-2024-001"
        )
        
        assert "not implemented" in statement
        assert "SQL injection" in statement
    
    def test_build_insufficient_evidence(self, builder):
        """Should build insufficient_evidence statement."""
        statement = builder.build_compliant_statement(
            "insufficient_evidence",
            control_id="CC7.1",
            available="Configuration files",
            required="Access control logs and audit trail"
        )
        
        assert "additional evidence" in statement
        assert "Required evidence:" in statement
    
    def test_rejects_invalid_template(self, builder):
        """Should reject unknown templates."""
        with pytest.raises(ValueError, match="Unknown template"):
            builder.build_compliant_statement("invalid_template")
    
    def test_validate_custom_statement_clean(self, builder):
        """Should validate clean custom statements."""
        is_valid, violations = builder.validate_custom_statement(
            "Control CC6.1 is implemented based on scan evidence EVD-001."
        )
        assert is_valid is True
        assert len(violations) == 0
    
    def test_validate_custom_statement_with_weasel(self, builder):
        """Should detect weasel words in custom statements."""
        is_valid, violations = builder.validate_custom_statement(
            "Control CC6.1 is probably implemented."
        )
        assert is_valid is False
        assert "probably" in violations


# ============================================================================
# Provenance Tracker Tests
# ============================================================================

class TestProvenanceTracker:
    """Test provenance chain tracking."""
    
    @pytest.fixture
    def tracker(self):
        return ProvenanceTracker()
    
    def test_add_mapping(self, tracker):
        """Should add provenance mapping."""
        tracker.add_mapping(
            finding_id="FND-001",
            evidence_id="EVD-001",
            control_id="CC6.1",
            framework="SOC2"
        )
        
        assert len(tracker.chains) == 1
        assert tracker.chains[0]["finding_id"] == "FND-001"
    
    def test_get_evidence_for_finding(self, tracker):
        """Should retrieve evidence IDs for a finding."""
        tracker.add_mapping("FND-001", "EVD-001", "CC6.1", "SOC2")
        tracker.add_mapping("FND-001", "EVD-002", "CC6.1", "SOC2")
        tracker.add_mapping("FND-002", "EVD-003", "CC6.2", "SOC2")
        
        evidence = tracker.get_evidence_for_finding("FND-001")
        assert len(evidence) == 2
        assert "EVD-001" in evidence
        assert "EVD-002" in evidence
    
    def test_get_controls_for_evidence(self, tracker):
        """Should retrieve control IDs that cite evidence."""
        tracker.add_mapping("FND-001", "EVD-001", "CC6.1", "SOC2")
        tracker.add_mapping("FND-002", "EVD-001", "CC6.2", "SOC2")
        
        controls = tracker.get_controls_for_evidence("EVD-001")
        assert len(controls) == 2
        assert "CC6.1" in controls
        assert "CC6.2" in controls
    
    def test_get_full_chain(self, tracker):
        """Should retrieve full provenance chain."""
        tracker.add_mapping("FND-001", "EVD-001", "CC6.1", "SOC2")
        tracker.add_mapping("FND-001", "EVD-002", "CC6.2", "GDPR")
        
        chain = tracker.get_full_chain("FND-001")
        assert len(chain) == 2
    
    def test_validate_chain_completeness_pass(self, tracker):
        """Complete chains should validate."""
        tracker.add_mapping("FND-001", "EVD-001", "CC6.1", "SOC2")
        
        is_valid, errors = tracker.validate_chain_completeness()
        assert is_valid is True
        assert len(errors) == 0
    
    def test_export_provenance_report(self, tracker):
        """Should export full provenance report."""
        tracker.add_mapping("FND-001", "EVD-001", "CC6.1", "SOC2")
        tracker.add_mapping("FND-002", "EVD-002", "CC6.2", "SOC2")
        
        report = tracker.export_provenance_report()
        assert report["total_mappings"] == 2
        assert "chains" in report
        assert "exported_at" in report


# ============================================================================
# Integration Tests
# ============================================================================

class TestAntiHallucinationIntegration:
    """Integration tests for the complete anti-hallucination workflow."""
    
    def test_full_validation_workflow(self):
        """Test complete validation from evidence to claim."""
        # Create evidence
        evidence = Evidence.create(
            EvidenceType.SCAN_RESULT,
            "OWASP ZAP Scanner",
            '{"vulnerabilities": [], "scan_date": "2024-01-15"}',
            "Clean vulnerability scan"
        )
        
        # Create validator and register evidence
        validator = AntiHallucinationValidator()
        validator.register_evidence(evidence)
        
        # Create compliant claim
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control CC6.1 is implemented",
            assessment_state=AssessmentState.PASS,
            evidence_ids=[evidence.evidence_id],
            reasoning="OWASP ZAP scan detected zero vulnerabilities",
            assessed_at=datetime.now(timezone.utc)
        )
        
        # Validate
        result = validator.validate_claim(claim)
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_full_rejection_workflow(self):
        """Test that invalid claims are properly rejected."""
        validator = AntiHallucinationValidator()
        
        # Create claim without evidence
        claim = ComplianceClaim(
            claim_id="CLM-001",
            control_id="CC6.1",
            statement="Control is likely compliant",  # Weasel word
            assessment_state=AssessmentState.PASS,
            evidence_ids=[],  # No evidence
            reasoning="Assumed based on best practices"  # Also has weasel word
        )
        
        result = validator.validate_claim(claim)
        assert result.is_valid is False
        assert len(result.errors) >= 2  # At least weasel word + missing evidence
    
    def test_provenance_chain_integrity(self):
        """Test full provenance chain from finding to framework."""
        tracker = ProvenanceTracker()
        
        # Add complete chain
        tracker.add_mapping(
            finding_id="FND-XSS-001",
            evidence_id="EVD-ZAP-001",
            control_id="CC6.1",
            framework="SOC2"
        )
        
        # Verify chain
        chain = tracker.get_full_chain("FND-XSS-001")
        assert len(chain) == 1
        assert chain[0]["framework"] == "SOC2"
        
        # Validate completeness
        is_valid, errors = tracker.validate_chain_completeness()
        assert is_valid is True
