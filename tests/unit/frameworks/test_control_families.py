"""
Unit tests for NIST 800-53A control family structure.

Tests cover:
- Control family organization
- Control hierarchy (parent/enhancement)
- Baseline assignments
- Agent mappings
- Family metadata

Total: 15 tests
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.utils.framework_helpers import (
    get_nested_value,
    extract_control_ids,
)


class TestControlFamilyOrganization:
    """Tests for control family organization."""
    
    def test_ac_family_metadata(self, ac_controls_yaml):
        """Test AC family has correct metadata."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        family = ac_controls_yaml.get('family', {})
        
        assert family.get('id') == 'AC'
        assert family.get('name') == 'Access Control'
        assert 'description' in family
        assert family.get('automation_level') == 'full'
    
    def test_au_family_metadata(self, au_controls_yaml):
        """Test AU family has correct metadata."""
        if au_controls_yaml is None:
            pytest.skip("au.yaml not available")
        
        family = au_controls_yaml.get('family', {})
        
        assert family.get('id') == 'AU'
        assert family.get('name') == 'Audit and Accountability'
        assert 'description' in family
        assert family.get('automation_level') == 'full'
    
    def test_ra_family_metadata(self, ra_si_controls_yaml):
        """Test RA family has correct metadata."""
        if ra_si_controls_yaml is None:
            pytest.skip("ra-si.yaml not available")
        
        family = ra_si_controls_yaml.get('ra_family', {})
        
        assert family.get('id') == 'RA'
        assert family.get('name') == 'Risk Assessment'
        assert family.get('automation_level') == 'full'
    
    def test_si_family_metadata(self, ra_si_controls_yaml):
        """Test SI family has correct metadata."""
        if ra_si_controls_yaml is None:
            pytest.skip("ra-si.yaml not available")
        
        family = ra_si_controls_yaml.get('si_family', {})
        
        assert family.get('id') == 'SI'
        assert family.get('name') == 'System and Information Integrity'
        assert family.get('automation_level') == 'full'


class TestControlHierarchy:
    """Tests for control hierarchy (base controls and enhancements)."""
    
    def test_ac_controls_follow_naming_convention(self, ac_controls_yaml):
        """Test AC controls follow AC-X or AC-X.Y naming convention."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        import re
        control_pattern = re.compile(r'^AC-\d+(\.\d+)?$')
        
        controls = ac_controls_yaml.get('controls', {})
        for control_id in controls.keys():
            assert control_pattern.match(control_id), f"Invalid control ID format: {control_id}"
    
    def test_au_controls_follow_naming_convention(self, au_controls_yaml):
        """Test AU controls follow AU-X or AU-X.Y naming convention."""
        if au_controls_yaml is None:
            pytest.skip("au.yaml not available")
        
        import re
        control_pattern = re.compile(r'^AU-\d+(\.\d+)?$')
        
        controls = au_controls_yaml.get('controls', {})
        for control_id in controls.keys():
            assert control_pattern.match(control_id), f"Invalid control ID format: {control_id}"
    
    def test_ra_controls_follow_naming_convention(self, ra_si_controls_yaml):
        """Test RA controls follow RA-X or RA-X.Y naming convention."""
        if ra_si_controls_yaml is None:
            pytest.skip("ra-si.yaml not available")
        
        import re
        control_pattern = re.compile(r'^RA-\d+(\.\d+)?$')
        
        controls = ra_si_controls_yaml.get('ra_controls', {})
        for control_id in controls.keys():
            assert control_pattern.match(control_id), f"Invalid control ID format: {control_id}"
    
    def test_si_controls_follow_naming_convention(self, ra_si_controls_yaml):
        """Test SI controls follow SI-X or SI-X.Y naming convention."""
        if ra_si_controls_yaml is None:
            pytest.skip("ra-si.yaml not available")
        
        import re
        control_pattern = re.compile(r'^SI-\d+(\.\d+)?$')
        
        controls = ra_si_controls_yaml.get('si_controls', {})
        for control_id in controls.keys():
            assert control_pattern.match(control_id), f"Invalid control ID format: {control_id}"


class TestBaselineAssignments:
    """Tests for FedRAMP baseline assignments."""
    
    def test_ac_controls_have_baseline(self, ac_controls_yaml, fedramp_baselines):
        """Test all AC controls have baseline assignments."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            baseline = control.get('baseline', [])
            assert len(baseline) > 0, f"{control_id} missing baseline assignment"
            for level in baseline:
                assert level in fedramp_baselines, f"Invalid baseline '{level}' in {control_id}"
    
    def test_low_baseline_controls_exist(self, ac_controls_yaml):
        """Test controls assigned to low baseline exist."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        low_baseline_controls = [
            cid for cid, ctrl in controls.items()
            if 'low' in ctrl.get('baseline', [])
        ]
        
        assert len(low_baseline_controls) > 0, "No controls assigned to low baseline"
    
    def test_moderate_baseline_includes_low(self, ac_controls_yaml):
        """Test moderate baseline includes all low baseline controls."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            baseline = control.get('baseline', [])
            if 'low' in baseline:
                # Low baseline controls should also be in moderate
                assert 'moderate' in baseline or 'high' in baseline, \
                    f"{control_id} is in low but not in moderate/high baseline"


class TestAgentMappings:
    """Tests for agent mappings in control families."""
    
    def test_ac_family_primary_agents(self, ac_controls_yaml):
        """Test AC family has correct primary agents."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        family = ac_controls_yaml.get('family', {})
        primary_agents = family.get('primary_agents', [])
        
        assert 'code_analyzer' in primary_agents
        assert 'compliance_checker' in primary_agents
    
    def test_au_family_primary_agents(self, au_controls_yaml):
        """Test AU family has correct primary agents."""
        if au_controls_yaml is None:
            pytest.skip("au.yaml not available")
        
        family = au_controls_yaml.get('family', {})
        primary_agents = family.get('primary_agents', [])
        
        assert 'log_analyzer' in primary_agents
        assert 'compliance_checker' in primary_agents
    
    def test_ra_family_primary_agents(self, ra_si_controls_yaml):
        """Test RA family has correct primary agents."""
        if ra_si_controls_yaml is None:
            pytest.skip("ra-si.yaml not available")
        
        family = ra_si_controls_yaml.get('ra_family', {})
        primary_agents = family.get('primary_agents', [])
        
        assert 'vulnerability_scanner' in primary_agents
    
    def test_objectives_reference_valid_agents(self, ac_controls_yaml):
        """Test assessment objectives reference valid agents."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        valid_agents = ['code_analyzer', 'log_analyzer', 'vulnerability_scanner', 'compliance_checker']
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            for objective in control.get('assessment_objectives', []):
                if 'agent' in objective:
                    assert objective['agent'] in valid_agents, \
                        f"Invalid agent '{objective['agent']}' in {objective.get('id')}"
