"""
Unit tests for NIST 800-53A framework schema validation.

Tests cover:
- Framework metadata schema
- Assessment methodology schema
- Control family schema
- Control structure schema
- Evidence requirements schema
- Data type validation
- Relationship validation

Total: 18 tests
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.utils.framework_helpers import (
    validate_yaml_structure,
    get_nested_value,
    validate_control_structure,
    validate_assessment_objective,
)


class TestFrameworkMetadataSchema:
    """Tests for framework metadata schema validation."""
    
    def test_framework_has_id(self, framework_yaml):
        """Test framework has required ID field."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        framework_id = get_nested_value(framework_yaml, 'framework.id')
        assert framework_id is not None
        assert framework_id == 'nist800-53a'
    
    def test_framework_has_name(self, framework_yaml):
        """Test framework has required name field."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        name = get_nested_value(framework_yaml, 'framework.name')
        assert name is not None
        assert 'NIST' in name or '800-53' in name
    
    def test_framework_has_version(self, framework_yaml):
        """Test framework has required version field."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        version = get_nested_value(framework_yaml, 'framework.version')
        assert version is not None
    
    def test_framework_has_description(self, framework_yaml):
        """Test framework has description field."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        description = get_nested_value(framework_yaml, 'framework.description')
        assert description is not None
        assert len(description) > 0


class TestAssessmentMethodologySchema:
    """Tests for assessment methodology schema validation."""
    
    def test_assessment_methods_exist(self, framework_yaml):
        """Test assessment methods are defined."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        methods = get_nested_value(framework_yaml, 'assessment.methods')
        assert methods is not None
        assert isinstance(methods, list)
        assert len(methods) > 0
    
    def test_assessment_method_has_required_fields(self, framework_yaml, nist_assessment_methods):
        """Test each assessment method has required fields."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        methods = get_nested_value(framework_yaml, 'assessment.methods', [])
        
        for method in methods:
            assert 'id' in method, "Method missing 'id'"
            assert 'name' in method, "Method missing 'name'"
            assert 'description' in method, "Method missing 'description'"
            assert method['id'] in nist_assessment_methods, f"Invalid method: {method['id']}"
    
    def test_depth_levels_defined(self, framework_yaml, nist_depth_levels):
        """Test depth levels are properly defined."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        depth_levels = get_nested_value(framework_yaml, 'assessment.depth_levels', [])
        
        level_ids = [level['id'] for level in depth_levels]
        for expected_level in nist_depth_levels:
            assert expected_level in level_ids, f"Missing depth level: {expected_level}"
    
    def test_coverage_levels_defined(self, framework_yaml):
        """Test coverage levels are properly defined."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        coverage_levels = get_nested_value(framework_yaml, 'assessment.coverage_levels', [])
        assert len(coverage_levels) > 0


class TestControlFamilySchema:
    """Tests for control family schema validation."""
    
    def test_control_families_is_list(self, framework_yaml):
        """Test control_families is a list."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        families = get_nested_value(framework_yaml, 'control_families')
        assert families is not None
        assert isinstance(families, list)
    
    def test_control_family_has_required_fields(self, framework_yaml):
        """Test each control family has required fields."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        families = get_nested_value(framework_yaml, 'control_families', [])
        
        for family in families:
            assert 'id' in family, f"Family missing 'id'"
            assert 'name' in family, f"Family missing 'name'"
            assert 'automation_level' in family, f"Family {family.get('id', 'unknown')} missing 'automation_level'"
    
    def test_required_families_present(self, framework_yaml):
        """Test required control families (AC, AU, RA, SI) are present."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        families = get_nested_value(framework_yaml, 'control_families', [])
        family_ids = [f['id'] for f in families]
        
        required_families = ['AC', 'AU', 'RA', 'SI']
        for required in required_families:
            assert required in family_ids, f"Missing required family: {required}"
    
    def test_automation_level_valid_values(self, framework_yaml):
        """Test automation_level has valid values."""
        if framework_yaml is None:
            pytest.skip("framework.yaml not available")
        
        valid_levels = ['full', 'partial', 'documentation', 'none']
        families = get_nested_value(framework_yaml, 'control_families', [])
        
        for family in families:
            level = family.get('automation_level')
            assert level in valid_levels, f"Invalid automation_level '{level}' for family {family.get('id')}"


class TestControlStructureSchema:
    """Tests for individual control structure validation."""
    
    def test_ac_control_structure(self, ac_controls_yaml):
        """Test AC control structure is valid."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        assert len(controls) > 0, "No controls found in AC family"
        
        for control_id, control in controls.items():
            is_valid, issues = validate_control_structure(control)
            assert is_valid, f"Control {control_id} has issues: {issues}"
    
    def test_au_control_structure(self, au_controls_yaml):
        """Test AU control structure is valid."""
        if au_controls_yaml is None:
            pytest.skip("au.yaml not available")
        
        controls = au_controls_yaml.get('controls', {})
        assert len(controls) > 0, "No controls found in AU family"
        
        for control_id, control in controls.items():
            is_valid, issues = validate_control_structure(control)
            assert is_valid, f"Control {control_id} has issues: {issues}"
    
    def test_assessment_objective_structure(self, ac_controls_yaml):
        """Test assessment objectives have valid structure."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            for objective in control.get('assessment_objectives', []):
                is_valid, issues = validate_assessment_objective(objective)
                assert is_valid, f"Objective {objective.get('id', 'unknown')} in {control_id} has issues: {issues}"


class TestDataTypeValidation:
    """Tests for data type validation in schemas."""
    
    def test_baseline_is_list_of_strings(self, ac_controls_yaml, fedramp_baselines):
        """Test baseline field contains valid baseline values."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            baseline = control.get('baseline', [])
            assert isinstance(baseline, list), f"{control_id} baseline is not a list"
            for value in baseline:
                assert value in fedramp_baselines, f"Invalid baseline '{value}' in {control_id}"
    
    def test_objects_is_list_of_strings(self, ac_controls_yaml):
        """Test objects field is a list of strings."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            for objective in control.get('assessment_objectives', []):
                objects = objective.get('objects', [])
                assert isinstance(objects, list), f"Objects in {objective.get('id')} is not a list"
                for obj in objects:
                    assert isinstance(obj, str), f"Object in {objective.get('id')} is not a string"
    
    def test_automated_is_boolean_or_string(self, ac_controls_yaml):
        """Test automated field is boolean or valid string."""
        if ac_controls_yaml is None:
            pytest.skip("ac.yaml not available")
        
        valid_values = [True, False, 'partial']
        controls = ac_controls_yaml.get('controls', {})
        
        for control_id, control in controls.items():
            for objective in control.get('assessment_objectives', []):
                if 'automated' in objective:
                    value = objective['automated']
                    assert value in valid_values, f"Invalid automated value '{value}' in {objective.get('id')}"
