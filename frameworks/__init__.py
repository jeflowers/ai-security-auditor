"""
Compliance Frameworks for AI-Powered Security Auditor

Supported frameworks:
- SOC 2 Trust Services Criteria
- GDPR (General Data Protection Regulation)
- HIPAA Security Rule

Each framework provides:
- Control definitions with evidence requirements
- CWE/OWASP to control mappings
- Scoring rubrics with anti-hallucination rules
- Assessment state validation

Usage:
    from frameworks import load_framework, get_available_frameworks
    
    # List available frameworks
    frameworks = get_available_frameworks()
    
    # Load a specific framework
    soc2 = load_framework("soc2")
    gdpr = load_framework("gdpr")
    hipaa = load_framework("hipaa")
"""

from pathlib import Path
from typing import Any

# Framework directory
FRAMEWORKS_DIR = Path(__file__).parent


def get_available_frameworks() -> list[str]:
    """
    Get list of available compliance frameworks.
    
    Returns:
        List of framework identifiers (e.g., ['soc2', 'gdpr', 'hipaa'])
    """
    frameworks = []
    for item in FRAMEWORKS_DIR.iterdir():
        if item.is_dir() and not item.name.startswith(('__', '.')):
            controls_file = item / "controls.yaml"
            if controls_file.exists():
                frameworks.append(item.name)
    return sorted(frameworks)


def load_framework(framework_id: str) -> Any:
    """
    Load a compliance framework by ID.
    
    Args:
        framework_id: Framework identifier (soc2, gdpr, hipaa)
    
    Returns:
        Framework class instance
    
    Raises:
        ValueError: If framework not found
    """
    framework_id = framework_id.lower()
    
    if framework_id == "soc2":
        from .soc2 import SOC2Framework
        return SOC2Framework()
    elif framework_id == "gdpr":
        from .gdpr import GDPRFramework
        return GDPRFramework()
    elif framework_id == "hipaa":
        from .hipaa import HIPAAFramework
        return HIPAAFramework()
    else:
        available = get_available_frameworks()
        raise ValueError(
            f"Unknown framework: {framework_id}. "
            f"Available frameworks: {available}"
        )


def get_framework_path(framework_id: str) -> Path:
    """
    Get the path to a framework's directory.
    
    Args:
        framework_id: Framework identifier
    
    Returns:
        Path to framework directory
    
    Raises:
        ValueError: If framework not found
    """
    framework_path = FRAMEWORKS_DIR / framework_id.lower()
    if not framework_path.exists():
        raise ValueError(f"Framework directory not found: {framework_path}")
    return framework_path


__all__ = [
    "get_available_frameworks",
    "load_framework",
    "get_framework_path",
    "FRAMEWORKS_DIR",
]
