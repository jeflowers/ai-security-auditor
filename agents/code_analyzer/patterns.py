"""
Security Patterns for Code Analysis.

Defines regex and AST-based patterns for detecting common vulnerabilities
mapped to CWE identifiers and OWASP Top 10 categories.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Pattern

from .models import (
    FindingSeverity,
    FindingConfidence,
    CWE_TO_OWASP,
    OWASP_TO_SOC2,
)


class PatternType(Enum):
    """Type of pattern matching."""
    REGEX = "regex"
    AST = "ast"
    COMBINED = "combined"


class Language(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GENERIC = "generic"  # Language-agnostic patterns


@dataclass
class SecurityPattern:
    """A security pattern for detecting vulnerabilities."""
    
    # Identification
    pattern_id: str
    name: str
    cwe_id: int
    
    # Classification
    severity: FindingSeverity
    confidence: FindingConfidence
    
    # Pattern definition
    pattern_type: PatternType
    regex: Optional[Pattern] = None
    ast_check: Optional[Callable] = None
    
    # Context
    languages: list[Language] = field(default_factory=lambda: [Language.GENERIC])
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    
    # False positive reduction
    exclude_patterns: list[Pattern] = field(default_factory=list)
    context_required: bool = False  # Requires data flow analysis
    
    @property
    def owasp_category(self) -> str:
        return CWE_TO_OWASP.get(self.cwe_id, "Unknown")
    
    @property
    def soc2_controls(self) -> list[str]:
        return OWASP_TO_SOC2.get(self.owasp_category, ["CC6.6"])
    
    def matches(self, code: str, line_number: int = 0) -> list[dict]:
        """
        Check if pattern matches in code.
        Returns list of match info dicts.
        """
        matches = []
        
        if self.pattern_type in (PatternType.REGEX, PatternType.COMBINED):
            if self.regex:
                for match in self.regex.finditer(code):
                    # Check exclusions
                    excluded = False
                    for exclude in self.exclude_patterns:
                        if exclude.search(match.group(0)):
                            excluded = True
                            break
                    
                    if not excluded:
                        # Calculate line number from match position
                        match_line = code[:match.start()].count('\n') + 1
                        matches.append({
                            "match_text": match.group(0),
                            "start": match.start(),
                            "end": match.end(),
                            "line": match_line + line_number,
                            "groups": match.groups(),
                        })
        
        return matches


# =============================================================================
# SQL Injection Patterns (CWE-89)
# =============================================================================

SQL_INJECTION_PATTERNS = [
    SecurityPattern(
        pattern_id="SQL-001",
        name="SQL Injection via String Concatenation",
        cwe_id=89,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:execute|cursor\.execute|query|raw|rawQuery)\s*\(\s*[f"'].*?'''
            r'''(?:\+|\%|\.format\(|{).*?(?:user|input|request|param|arg|data|query)''',
            re.IGNORECASE | re.DOTALL
        ),
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA],
        description="SQL query constructed using string concatenation with user input.",
        remediation="Use parameterized queries or prepared statements instead of string concatenation.",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    ),
    SecurityPattern(
        pattern_id="SQL-002",
        name="SQL Injection via f-string (Python)",
        cwe_id=89,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:execute|cursor\.execute)\s*\(\s*f["\'].*?'''
            r'''(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?{.*?}''',
            re.IGNORECASE | re.DOTALL
        ),
        languages=[Language.PYTHON],
        description="SQL query using Python f-string with embedded variables.",
        remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
    SecurityPattern(
        pattern_id="SQL-003",
        name="SQL Injection via .format()",
        cwe_id=89,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:execute|query)\s*\(\s*["\'].*?'''
            r'''(?:SELECT|INSERT|UPDATE|DELETE).*?(?:\{\}|%s).*?["\']\.format\(''',
            re.IGNORECASE | re.DOTALL
        ),
        languages=[Language.PYTHON],
        description="SQL query using .format() method for variable interpolation.",
        remediation="Use parameterized queries instead of .format().",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    ),
]


# =============================================================================
# Cross-Site Scripting (XSS) Patterns (CWE-79)
# =============================================================================

XSS_PATTERNS = [
    SecurityPattern(
        pattern_id="XSS-001",
        name="Reflected XSS via innerHTML",
        cwe_id=79,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''\.innerHTML\s*=\s*(?:.*?(?:request|param|query|input|user|data)|'''
            r'''["\'].*?\+.*?(?:request|param|query|input|user|data))''',
            re.IGNORECASE
        ),
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        description="Direct assignment of user input to innerHTML.",
        remediation="Use textContent instead of innerHTML, or sanitize HTML before rendering.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    ),
    SecurityPattern(
        pattern_id="XSS-002",
        name="DOM XSS via document.write",
        cwe_id=79,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''document\.write\s*\(\s*(?:.*?(?:location|document\.URL|document\.referrer|'''
            r'''window\.name|\.search|\.hash)|[^)]*\+[^)]*(?:user|input|param|query))''',
            re.IGNORECASE
        ),
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        description="document.write() called with potentially tainted data.",
        remediation="Avoid document.write(). Use DOM manipulation with sanitized content.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
    SecurityPattern(
        pattern_id="XSS-003",
        name="XSS via Python Jinja2 without escaping",
        cwe_id=79,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''\{\{.*?\|safe\}\}|\{\%\s*autoescape\s+false\s*\%\}''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Jinja2 template disabling auto-escaping or using |safe filter.",
        remediation="Remove |safe filter and ensure autoescape is enabled.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
    SecurityPattern(
        pattern_id="XSS-004",
        name="XSS via dangerouslySetInnerHTML (React)",
        cwe_id=79,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:''',
            re.IGNORECASE
        ),
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        description="React dangerouslySetInnerHTML usage detected.",
        remediation="Sanitize HTML content with DOMPurify before using dangerouslySetInnerHTML.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    ),
]


# =============================================================================
# Command Injection Patterns (CWE-78)
# =============================================================================

COMMAND_INJECTION_PATTERNS = [
    SecurityPattern(
        pattern_id="CMD-001",
        name="OS Command Injection via subprocess",
        cwe_id=78,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(\s*'''
            r'''(?:f["\']|["\'].*?\+|.*?\.format\(|.*?%\s*\()''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Subprocess call with string formatting or concatenation.",
        remediation="Use subprocess with a list of arguments instead of shell string. Set shell=False.",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    ),
    SecurityPattern(
        pattern_id="CMD-002",
        name="OS Command Injection via os.system",
        cwe_id=78,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''os\.(?:system|popen|popen2|popen3|popen4)\s*\(\s*'''
            r'''(?:f["\']|["\'].*?\+|.*?\.format\(|.*?%\s*\()''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="os.system() or os.popen() with user-controlled input.",
        remediation="Use subprocess module with list arguments and shell=False.",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    SecurityPattern(
        pattern_id="CMD-003",
        name="OS Command Injection via shell=True",
        cwe_id=78,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Subprocess with shell=True enables shell injection.",
        remediation="Set shell=False and pass command as a list.",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
    SecurityPattern(
        pattern_id="CMD-004",
        name="Command Injection via child_process (Node.js)",
        cwe_id=78,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`.*?\$\{|'''
            r'''["\'].*?\+|.*?(?:req\.|request\.|params\.|query\.))''',
            re.IGNORECASE
        ),
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        description="child_process function with template literal or concatenation.",
        remediation="Use execFile or spawn with arguments array. Never pass user input to exec().",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    ),
]


# =============================================================================
# Path Traversal Patterns (CWE-22)
# =============================================================================

PATH_TRAVERSAL_PATTERNS = [
    SecurityPattern(
        pattern_id="PATH-001",
        name="Path Traversal via open()",
        cwe_id=22,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''open\s*\(\s*(?:f["\']|["\'].*?\+|.*?\.format\(|'''
            r'''.*?(?:request|param|user|input|arg|query))''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="File open() with potentially user-controlled path.",
        remediation="Validate and sanitize file paths. Use os.path.realpath() and check against allowed directories.",
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    ),
    SecurityPattern(
        pattern_id="PATH-002",
        name="Path Traversal via send_file()",
        cwe_id=22,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''send_file\s*\(\s*(?:f["\']|["\'].*?\+|os\.path\.join\s*\([^)]*'''
            r'''(?:request|param|user|input))''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Flask send_file() with user-controlled path component.",
        remediation="Use send_from_directory() with a fixed base directory.",
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    ),
    SecurityPattern(
        pattern_id="PATH-003",
        name="Path Traversal via fs operations (Node.js)",
        cwe_id=22,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''fs\.(?:readFile|writeFile|readFileSync|writeFileSync|unlink|rmdir)\s*\(\s*'''
            r'''(?:`.*?\$\{|.*?(?:req\.|request\.|params\.|query\.)|.*?\+)''',
            re.IGNORECASE
        ),
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        description="File system operation with user-controlled path.",
        remediation="Use path.resolve() and validate against allowed base directory.",
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    ),
]


# =============================================================================
# Hardcoded Credentials Patterns (CWE-798)
# =============================================================================

HARDCODED_CREDENTIALS_PATTERNS = [
    SecurityPattern(
        pattern_id="CRED-001",
        name="Hardcoded Password",
        cwe_id=798,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:password|passwd|pwd|secret|api_key|apikey|auth_token|'''
            r'''access_token|private_key)\s*[=:]\s*["\'][^"\']{8,}["\']''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="Hardcoded password or secret detected in source code.",
        remediation="Use environment variables or secure secret management (e.g., AWS Secrets Manager, HashiCorp Vault).",
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ],
        exclude_patterns=[
            re.compile(r'''[=:]\s*["\'](?:None|null|undefined|<.*?>|\*+|x+|\.\.\.)["\']''', re.IGNORECASE),
            re.compile(r'''[=:]\s*["\'](?:your|my|example|test|dummy|placeholder)''', re.IGNORECASE),
        ],
    ),
    SecurityPattern(
        pattern_id="CRED-002",
        name="Hardcoded AWS Credentials",
        cwe_id=798,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:AKIA[0-9A-Z]{16}|aws_secret_access_key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\'])''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="AWS access key ID or secret access key in source code.",
        remediation="Remove credentials immediately. Use IAM roles or environment variables.",
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    ),
    SecurityPattern(
        pattern_id="CRED-003",
        name="Hardcoded Private Key",
        cwe_id=798,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="Private key embedded in source code.",
        remediation="Store private keys in secure key management systems, not in code.",
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    ),
    SecurityPattern(
        pattern_id="CRED-004",
        name="Hardcoded JWT Secret",
        cwe_id=798,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:jwt_secret|JWT_SECRET|secret_key|SECRET_KEY)\s*[=:]\s*["\'][^"\']{16,}["\']''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="Hardcoded JWT or session secret.",
        remediation="Use environment variables for secrets.",
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        exclude_patterns=[
            re.compile(r'''[=:]\s*["\'](?:os\.environ|process\.env|config\.)''', re.IGNORECASE),
        ],
    ),
]


# =============================================================================
# Insecure Deserialization Patterns (CWE-502)
# =============================================================================

DESERIALIZATION_PATTERNS = [
    SecurityPattern(
        pattern_id="DESER-001",
        name="Insecure Pickle Deserialization",
        cwe_id=502,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''pickle\.(?:loads?|Unpickler)\s*\(\s*(?:.*?(?:request|input|user|data|file|open)|'''
            r'''[^)]*\.(?:read|recv|get))''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Pickle deserialization of untrusted data can lead to RCE.",
        remediation="Never unpickle untrusted data. Use JSON or other safe formats.",
        references=[
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ],
    ),
    SecurityPattern(
        pattern_id="DESER-002",
        name="Insecure YAML Load",
        cwe_id=502,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''yaml\.(?:load|unsafe_load)\s*\([^)]*(?:Loader\s*=\s*(?:yaml\.)?(?:Loader|UnsafeLoader|FullLoader)|'''
            r'''(?!Loader))''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Unsafe YAML loading can execute arbitrary code.",
        remediation="Use yaml.safe_load() instead of yaml.load().",
        references=[
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    ),
    SecurityPattern(
        pattern_id="DESER-003",
        name="Insecure JSON Deserialization (Java)",
        cwe_id=502,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:ObjectMapper|JsonParser).*?\.(?:readValue|enableDefaultTyping)''',
            re.IGNORECASE | re.DOTALL
        ),
        languages=[Language.JAVA],
        description="Jackson deserialization with default typing enabled.",
        remediation="Disable default typing. Use explicit type handling.",
        references=[
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    ),
]


# =============================================================================
# XML External Entity (XXE) Patterns (CWE-611)
# =============================================================================

XXE_PATTERNS = [
    SecurityPattern(
        pattern_id="XXE-001",
        name="XXE via Python XML Parser",
        cwe_id=611,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.parse\s*\(''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="Python XML parser vulnerable to XXE by default.",
        remediation="Use defusedxml library instead of standard XML parsers.",
        references=[
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    ),
    SecurityPattern(
        pattern_id="XXE-002",
        name="XXE via lxml without safe defaults",
        cwe_id=611,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''lxml\.etree\.(?:parse|fromstring|XML)\s*\([^)]*(?!resolve_entities\s*=\s*False)''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="lxml parser without disabled entity resolution.",
        remediation="Set resolve_entities=False and no_network=True in parser.",
        references=[
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    ),
]


# =============================================================================
# Server-Side Request Forgery (SSRF) Patterns (CWE-918)
# =============================================================================

SSRF_PATTERNS = [
    SecurityPattern(
        pattern_id="SSRF-001",
        name="SSRF via requests library",
        cwe_id=918,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''requests\.(?:get|post|put|delete|patch|head)\s*\(\s*'''
            r'''(?:f["\']|["\'].*?\+|.*?\.format\(|.*?(?:request|param|user|input|url|uri))''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="HTTP request with user-controlled URL.",
        remediation="Validate and whitelist allowed URLs/domains. Block internal IPs.",
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        ],
    ),
    SecurityPattern(
        pattern_id="SSRF-002",
        name="SSRF via urllib",
        cwe_id=918,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''urllib\.request\.(?:urlopen|urlretrieve|Request)\s*\(\s*'''
            r'''(?:f["\']|["\'].*?\+|.*?(?:request|param|user|input|url))''',
            re.IGNORECASE
        ),
        languages=[Language.PYTHON],
        description="urllib request with user-controlled URL.",
        remediation="Validate URLs against whitelist. Block private IP ranges.",
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    ),
    SecurityPattern(
        pattern_id="SSRF-003",
        name="SSRF via fetch/axios (Node.js)",
        cwe_id=918,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*'''
            r'''(?:`.*?\$\{|.*?(?:req\.|request\.|params\.|query\.)|.*?\+)''',
            re.IGNORECASE
        ),
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        description="HTTP request with user-controlled URL.",
        remediation="Validate URLs. Use URL allowlist. Block internal addresses.",
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    ),
]


# =============================================================================
# Weak Cryptography Patterns (CWE-327, CWE-328)
# =============================================================================

WEAK_CRYPTO_PATTERNS = [
    SecurityPattern(
        pattern_id="CRYPTO-001",
        name="Weak Hash Algorithm (MD5)",
        cwe_id=328,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:hashlib\.md5|MD5\.new|MessageDigest\.getInstance\s*\(\s*["\']MD5["\'])''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="MD5 is cryptographically broken and should not be used for security.",
        remediation="Use SHA-256 or stronger hash functions.",
        references=[
            "https://cwe.mitre.org/data/definitions/328.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
    ),
    SecurityPattern(
        pattern_id="CRYPTO-002",
        name="Weak Hash Algorithm (SHA1)",
        cwe_id=328,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:hashlib\.sha1|SHA1\.new|MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\'])''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="SHA-1 is deprecated and vulnerable to collision attacks.",
        remediation="Use SHA-256 or SHA-3.",
        references=[
            "https://cwe.mitre.org/data/definitions/328.html",
        ],
    ),
    SecurityPattern(
        pattern_id="CRYPTO-003",
        name="Insecure Random Number Generator",
        cwe_id=330,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:random\.(?:random|randint|choice|shuffle)|Math\.random\(\))''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="Non-cryptographic random number generator used.",
        remediation="Use secrets module (Python) or crypto.randomBytes (Node.js) for security-sensitive operations.",
        references=[
            "https://cwe.mitre.org/data/definitions/330.html",
        ],
    ),
]


# =============================================================================
# Logging Sensitive Data Patterns (CWE-532)
# =============================================================================

LOGGING_PATTERNS = [
    SecurityPattern(
        pattern_id="LOG-001",
        name="Logging Sensitive Data",
        cwe_id=532,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        pattern_type=PatternType.REGEX,
        regex=re.compile(
            r'''(?:logger?|logging|console|print)\s*\.?\s*(?:info|debug|warn|error|log)?\s*\(\s*'''
            r'''.*?(?:password|secret|token|key|credential|ssn|credit.?card)''',
            re.IGNORECASE
        ),
        languages=[Language.GENERIC],
        description="Potentially logging sensitive information.",
        remediation="Mask or redact sensitive data before logging.",
        references=[
            "https://cwe.mitre.org/data/definitions/532.html",
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        ],
    ),
]


# =============================================================================
# Combined Pattern Registry
# =============================================================================

SECURITY_PATTERNS: list[SecurityPattern] = [
    *SQL_INJECTION_PATTERNS,
    *XSS_PATTERNS,
    *COMMAND_INJECTION_PATTERNS,
    *PATH_TRAVERSAL_PATTERNS,
    *HARDCODED_CREDENTIALS_PATTERNS,
    *DESERIALIZATION_PATTERNS,
    *XXE_PATTERNS,
    *SSRF_PATTERNS,
    *WEAK_CRYPTO_PATTERNS,
    *LOGGING_PATTERNS,
]


def get_patterns_by_cwe(cwe_id: int) -> list[SecurityPattern]:
    """Get all patterns for a specific CWE ID."""
    return [p for p in SECURITY_PATTERNS if p.cwe_id == cwe_id]


def get_patterns_by_owasp(owasp_category: str) -> list[SecurityPattern]:
    """Get all patterns for an OWASP Top 10 category."""
    return [p for p in SECURITY_PATTERNS if p.owasp_category == owasp_category]


def get_patterns_by_language(language: Language) -> list[SecurityPattern]:
    """Get all patterns applicable to a specific language."""
    return [
        p for p in SECURITY_PATTERNS 
        if language in p.languages or Language.GENERIC in p.languages
    ]


def get_patterns_by_severity(min_severity: FindingSeverity) -> list[SecurityPattern]:
    """Get patterns with at least the specified severity."""
    severity_order = [
        FindingSeverity.INFO,
        FindingSeverity.LOW,
        FindingSeverity.MEDIUM,
        FindingSeverity.HIGH,
        FindingSeverity.CRITICAL,
    ]
    min_idx = severity_order.index(min_severity)
    return [
        p for p in SECURITY_PATTERNS
        if severity_order.index(p.severity) >= min_idx
    ]
