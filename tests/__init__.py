"""
AI-Powered Security Auditor Test Suite

Test packages:
- test_code_analyzer: Code security analysis tests
- test_log_analyzer: Log analysis tests  
- test_compliance_checker: Compliance assessment tests
- test_rag_pipeline: RAG pipeline tests
- test_orchestrator: Workflow orchestration tests

Run all tests:
    pytest tests/ -v

Run with coverage:
    pytest tests/ --cov=agents --cov-report=html

Run specific test file:
    pytest tests/test_code_analyzer.py -v
"""

# Test suite configuration
TEST_EVIDENCE_DIR = "tests/fixtures/evidence"
TEST_LOGS_DIR = "tests/fixtures/logs"
TEST_CODE_DIR = "tests/fixtures/code"
