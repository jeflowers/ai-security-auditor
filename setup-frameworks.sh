#!/bin/bash
# SOC 2 Framework Setup Script
# AI-Powered Security Auditor - Organize Framework Files
# 
# This script organizes the compliance framework files into the proper
# directory structure for the Security Auditor project.
#
# Usage: ./setup-frameworks.sh [project_root]
#
# Directory structure after running:
#   frameworks/
#   ├── nist800-53a/
#   │   ├── framework.yaml       # Main NIST 800-53A config
#   │   ├── ac.yaml             # Access Control family
#   │   ├── au.yaml             # Audit and Accountability family
#   │   └── ra-si.yaml          # Risk Assessment & System Integrity
#   └── soc2/
#       ├── soc2-mapping.yaml   # SOC 2 to NIST mapping
#       ├── soc2-report-types.yaml    # Type 1/Type 2 methodology
#       └── soc2-testing-matrix.yaml  # Control testing specs

set -e  # Exit on error

# Default project root
PROJECT_ROOT="${1:-.}"

echo "======================================"
echo "SOC 2 Framework Setup Script"
echo "======================================"
echo ""
echo "Project root: $PROJECT_ROOT"
echo ""

# Validate project root
if [ ! -d "$PROJECT_ROOT" ]; then
    echo "ERROR: Project root '$PROJECT_ROOT' does not exist"
    exit 1
fi

# Create framework directories
echo "[1/5] Creating framework directories..."
mkdir -p "$PROJECT_ROOT/frameworks/nist800-53a"
mkdir -p "$PROJECT_ROOT/frameworks/soc2"
echo "      ✓ Created frameworks/nist800-53a/"
echo "      ✓ Created frameworks/soc2/"

# Move NIST 800-53A files
echo ""
echo "[2/5] Organizing NIST 800-53A files..."

# Check for files in project root or current location
for file in framework.yaml ac.yaml au.yaml ra-si.yaml; do
    if [ -f "$PROJECT_ROOT/$file" ]; then
        mv "$PROJECT_ROOT/$file" "$PROJECT_ROOT/frameworks/nist800-53a/"
        echo "      ✓ Moved $file → frameworks/nist800-53a/"
    elif [ -f "$PROJECT_ROOT/frameworks/nist800-53a/$file" ]; then
        echo "      - $file already in place"
    else
        echo "      ! $file not found (may need manual copy)"
    fi
done

# Move SOC 2 mapping file
echo ""
echo "[3/5] Organizing SOC 2 mapping file..."
if [ -f "$PROJECT_ROOT/soc2-mapping.yaml" ]; then
    mv "$PROJECT_ROOT/soc2-mapping.yaml" "$PROJECT_ROOT/frameworks/soc2/"
    echo "      ✓ Moved soc2-mapping.yaml → frameworks/soc2/"
elif [ -f "$PROJECT_ROOT/frameworks/soc2/soc2-mapping.yaml" ]; then
    echo "      - soc2-mapping.yaml already in place"
else
    echo "      ! soc2-mapping.yaml not found (may need manual copy)"
fi

# Copy new SOC 2 Type 1/Type 2 files
echo ""
echo "[4/5] Adding SOC 2 Type 1/Type 2 framework files..."

# These files should be in the same directory as this script or specified location
SCRIPT_DIR="$(dirname "$0")"

for file in soc2-report-types.yaml soc2-testing-matrix.yaml; do
    if [ -f "$SCRIPT_DIR/$file" ]; then
        cp "$SCRIPT_DIR/$file" "$PROJECT_ROOT/frameworks/soc2/"
        echo "      ✓ Copied $file → frameworks/soc2/"
    elif [ -f "$PROJECT_ROOT/frameworks/soc2/$file" ]; then
        echo "      - $file already in place"
    else
        echo "      ! $file not found in $SCRIPT_DIR"
    fi
done

# Display final structure
echo ""
echo "[5/5] Verifying framework structure..."
echo ""
echo "Framework directory structure:"
echo "────────────────────────────────"

if command -v tree &> /dev/null; then
    tree "$PROJECT_ROOT/frameworks" 2>/dev/null || find "$PROJECT_ROOT/frameworks" -type f | sort
else
    find "$PROJECT_ROOT/frameworks" -type f | sort | while read f; do
        echo "  $f"
    done
fi

echo ""
echo "======================================"
echo "Framework setup complete!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Update agents/compliance_checker/agent.py to load from frameworks/"
echo "  2. Update orchestrator.py with report type selection"
echo "  3. Run tests: pytest tests/ -v"
echo ""
echo "Framework file summary:"
echo "  • NIST 800-53A: AC, AU, RA, SI control families"
echo "  • SOC 2: Type 1 and Type 2 assessment methodology"
echo "  • Cross-mapping: SOC 2 ↔ NIST control alignment"
echo ""
