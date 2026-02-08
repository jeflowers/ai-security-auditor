"""
Code Parser for extracting AST information and code context.

Supports Python AST parsing and regex-based parsing for other languages.
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Iterator


@dataclass
class FunctionInfo:
    """Information about a function definition."""
    name: str
    line_number: int
    end_line: int
    class_name: Optional[str] = None
    args: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)  # Functions called within
    

@dataclass
class ImportInfo:
    """Information about an import statement."""
    module: str
    names: list[str]
    line_number: int
    is_from_import: bool = False


@dataclass
class StringLiteral:
    """A string literal found in code."""
    value: str
    line_number: int
    column: int
    in_function: Optional[str] = None
    in_class: Optional[str] = None


@dataclass
class ParseResult:
    """Result of parsing a source file."""
    file_path: str
    language: str
    lines_of_code: int
    
    functions: list[FunctionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    strings: list[StringLiteral] = field(default_factory=list)
    
    # For taint tracking
    variables: dict[str, list[int]] = field(default_factory=dict)  # var -> line numbers
    
    errors: list[str] = field(default_factory=list)


class PythonASTParser:
    """Python-specific AST parser."""
    
    def __init__(self):
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None
    
    def parse(self, code: str, file_path: str = "<string>") -> ParseResult:
        """Parse Python code and extract information."""
        result = ParseResult(
            file_path=file_path,
            language="python",
            lines_of_code=len(code.splitlines()),
        )
        
        try:
            tree = ast.parse(code)
            self._visit_module(tree, result, code)
        except SyntaxError as e:
            result.errors.append(f"Syntax error: {e}")
        except Exception as e:
            result.errors.append(f"Parse error: {e}")
        
        return result
    
    def _visit_module(self, tree: ast.Module, result: ParseResult, code: str):
        """Visit all nodes in the module."""
        # Process top-level nodes only to avoid duplicates
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                self._handle_function(node, result)
            elif isinstance(node, ast.ClassDef):
                self._handle_class(node, result)
            elif isinstance(node, ast.Import):
                self._handle_import(node, result)
            elif isinstance(node, ast.ImportFrom):
                self._handle_import_from(node, result)
            elif isinstance(node, ast.Assign):
                self._handle_assignment(node, result)
        
        # Use ast.walk for strings and nested assignments (they don't cause duplicates)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self._handle_string(node, result)
            elif isinstance(node, ast.Assign) and node not in tree.body:
                self._handle_assignment(node, result)
    
    def _handle_function(
        self, 
        node: ast.FunctionDef | ast.AsyncFunctionDef, 
        result: ParseResult
    ):
        """Extract function information."""
        # Get function calls within this function
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    calls.append(call_name)
        
        func_info = FunctionInfo(
            name=node.name,
            line_number=node.lineno,
            end_line=node.end_lineno or node.lineno,
            class_name=self.current_class,
            args=[arg.arg for arg in node.args.args],
            decorators=[self._get_decorator_name(d) for d in node.decorator_list],
            calls=calls,
        )
        result.functions.append(func_info)
    
    def _handle_class(self, node: ast.ClassDef, result: ParseResult):
        """Track class context."""
        old_class = self.current_class
        self.current_class = node.name
        
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._handle_function(child, result)
        
        self.current_class = old_class
    
    def _handle_import(self, node: ast.Import, result: ParseResult):
        """Extract import information."""
        for alias in node.names:
            result.imports.append(ImportInfo(
                module=alias.name,
                names=[alias.asname or alias.name],
                line_number=node.lineno,
                is_from_import=False,
            ))
    
    def _handle_import_from(self, node: ast.ImportFrom, result: ParseResult):
        """Extract from-import information."""
        module = node.module or ""
        names = [alias.name for alias in node.names]
        result.imports.append(ImportInfo(
            module=module,
            names=names,
            line_number=node.lineno,
            is_from_import=True,
        ))
    
    def _handle_string(self, node: ast.Constant, result: ParseResult):
        """Extract string literal information."""
        result.strings.append(StringLiteral(
            value=str(node.value),
            line_number=node.lineno,
            column=node.col_offset,
            in_function=self.current_function,
            in_class=self.current_class,
        ))
    
    def _handle_assignment(self, node: ast.Assign, result: ParseResult):
        """Track variable assignments for taint analysis."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name not in result.variables:
                    result.variables[var_name] = []
                result.variables[var_name].append(node.lineno)
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None
    
    def _get_decorator_name(self, node: ast.expr) -> str:
        """Get decorator name."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_call_name(ast.Call(func=node, args=[], keywords=[]))
        elif isinstance(node, ast.Call):
            return self._get_call_name(node) or ""
        return ""


class GenericParser:
    """Generic regex-based parser for languages without AST support."""
    
    # Language-specific patterns
    FUNCTION_PATTERNS = {
        "javascript": re.compile(
            r'''(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?'''
            r'''(?:function|\([^)]*\)\s*=>|\w+\s*=>))''',
            re.MULTILINE
        ),
        "typescript": re.compile(
            r'''(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*'''
            r'''(?:async\s+)?(?:function|\([^)]*\)\s*=>))''',
            re.MULTILINE
        ),
        "java": re.compile(
            r'''(?:public|private|protected)?\s*(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(''',
            re.MULTILINE
        ),
    }
    
    STRING_PATTERNS = {
        "javascript": re.compile(r'''(?:"[^"]*"|'[^']*'|`[^`]*`)'''),
        "typescript": re.compile(r'''(?:"[^"]*"|'[^']*'|`[^`]*`)'''),
        "java": re.compile(r'''"[^"]*"'''),
    }
    
    IMPORT_PATTERNS = {
        "javascript": re.compile(
            r'''(?:import\s+(?:\{[^}]+\}|\*\s+as\s+\w+|\w+)\s+from\s+["\']([^"\']+)["\']|'''
            r'''require\s*\(\s*["\']([^"\']+)["\']\s*\))''',
            re.MULTILINE
        ),
        "typescript": re.compile(
            r'''import\s+(?:\{[^}]+\}|\*\s+as\s+\w+|\w+)\s+from\s+["\']([^"\']+)["\']''',
            re.MULTILINE
        ),
        "java": re.compile(
            r'''import\s+(?:static\s+)?([a-zA-Z_][\w.]*(?:\.\*)?)\s*;''',
            re.MULTILINE
        ),
    }
    
    def parse(self, code: str, language: str, file_path: str = "<string>") -> ParseResult:
        """Parse code using regex patterns."""
        result = ParseResult(
            file_path=file_path,
            language=language,
            lines_of_code=len(code.splitlines()),
        )
        
        # Extract functions
        if language in self.FUNCTION_PATTERNS:
            pattern = self.FUNCTION_PATTERNS[language]
            for match in pattern.finditer(code):
                name = match.group(1) or match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(1)
                if name:
                    line_num = code[:match.start()].count('\n') + 1
                    result.functions.append(FunctionInfo(
                        name=name,
                        line_number=line_num,
                        end_line=line_num,  # Can't determine without full parsing
                    ))
        
        # Extract imports
        if language in self.IMPORT_PATTERNS:
            pattern = self.IMPORT_PATTERNS[language]
            for match in pattern.finditer(code):
                module = match.group(1) or (match.group(2) if match.lastindex and match.lastindex >= 2 else "")
                if module:
                    line_num = code[:match.start()].count('\n') + 1
                    result.imports.append(ImportInfo(
                        module=module,
                        names=[],
                        line_number=line_num,
                    ))
        
        # Extract strings
        if language in self.STRING_PATTERNS:
            pattern = self.STRING_PATTERNS[language]
            for match in pattern.finditer(code):
                line_num = code[:match.start()].count('\n') + 1
                result.strings.append(StringLiteral(
                    value=match.group(0),
                    line_number=line_num,
                    column=match.start() - code.rfind('\n', 0, match.start()) - 1,
                ))
        
        return result


class CodeParser:
    """Unified code parser supporting multiple languages."""
    
    LANGUAGE_EXTENSIONS = {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
    }
    
    def __init__(self):
        self.python_parser = PythonASTParser()
        self.generic_parser = GenericParser()
    
    def detect_language(self, file_path: str) -> str:
        """Detect language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.LANGUAGE_EXTENSIONS.get(ext, "unknown")
    
    def parse(
        self, 
        code: str, 
        file_path: str = "<string>",
        language: Optional[str] = None
    ) -> ParseResult:
        """Parse code and return extracted information."""
        if language is None:
            language = self.detect_language(file_path)
        
        if language == "python":
            return self.python_parser.parse(code, file_path)
        elif language in ("javascript", "typescript", "java"):
            return self.generic_parser.parse(code, language, file_path)
        else:
            # Return basic result for unknown languages
            return ParseResult(
                file_path=file_path,
                language=language,
                lines_of_code=len(code.splitlines()),
            )
    
    def parse_file(self, file_path: str) -> ParseResult:
        """Parse a file from disk."""
        path = Path(file_path)
        if not path.exists():
            result = ParseResult(
                file_path=file_path,
                language="unknown",
                lines_of_code=0,
            )
            result.errors.append(f"File not found: {file_path}")
            return result
        
        try:
            code = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                code = path.read_text(encoding="latin-1")
            except Exception as e:
                result = ParseResult(
                    file_path=file_path,
                    language=self.detect_language(file_path),
                    lines_of_code=0,
                )
                result.errors.append(f"Failed to read file: {e}")
                return result
        
        return self.parse(code, file_path)
    
    def get_code_context(
        self, 
        code: str, 
        line_number: int, 
        context_lines: int = 3
    ) -> str:
        """Get code snippet around a specific line."""
        lines = code.splitlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context_lines_list = []
        for i, line in enumerate(lines[start:end], start=start + 1):
            marker = ">>>" if i == line_number else "   "
            context_lines_list.append(f"{marker} {i:4d} | {line}")
        
        return "\n".join(context_lines_list)
    
    def find_function_at_line(
        self, 
        parse_result: ParseResult, 
        line_number: int
    ) -> Optional[FunctionInfo]:
        """Find which function contains a given line."""
        for func in parse_result.functions:
            if func.line_number <= line_number <= func.end_line:
                return func
        return None
