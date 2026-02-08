"""
Log Parsers for different log formats.

Supports syslog, JSON, Apache/Nginx access logs, and generic formats.
"""

import re
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Any

from .models import LogEntry, LogLevel


@dataclass
class ParseResult:
    """Result of parsing a log file."""
    entries: list[LogEntry]
    format_detected: str
    total_lines: int
    parsed_lines: int
    errors: list[str]
    
    @property
    def success_rate(self) -> float:
        """Percentage of successfully parsed lines."""
        if self.total_lines == 0:
            return 0.0
        return (self.parsed_lines / self.total_lines) * 100


class LogParser(ABC):
    """Abstract base class for log parsers."""
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int = 0) -> Optional[LogEntry]:
        """Parse a single log line."""
        pass
    
    @abstractmethod
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Check if this parser can handle the log format."""
        pass
    
    def parse_file(self, file_path: str | Path) -> ParseResult:
        """Parse an entire log file."""
        path = Path(file_path)
        entries: list[LogEntry] = []
        errors: list[str] = []
        total_lines = 0
        parsed_lines = 0
        
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    total_lines += 1
                    line = line.rstrip('\n\r')
                    if not line.strip():
                        continue
                    
                    try:
                        entry = self.parse_line(line, line_num)
                        if entry:
                            entry.file_path = str(path)
                            entries.append(entry)
                            parsed_lines += 1
                    except Exception as e:
                        errors.append(f"Line {line_num}: {e}")
        except Exception as e:
            errors.append(f"File error: {e}")
        
        return ParseResult(
            entries=entries,
            format_detected=self.__class__.__name__,
            total_lines=total_lines,
            parsed_lines=parsed_lines,
            errors=errors,
        )
    
    def parse_string(self, content: str) -> ParseResult:
        """Parse log content from a string."""
        lines = content.splitlines()
        entries: list[LogEntry] = []
        errors: list[str] = []
        parsed_lines = 0
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            try:
                entry = self.parse_line(line, line_num)
                if entry:
                    entries.append(entry)
                    parsed_lines += 1
            except Exception as e:
                errors.append(f"Line {line_num}: {e}")
        
        return ParseResult(
            entries=entries,
            format_detected=self.__class__.__name__,
            total_lines=len(lines),
            parsed_lines=parsed_lines,
            errors=errors,
        )


class SyslogParser(LogParser):
    """Parser for syslog format (RFC 3164 and RFC 5424)."""
    
    # RFC 3164: <priority>timestamp hostname program[pid]: message
    # Example: Dec 31 10:30:45 myhost sshd[1234]: Failed password for user
    RFC3164_PATTERN = re.compile(
        r'^(?:<(\d+)>)?'  # Optional priority
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
        r'(\S+)\s+'  # Hostname
        r'(\S+?)(?:\[(\d+)\])?:\s*'  # Program and optional PID
        r'(.*)$'  # Message
    )
    
    # RFC 5424: <priority>version timestamp hostname app-name procid msgid structured-data msg
    RFC5424_PATTERN = re.compile(
        r'^<(\d+)>(\d+)\s+'  # Priority and version
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'  # ISO timestamp
        r'(\S+)\s+'  # Hostname
        r'(\S+)\s+'  # App name
        r'(\S+)\s+'  # Proc ID
        r'(\S+)\s+'  # Msg ID
        r'(?:\[(.*?)\]\s*)?'  # Structured data
        r'(.*)$'  # Message
    )
    
    # Syslog severity levels (from priority)
    SYSLOG_SEVERITIES = {
        0: LogLevel.EMERGENCY,
        1: LogLevel.ALERT,
        2: LogLevel.CRITICAL,
        3: LogLevel.ERROR,
        4: LogLevel.WARNING,
        5: LogLevel.INFO,  # Notice
        6: LogLevel.INFO,
        7: LogLevel.DEBUG,
    }
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[LogEntry]:
        """Parse a syslog line."""
        # Try RFC 5424 first
        match = self.RFC5424_PATTERN.match(line)
        if match:
            return self._parse_rfc5424(match, line, line_number)
        
        # Try RFC 3164
        match = self.RFC3164_PATTERN.match(line)
        if match:
            return self._parse_rfc3164(match, line, line_number)
        
        return None
    
    def _parse_rfc3164(self, match: re.Match, raw_line: str, line_number: int) -> LogEntry:
        """Parse RFC 3164 format."""
        priority, timestamp_str, hostname, program, pid, message = match.groups()
        
        # Parse timestamp (assume current year)
        timestamp = self._parse_timestamp(timestamp_str)
        
        # Extract severity from priority
        level = LogLevel.INFO
        if priority:
            severity = int(priority) % 8
            level = self.SYSLOG_SEVERITIES.get(severity, LogLevel.INFO)
        
        return LogEntry(
            timestamp=timestamp,
            message=message,
            level=level,
            source=program or "",
            hostname=hostname,
            raw_line=raw_line,
            line_number=line_number,
            metadata={"pid": pid} if pid else {},
        )
    
    def _parse_rfc5424(self, match: re.Match, raw_line: str, line_number: int) -> LogEntry:
        """Parse RFC 5424 format."""
        priority, version, timestamp_str, hostname, app_name, proc_id, msg_id, sd, message = match.groups()
        
        # Parse ISO timestamp
        timestamp = self._parse_iso_timestamp(timestamp_str)
        
        # Extract severity from priority
        severity = int(priority) % 8
        level = self.SYSLOG_SEVERITIES.get(severity, LogLevel.INFO)
        
        return LogEntry(
            timestamp=timestamp,
            message=message,
            level=level,
            source=app_name if app_name != "-" else "",
            hostname=hostname if hostname != "-" else "",
            raw_line=raw_line,
            line_number=line_number,
            metadata={
                "version": version,
                "proc_id": proc_id if proc_id != "-" else None,
                "msg_id": msg_id if msg_id != "-" else None,
                "structured_data": sd,
            },
        )
    
    def _parse_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse RFC 3164 timestamp (e.g., 'Dec 31 10:30:45')."""
        try:
            # Add current year
            year = datetime.now().year
            return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
    
    def _parse_iso_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse ISO 8601 timestamp."""
        try:
            # Handle various ISO formats
            ts = ts.replace('Z', '+00:00')
            return datetime.fromisoformat(ts)
        except ValueError:
            return None
    
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Check if lines look like syslog."""
        if not sample_lines:
            return False
        
        matches = 0
        for line in sample_lines[:10]:
            if self.RFC5424_PATTERN.match(line) or self.RFC3164_PATTERN.match(line):
                matches += 1
        
        return matches >= len(sample_lines[:10]) * 0.5


class JSONLogParser(LogParser):
    """Parser for JSON-formatted logs (one JSON object per line)."""
    
    # Common field names for standard log fields
    TIMESTAMP_FIELDS = ['timestamp', 'time', '@timestamp', 'datetime', 'date', 'ts', 'created']
    MESSAGE_FIELDS = ['message', 'msg', 'text', 'log', 'content', 'body']
    LEVEL_FIELDS = ['level', 'severity', 'loglevel', 'log_level', 'priority']
    SOURCE_FIELDS = ['source', 'logger', 'name', 'service', 'app', 'application']
    HOSTNAME_FIELDS = ['hostname', 'host', 'server', 'node']
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[LogEntry]:
        """Parse a JSON log line."""
        line = line.strip()
        if not line:
            return None
        
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                return None
        except json.JSONDecodeError:
            return None
        
        # Extract standard fields
        timestamp = self._extract_timestamp(data)
        message = self._extract_field(data, self.MESSAGE_FIELDS)
        level = self._extract_level(data)
        source = self._extract_field(data, self.SOURCE_FIELDS)
        hostname = self._extract_field(data, self.HOSTNAME_FIELDS)
        
        # If no message field, use entire JSON as message
        if not message:
            message = line
        
        return LogEntry(
            timestamp=timestamp,
            message=message,
            level=level,
            source=source,
            hostname=hostname,
            raw_line=line,
            line_number=line_number,
            metadata=data,
        )
    
    def _extract_field(self, data: dict, field_names: list[str]) -> str:
        """Extract a field trying multiple possible names."""
        for name in field_names:
            # Try exact match
            if name in data:
                return str(data[name])
            # Try case-insensitive
            for key in data:
                if key.lower() == name.lower():
                    return str(data[key])
        return ""
    
    def _extract_timestamp(self, data: dict) -> Optional[datetime]:
        """Extract and parse timestamp from JSON."""
        for name in self.TIMESTAMP_FIELDS:
            value = None
            if name in data:
                value = data[name]
            else:
                for key in data:
                    if key.lower() == name.lower():
                        value = data[key]
                        break
            
            if value is not None:
                ts = self._parse_timestamp_value(value)
                if ts:
                    return ts
        
        return None
    
    def _parse_timestamp_value(self, value: Any) -> Optional[datetime]:
        """Parse various timestamp formats."""
        if isinstance(value, (int, float)):
            # Unix timestamp
            try:
                if value > 1e12:  # Milliseconds
                    return datetime.fromtimestamp(value / 1000)
                return datetime.fromtimestamp(value)
            except (ValueError, OSError):
                return None
        
        if isinstance(value, str):
            # Try various formats
            formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value.replace('+00:00', 'Z').rstrip('Z') + 'Z' if 'Z' not in value else value, fmt)
                except ValueError:
                    continue
            
            # Try ISO format
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                return None
        
        return None
    
    def _extract_level(self, data: dict) -> LogLevel:
        """Extract log level from JSON."""
        level_str = self._extract_field(data, self.LEVEL_FIELDS)
        if level_str:
            return LogLevel.from_string(level_str)
        return LogLevel.INFO
    
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Check if lines are JSON."""
        if not sample_lines:
            return False
        
        json_lines = 0
        for line in sample_lines[:10]:
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    json.loads(line)
                    json_lines += 1
                except json.JSONDecodeError:
                    pass
        
        return json_lines >= len(sample_lines[:10]) * 0.5


class ApacheAccessLogParser(LogParser):
    """Parser for Apache/Nginx combined access log format."""
    
    # Combined log format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
    # Example: 192.168.1.1 - - [31/Dec/2024:10:30:45 +0000] "GET /page HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
    COMBINED_PATTERN = re.compile(
        r'^(\S+)\s+'  # IP address
        r'(\S+)\s+'  # Identity
        r'(\S+)\s+'  # User
        r'\[([^\]]+)\]\s+'  # Timestamp
        r'"([^"]*)"\s+'  # Request
        r'(\d{3})\s+'  # Status code
        r'(\S+)'  # Bytes
        r'(?:\s+"([^"]*)"\s+"([^"]*)")?'  # Referer and User-Agent (optional)
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[LogEntry]:
        """Parse an access log line."""
        match = self.COMBINED_PATTERN.match(line)
        if not match:
            return None
        
        ip, identity, user, timestamp_str, request, status, bytes_sent, referer, user_agent = match.groups()
        
        # Parse timestamp
        timestamp = self._parse_timestamp(timestamp_str)
        
        # Determine log level from status code
        status_code = int(status)
        level = self._status_to_level(status_code)
        
        # Build message
        message = f"{request} - {status}"
        
        return LogEntry(
            timestamp=timestamp,
            message=message,
            level=level,
            source="access_log",
            hostname="",
            raw_line=line,
            line_number=line_number,
            metadata={
                "ip": ip,
                "user": user if user != "-" else None,
                "request": request,
                "status_code": status_code,
                "bytes": int(bytes_sent) if bytes_sent != "-" else 0,
                "referer": referer if referer and referer != "-" else None,
                "user_agent": user_agent,
            },
        )
    
    def _parse_timestamp(self, ts: str) -> Optional[datetime]:
        """Parse Apache timestamp format: 31/Dec/2024:10:30:45 +0000."""
        try:
            # Remove timezone for parsing
            ts_clean = ts.split()[0] if ' ' in ts else ts
            return datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None
    
    def _status_to_level(self, status: int) -> LogLevel:
        """Convert HTTP status code to log level."""
        if status >= 500:
            return LogLevel.ERROR
        elif status >= 400:
            return LogLevel.WARNING
        elif status >= 300:
            return LogLevel.INFO
        else:
            return LogLevel.INFO
    
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Check if lines are Apache access logs."""
        if not sample_lines:
            return False
        
        matches = 0
        for line in sample_lines[:10]:
            if self.COMBINED_PATTERN.match(line):
                matches += 1
        
        return matches >= len(sample_lines[:10]) * 0.5


class GenericLogParser(LogParser):
    """Generic parser for unstructured log formats."""
    
    # Common timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO format: 2024-12-31T10:30:45
        (r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)', "%Y-%m-%dT%H:%M:%S"),
        # Date time: 2024-12-31 10:30:45
        (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', "%Y-%m-%d %H:%M:%S"),
        # US format: 12/31/2024 10:30:45
        (r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})', "%m/%d/%Y %H:%M:%S"),
        # Syslog style: Dec 31 10:30:45
        (r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', None),
    ]
    
    # Log level patterns
    LEVEL_PATTERN = re.compile(
        r'\b(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|ALERT|EMERG(?:ENCY)?|FATAL)\b',
        re.IGNORECASE
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[LogEntry]:
        """Parse a generic log line."""
        if not line.strip():
            return None
        
        timestamp = self._extract_timestamp(line)
        level = self._extract_level(line)
        
        return LogEntry(
            timestamp=timestamp,
            message=line,
            level=level,
            source="",
            hostname="",
            raw_line=line,
            line_number=line_number,
        )
    
    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Try to extract timestamp from line."""
        for pattern, fmt in self.TIMESTAMP_PATTERNS:
            match = re.search(pattern, line)
            if match:
                ts_str = match.group(1)
                if fmt:
                    try:
                        # Handle T separator
                        ts_str = ts_str.replace('T', ' ').split('.')[0]
                        return datetime.strptime(ts_str, fmt.replace('T', ' '))
                    except ValueError:
                        continue
                else:
                    # Syslog style - add current year
                    try:
                        year = datetime.now().year
                        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                    except ValueError:
                        continue
        
        return None
    
    def _extract_level(self, line: str) -> LogLevel:
        """Try to extract log level from line."""
        match = self.LEVEL_PATTERN.search(line)
        if match:
            return LogLevel.from_string(match.group(1))
        return LogLevel.INFO
    
    def can_parse(self, sample_lines: list[str]) -> bool:
        """Generic parser can always try to parse."""
        return True


class LogParserFactory:
    """Factory for selecting and creating appropriate log parsers."""
    
    PARSERS: list[type[LogParser]] = [
        JSONLogParser,
        SyslogParser,
        ApacheAccessLogParser,
        GenericLogParser,  # Fallback
    ]
    
    @classmethod
    def detect_format(cls, file_path: str | Path) -> LogParser:
        """Detect log format and return appropriate parser."""
        path = Path(file_path)
        
        # Read sample lines
        sample_lines: list[str] = []
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= 20:
                        break
                    line = line.strip()
                    if line:
                        sample_lines.append(line)
        except Exception:
            return GenericLogParser()
        
        return cls.detect_format_from_content(sample_lines)
    
    @classmethod
    def detect_format_from_content(cls, sample_lines: list[str]) -> LogParser:
        """Detect format from sample content."""
        for parser_class in cls.PARSERS:
            parser = parser_class()
            if parser.can_parse(sample_lines):
                return parser
        
        return GenericLogParser()
    
    @classmethod
    def get_parser(cls, format_name: str) -> LogParser:
        """Get parser by format name."""
        parsers = {
            "syslog": SyslogParser,
            "json": JSONLogParser,
            "apache": ApacheAccessLogParser,
            "nginx": ApacheAccessLogParser,
            "access": ApacheAccessLogParser,
            "generic": GenericLogParser,
        }
        
        parser_class = parsers.get(format_name.lower(), GenericLogParser)
        return parser_class()
