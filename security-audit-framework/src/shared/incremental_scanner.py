"""
Incremental Scanning Engine - Efficient diff-based security analysis
"""
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
import git
from dataclasses import dataclass, asdict
import pickle
import sqlite3

@dataclass
class FileMetadata:
    """Metadata for tracked files"""
    path: str
    hash: str
    last_scanned: str
    last_modified: float
    findings_count: int
    risk_score: float

@dataclass 
class ScanCache:
    """Cache for scan results"""
    file_path: str
    file_hash: str
    findings: List[Dict[str, Any]]
    scan_time: str
    ai_confidence: float

class IncrementalScanner:
    """
    Manages incremental scanning with caching and diff analysis
    """
    
    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or Path.home() / '.security-audit' / 'cache'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / 'scan_cache.db'
        self._init_db()
        self.repo = self._init_git_repo()
        
    def _init_db(self):
        """Initialize SQLite cache database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # File metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_metadata (
                path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                last_scanned TIMESTAMP,
                last_modified REAL,
                findings_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0.0
            )
        ''')
        
        # Scan cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_cache (
                file_path TEXT,
                file_hash TEXT,
                findings TEXT,
                scan_time TIMESTAMP,
                ai_confidence REAL,
                PRIMARY KEY (file_path, file_hash)
            )
        ''')
        
        # Finding suppressions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suppressions (
                finding_hash TEXT PRIMARY KEY,
                file_path TEXT,
                reason TEXT,
                suppressed_by TEXT,
                suppressed_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _init_git_repo(self) -> Optional[git.Repo]:
        """Initialize git repo if available"""
        try:
            return git.Repo(search_parent_directories=True)
        except:
            return None
    
    def get_files_to_scan(self, 
                         path: Path, 
                         force_all: bool = False,
                         commit_range: Optional[str] = None) -> List[Tuple[Path, str]]:
        """
        Get list of files that need scanning
        Returns list of (file_path, reason) tuples
        """
        files_to_scan = []
        
        if force_all:
            # Scan all files
            for file_path in self._get_all_files(path):
                files_to_scan.append((file_path, "force_scan"))
        else:
            # Incremental scan
            if commit_range and self.repo:
                # Get files changed in commit range
                changed_files = self._get_changed_in_range(commit_range)
                for file_path in changed_files:
                    files_to_scan.append((file_path, f"changed_in_{commit_range}"))
            
            # Check for modified files since last scan
            for file_path in self._get_all_files(path):
                if self._needs_rescan(file_path):
                    if (file_path, any) not in files_to_scan:
                        files_to_scan.append((file_path, "modified"))
        
        return files_to_scan
    
    def _needs_rescan(self, file_path: Path) -> bool:
        """Check if file needs rescanning"""
        # Get file hash
        current_hash = self._calculate_file_hash(file_path)
        
        # Check cache
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT hash, last_modified FROM file_metadata 
            WHERE path = ?
        ''', (str(file_path),))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return True  # Never scanned
        
        cached_hash, last_modified = result
        
        # Check if file changed
        if current_hash != cached_hash:
            return True
            
        # Check if file modified since last scan
        current_mtime = file_path.stat().st_mtime
        if current_mtime > last_modified:
            return True
            
        return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file content"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""
    
    def get_cached_findings(self, file_path: Path) -> Optional[List[Dict[str, Any]]]:
        """Get cached findings for a file"""
        file_hash = self._calculate_file_hash(file_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT findings, ai_confidence FROM scan_cache 
            WHERE file_path = ? AND file_hash = ?
        ''', (str(file_path), file_hash))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            findings_json, confidence = result
            findings = json.loads(findings_json)
            
            # Filter out suppressed findings
            findings = self._filter_suppressed(findings, file_path)
            
            return findings
        
        return None
    
    def cache_scan_results(self, file_path: Path, findings: List[Dict[str, Any]], 
                          ai_confidence: float = 0.95):
        """Cache scan results for a file"""
        file_hash = self._calculate_file_hash(file_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Update file metadata
        cursor.execute('''
            INSERT OR REPLACE INTO file_metadata 
            (path, hash, last_scanned, last_modified, findings_count, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            str(file_path),
            file_hash,
            datetime.utcnow().isoformat(),
            file_path.stat().st_mtime,
            len(findings),
            self._calculate_risk_score(findings)
        ))
        
        # Cache findings
        cursor.execute('''
            INSERT OR REPLACE INTO scan_cache 
            (file_path, file_hash, findings, scan_time, ai_confidence)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            str(file_path),
            file_hash,
            json.dumps(findings),
            datetime.utcnow().isoformat(),
            ai_confidence
        ))
        
        conn.commit()
        conn.close()
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate risk score for findings"""
        if not findings:
            return 0.0
            
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 5.0,
            'MEDIUM': 2.0,
            'LOW': 0.5
        }
        
        score = sum(
            severity_weights.get(f.get('severity', 'MEDIUM'), 1.0) 
            for f in findings
        )
        
        # Normalize to 0-100
        return min(100.0, score)
    
    def suppress_finding(self, finding_hash: str, file_path: Path, 
                        reason: str, suppressed_by: str, 
                        expires_days: Optional[int] = None):
        """Suppress a specific finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = None
        if expires_days:
            expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO suppressions 
            (finding_hash, file_path, reason, suppressed_by, suppressed_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            finding_hash,
            str(file_path),
            reason,
            suppressed_by,
            datetime.utcnow().isoformat(),
            expires_at
        ))
        
        conn.commit()
        conn.close()
    
    def _filter_suppressed(self, findings: List[Dict[str, Any]], 
                          file_path: Path) -> List[Dict[str, Any]]:
        """Filter out suppressed findings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get active suppressions
        cursor.execute('''
            SELECT finding_hash FROM suppressions 
            WHERE file_path = ? 
            AND (expires_at IS NULL OR expires_at > ?)
        ''', (str(file_path), datetime.utcnow().isoformat()))
        
        suppressed_hashes = {row[0] for row in cursor.fetchall()}
        conn.close()
        
        # Filter findings
        filtered = []
        for finding in findings:
            finding_hash = self._hash_finding(finding)
            if finding_hash not in suppressed_hashes:
                filtered.append(finding)
            else:
                finding['suppressed'] = True
                
        return filtered
    
    def _hash_finding(self, finding: Dict[str, Any]) -> str:
        """Generate unique hash for a finding"""
        # Create deterministic hash from finding properties
        key_parts = [
            finding.get('file', ''),
            str(finding.get('line', 0)),
            finding.get('type', ''),
            finding.get('message', '')
        ]
        
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
    
    def get_diff_analysis(self, base_commit: str, head_commit: str = 'HEAD') -> Dict[str, Any]:
        """Analyze security changes between commits"""
        if not self.repo:
            return {'error': 'Not a git repository'}
        
        # Get changed files
        diff_index = self.repo.diff(base_commit, head_commit)
        
        analysis = {
            'base_commit': base_commit,
            'head_commit': head_commit,
            'files_changed': 0,
            'findings_added': [],
            'findings_fixed': [],
            'risk_delta': 0.0
        }
        
        for diff_item in diff_index:
            if diff_item.a_path:  # File exists in base
                analysis['files_changed'] += 1
                
                # Get findings from cache for both versions
                # This is simplified - in production would need to checkout files
                
        return analysis
    
    def _get_changed_in_range(self, commit_range: str) -> List[Path]:
        """Get files changed in commit range"""
        if not self.repo:
            return []
            
        try:
            changed_files = self.repo.git.diff(
                commit_range, 
                name_only=True
            ).splitlines()
            
            repo_root = Path(self.repo.working_dir)
            return [
                repo_root / f for f in changed_files 
                if (repo_root / f).exists()
            ]
        except:
            return []
    
    def _get_all_files(self, path: Path) -> List[Path]:
        """Get all scannable files"""
        files = []
        exclude_patterns = {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            'dist', 'build', 'target', '.idea', '.vscode'
        }
        
        for root, dirs, filenames in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude_patterns]
            
            for filename in filenames:
                file_path = Path(root) / filename
                # Skip binary files
                if file_path.suffix in {'.pyc', '.pyo', '.so', '.dll', '.exe'}:
                    continue
                files.append(file_path)
                
        return files
    
    def generate_incremental_report(self) -> Dict[str, Any]:
        """Generate report on incremental scanning performance"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get scan statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_files,
                SUM(findings_count) as total_findings,
                AVG(risk_score) as avg_risk,
                MAX(last_scanned) as last_scan
            FROM file_metadata
        ''')
        
        stats = cursor.fetchone()
        
        # Get cache hit rate
        cursor.execute('''
            SELECT COUNT(DISTINCT file_path) FROM scan_cache
        ''')
        cached_files = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_files_tracked': stats[0],
            'total_findings': stats[1] or 0,
            'average_risk_score': round(stats[2] or 0, 2),
            'last_scan_time': stats[3],
            'cache_size_mb': round(self.db_path.stat().st_size / 1024 / 1024, 2),
            'cached_files': cached_files,
            'cache_hit_rate': round(cached_files / max(stats[0], 1) * 100, 2)
        }