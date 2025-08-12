"""
Incremental Scanner - Efficient scanning for code changes
"""
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
import git
from dataclasses import dataclass, asdict


@dataclass
class FileChange:
    """Represents a file change in the repository"""
    path: str
    change_type: str  # added, modified, deleted
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    
    
@dataclass
class ScanCache:
    """Cache for incremental scanning"""
    last_scan_time: str
    file_hashes: Dict[str, str]
    last_commit: Optional[str] = None
    findings_cache: Optional[Dict[str, List]] = None


class IncrementalScanner:
    """
    Handles incremental scanning by tracking file changes
    and only scanning modified files
    """
    
    def __init__(self, cache_dir: str = ".security/cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "scan_cache.json"
        
    def get_changed_files(self, repo_path: str) -> List[FileChange]:
        """
        Get list of changed files since last scan
        
        Args:
            repo_path: Path to repository
            
        Returns:
            List of file changes
        """
        changes = []
        cache = self._load_cache(repo_path)
        current_hashes = self._calculate_file_hashes(repo_path)
        
        # Check for new or modified files
        for file_path, new_hash in current_hashes.items():
            old_hash = cache.file_hashes.get(file_path)
            
            if old_hash is None:
                changes.append(FileChange(
                    path=file_path,
                    change_type="added",
                    new_hash=new_hash
                ))
            elif old_hash != new_hash:
                changes.append(FileChange(
                    path=file_path,
                    change_type="modified",
                    old_hash=old_hash,
                    new_hash=new_hash
                ))
        
        # Check for deleted files
        for file_path in cache.file_hashes:
            if file_path not in current_hashes:
                changes.append(FileChange(
                    path=file_path,
                    change_type="deleted",
                    old_hash=cache.file_hashes[file_path]
                ))
        
        return changes
    
    def update_cache(self, repo_path: str, scan_results: Dict[str, Any]):
        """Update cache after scan completion"""
        current_hashes = self._calculate_file_hashes(repo_path)
        
        cache = ScanCache(
            last_scan_time=datetime.utcnow().isoformat(),
            file_hashes=current_hashes,
            last_commit=self._get_last_commit(repo_path),
            findings_cache=scan_results.get('findings', {})
        )
        
        self._save_cache(repo_path, cache)
    
    def get_pr_changes(self, repo_path: str, base_branch: str = "main") -> List[FileChange]:
        """Get changes for PR review"""
        try:
            repo = git.Repo(repo_path)
            changes = []
            
            # Get diff between current branch and base
            diffs = repo.head.commit.diff(base_branch)
            
            for diff in diffs:
                if diff.a_path:  # File exists
                    change_type = "added" if diff.new_file else "modified"
                    changes.append(FileChange(
                        path=diff.a_path,
                        change_type=change_type
                    ))
                elif diff.b_path and diff.deleted_file:
                    changes.append(FileChange(
                        path=diff.b_path,
                        change_type="deleted"
                    ))
            
            return changes
            
        except Exception as e:
            print(f"Error getting PR changes: {e}")
            return []
    
    def _calculate_file_hashes(self, repo_path: str) -> Dict[str, str]:
        """Calculate hash for each file in repository"""
        hashes = {}
        repo_path = Path(repo_path)
        
        # Define patterns to scan
        patterns = ['**/*.py', '**/*.js', '**/*.java', '**/*.go', '**/*.yaml', '**/*.yml']
        ignore_dirs = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache'}
        
        for pattern in patterns:
            for file_path in repo_path.glob(pattern):
                # Skip ignored directories
                if any(ignored in file_path.parts for ignored in ignore_dirs):
                    continue
                    
                try:
                    rel_path = str(file_path.relative_to(repo_path))
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    hashes[rel_path] = file_hash
                except Exception:
                    continue
        
        return hashes
    
    def _load_cache(self, repo_path: str) -> ScanCache:
        """Load cache for repository"""
        cache_key = hashlib.md5(repo_path.encode()).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                return ScanCache(**data)
            except Exception:
                pass
        
        # Return empty cache
        return ScanCache(
            last_scan_time=datetime.utcnow().isoformat(),
            file_hashes={}
        )
    
    def _save_cache(self, repo_path: str, cache: ScanCache):
        """Save cache for repository"""
        cache_key = hashlib.md5(repo_path.encode()).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        with open(cache_file, 'w') as f:
            json.dump(asdict(cache), f, indent=2)
    
    def _get_last_commit(self, repo_path: str) -> Optional[str]:
        """Get last commit SHA"""
        try:
            repo = git.Repo(repo_path)
            return repo.head.commit.hexsha
        except Exception:
            return None