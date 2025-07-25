"""Core analyzer module for SAST-Blame."""

from typing import Dict, List, Optional, Union
from pydantic import BaseModel
from github import Github
import gitlab
import subprocess
import json

class SastResult(BaseModel):
    """Model representing a SAST finding."""
    file: str
    line: int
    message: str
    severity: str
    rule_id: str

class BlameInfo(BaseModel):
    """Model representing blame information for a line of code."""
    author: str
    commit: str
    date: str

class SastAnalyzer:
    """Main analyzer class that integrates SAST results with VCS blame information."""
    
    def __init__(
        self,
        gitlab_token: Optional[str] = None,
        github_token: Optional[str] = None
    ):
        """Initialize the analyzer with VCS credentials."""
        self.gitlab_token = gitlab_token
        self.github_token = github_token
        self.gitlab_client = gitlab.Gitlab(private_token=gitlab_token) if gitlab_token else None
        self.github_client = Github(github_token) if github_token else None

    def run_semgrep(self, path: str) -> List[SastResult]:
        """Run Semgrep analysis on the specified path."""
        try:
            cmd = ["semgrep", "--json", path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            findings = json.loads(result.stdout)
            
            return [
                SastResult(
                    file=finding["path"],
                    line=finding["start"]["line"],
                    message=finding["extra"]["message"],
                    severity=finding["extra"]["severity"],
                    rule_id=finding["check_id"]
                )
                for finding in findings.get("results", [])
            ]
        except Exception as e:
            raise RuntimeError(f"Semgrep analysis failed: {str(e)}")

    def get_blame_info(
        self,
        repo_url: str,
        file_path: str,
        line: int
    ) -> Optional[BlameInfo]:
        """Get blame information for a specific line in a file."""
        if self.gitlab_client and "gitlab" in repo_url:
            return self._get_gitlab_blame(repo_url, file_path, line)
        elif self.github_client and "github" in repo_url:
            return self._get_github_blame(repo_url, file_path, line)
        return None

    def _get_gitlab_blame(
        self,
        repo_url: str,
        file_path: str,
        line: int
    ) -> Optional[BlameInfo]:
        """Get blame information from GitLab."""
        try:
            project = self.gitlab_client.projects.get(repo_url)
            blame = project.repository_blob(file_path).blame()
            for entry in blame:
                if entry["lines"]["start"] <= line <= entry["lines"]["end"]:
                    return BlameInfo(
                        author=entry["commit"]["author_name"],
                        commit=entry["commit"]["id"],
                        date=entry["commit"]["committed_date"]
                    )
        except Exception:
            return None

    def _get_github_blame(
        self,
        repo_url: str,
        file_path: str,
        line: int
    ) -> Optional[BlameInfo]:
        """Get blame information from GitHub."""
        try:
            repo = self.github_client.get_repo(repo_url)
            blame = repo.get_contents(file_path).blame()
            for entry in blame:
                if entry.lines[0] <= line <= entry.lines[-1]:
                    commit = entry.commit
                    return BlameInfo(
                        author=commit.author.name,
                        commit=commit.sha,
                        date=commit.committed_date.isoformat()
                    )
        except Exception:
            return None

    def analyze_repository(
        self,
        repo_url: str,
        path: str = "."
    ) -> Dict[str, Union[SastResult, BlameInfo]]:
        """Run full analysis on a repository, combining SAST results with blame info."""
        sast_results = self.run_semgrep(path)
        enriched_results = {}
        
        for result in sast_results:
            blame = self.get_blame_info(repo_url, result.file, result.line)
            enriched_results[f"{result.file}:{result.line}"] = {
                "sast": result,
                "blame": blame
            }
        
        return enriched_results
