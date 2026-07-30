"""Pydantic models for LLM structured output.

Refactor note: these replace the manual JSON schema contracts embedded in
prompt files and the repair_json + retry parsing logic. deepagent/langchain
structured output uses these as response_format, guaranteeing parseable output
without manual JSON repair. The schemas mirror the contracts in
prompt/FunctionAnalysisAgent.md and prompt/MalwareAnalysisAgent.md.
"""
from typing import List

from pydantic import BaseModel, Field


class IOCs(BaseModel):
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)
    mutexes: List[str] = Field(default_factory=list)
    process_names: List[str] = Field(default_factory=list)
    service_names: List[str] = Field(default_factory=list)


class Evidence(BaseModel):
    api_sequence: List[str] = Field(default_factory=list)
    artifacts: List[str] = Field(default_factory=list)
    notes: str = ""


class AttackMatch(BaseModel):
    technique_id: str = ""
    technique_name: str = ""
    tactics: List[str] = Field(default_factory=list)
    evidence: Evidence = Field(default_factory=Evidence)


class FunctionAnalysisResult(BaseModel):
    """Structured output for FunctionAnalysisAgent (per-function analysis)."""
    function_summary: str = ""
    iocs: IOCs = Field(default_factory=IOCs)
    attack_matches: List[AttackMatch] = Field(default_factory=list)


class EvidenceRef(BaseModel):
    function_name: str = ""
    evidence: str = ""


class KeyTTP(BaseModel):
    technique_id: str = ""
    technique_name: str = ""
    tactics: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)


class MaliciousFunction(BaseModel):
    name: str = ""
    reason: str = ""
    severity: str = "low"
    mapped_techniques: List[str] = Field(default_factory=list)


class MalwareReport(BaseModel):
    """Structured output for MalwareAnalysisAgent (final report)."""
    threat_type: str = "clean"
    risk_level: str = "safe"
    malware_name: str = "N/A"
    attack_chain: str = ""
    reason: str = ""
    malicious_functions: List[MaliciousFunction] = Field(default_factory=list)
    key_ttps: List[KeyTTP] = Field(default_factory=list)
    extracted_iocs: IOCs = Field(default_factory=IOCs)
