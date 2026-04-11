"""Engine scoring — static + dynamic score computation."""

from typing import List, Optional

from ..config import SCORING_WEIGHTS, DYNAMIC_SCORING_WEIGHTS
from ..models.findings import StaticAnalysisResult
from ..models.verdict import SandboxEvidence


def score_static(result: StaticAnalysisResult) -> int:
    """Return the already-computed static score (set by the coordinator)."""
    return result.static_score


def score_dynamic(sandbox_results: Optional[List[SandboxEvidence]]) -> int:
    """Aggregate dynamic score across all sandbox detonation results."""
    if not sandbox_results:
        return 0

    score = 0
    for evidence in sandbox_results:
        if evidence.detected_credential_harvest:
            score += DYNAMIC_SCORING_WEIGHTS.get("credential_harvest", 50)
        if evidence.detected_executable_network_callback:
            score += DYNAMIC_SCORING_WEIGHTS.get("executable_network_callback", 40)
        if evidence.detected_persistence:
            score += DYNAMIC_SCORING_WEIGHTS.get("persistence_attempt", 40)
        if evidence.detected_file_download:
            score += DYNAMIC_SCORING_WEIGHTS.get("download_triggered", 20)
        if evidence.detected_login_form:
            score += DYNAMIC_SCORING_WEIGHTS.get("redirect_to_login_form", 25)
        if evidence.file_drops:
            for drop in evidence.file_drops:
                if drop.get("executable"):
                    score += DYNAMIC_SCORING_WEIGHTS.get("file_drop_executable", 30)
                    break
        if evidence.registry_changes:
            score += DYNAMIC_SCORING_WEIGHTS.get("registry_modification", 20)

    return min(score, 100)
