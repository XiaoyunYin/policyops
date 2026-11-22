"""Server-selected investigation behavior."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from policyops.persistence.retrieval import LexicalMode



class InvestigationProfile(StrEnum):
    BASELINE = "baseline"
    TOOL_CONTRACT_V1 = "tool-contract-v1"
    TOOL_CONTRACT_V1R1 = "tool-contract-v1r1"

    @property
    def tool_contract(self) -> bool:
        return self in (InvestigationProfile.TOOL_CONTRACT_V1, InvestigationProfile.TOOL_CONTRACT_V1R1)

    @property
    def lexical_mode(self) -> LexicalMode:
        return "bm25" if self.tool_contract else "all_terms"
