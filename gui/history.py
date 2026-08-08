"""GUI oturum geçmişi (in-memory).

Analiz sonuçlarını diske yazmadan pencerede tutar.
Kullanıcı önceki bir satıra tıklayınca sonucu tekrar görebilir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator

from detector.analyzer import AnalysisResult

# Aynı oturumda tutulacak maksimum kayıt.
DEFAULT_HISTORY_LIMIT: int = 20


@dataclass(frozen=True)
class HistoryEntry:
    """Tek bir geçmiş kaydı."""

    analyzed_at: datetime
    raw_input: str
    result: AnalysisResult

    @property
    def display_label(self) -> str:
        """Listbox'ta gösterilecek kısa etiket."""
        stamp = self.analyzed_at.strftime("%H:%M:%S")
        level = self.result.risk_level if self.result.is_valid else "INVALID"
        score = self.result.risk_score if self.result.is_valid else "-"
        url = self.result.url or self.raw_input
        if len(url) > 48:
            url = url[:45] + "..."
        return f"[{stamp}] {level} ({score}) | {url}"


@dataclass
class HistoryStore:
    """FIFO geçmiş deposu (en yeni başta)."""

    limit: int = DEFAULT_HISTORY_LIMIT
    _entries: list[HistoryEntry] = field(default_factory=list)

    def add(self, raw_input: str, result: AnalysisResult) -> HistoryEntry:
        """Yeni kaydı listenin başına ekle; limit aşımında eskileri at."""
        entry = HistoryEntry(
            analyzed_at=datetime.now(),
            raw_input=raw_input,
            result=result,
        )
        self._entries.insert(0, entry)
        if len(self._entries) > self.limit:
            self._entries = self._entries[: self.limit]
        return entry

    def clear(self) -> None:
        """Tüm geçmişi sil."""
        self._entries.clear()

    def get(self, index: int) -> HistoryEntry | None:
        """İndeksteki kaydı döndür; yoksa None."""
        if index < 0 or index >= len(self._entries):
            return None
        return self._entries[index]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[HistoryEntry]:
        return iter(self._entries)

    @property
    def labels(self) -> list[str]:
        """Listbox için etiket listesi."""
        return [entry.display_label for entry in self._entries]
