"""Phishing URL Detector - Tkinter arayüzü.

Tasarım hedefleri:
- Koyu (dark) siber güvenlik teması
- Risk seviyesine göre yeşil / sarı / kırmızı vurgu
- Analiz işini threading ile arka planda çalıştırma
  (WHOIS ağ çağrısı arayüzü kilitlemesin)

Bu modül yalnızca sunum katmanıdır; iş mantığı detector.analyzer'dadır.
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

from detector.analyzer import AnalysisResult, analyze_url
from detector.report import save_json_report, save_pdf_report
from utils.logger import get_logger

logger = get_logger()


# ---------------------------------------------------------------------------
# Tema renkleri (cyber security / dark)
# ---------------------------------------------------------------------------

COLORS = {
    "bg": "#0b1220",
    "panel": "#121a2b",
    "input_bg": "#1a2438",
    "fg": "#e6edf7",
    "muted": "#8b9bb4",
    "accent": "#00d4aa",
    "border": "#243049",
    "safe": "#22c55e",
    "suspicious": "#eab308",
    "high_risk": "#ef4444",
    "button": "#143d36",
    "button_active": "#1a5c50",
}


class PhishingDetectorApp(tk.Tk):
    """Ana uygulama penceresi."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Phishing URL Detector")
        self.geometry("920x680")
        self.minsize(780, 560)
        self.configure(bg=COLORS["bg"])

        self._last_result: AnalysisResult | None = None
        self._is_analyzing = False

        self._build_style()
        self._build_layout()
        logger.info("GUI başlatıldı")

    def _build_style(self) -> None:
        """ttk stilini koyu temaya göre ayarla."""
        style = ttk.Style(self)
        # Windows'ta 'clam' özel renkleri daha iyi uygular.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "TFrame",
            background=COLORS["bg"],
        )
        style.configure(
            "Card.TFrame",
            background=COLORS["panel"],
        )
        style.configure(
            "TLabel",
            background=COLORS["bg"],
            foreground=COLORS["fg"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Title.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["accent"],
            font=("Segoe UI Semibold", 20),
        )
        style.configure(
            "Subtitle.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Card.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["fg"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Score.TLabel",
            background=COLORS["panel"],
            foreground=COLORS["fg"],
            font=("Segoe UI Semibold", 28),
        )
        style.configure(
            "TButton",
            background=COLORS["button"],
            foreground=COLORS["fg"],
            font=("Segoe UI Semibold", 10),
            padding=(14, 8),
            borderwidth=0,
        )
        style.map(
            "TButton",
            background=[
                ("active", COLORS["button_active"]),
                ("disabled", COLORS["border"]),
            ],
            foreground=[("disabled", COLORS["muted"])],
        )
        style.configure(
            "TEntry",
            fieldbackground=COLORS["input_bg"],
            foreground=COLORS["fg"],
            insertcolor=COLORS["fg"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["accent"],
            darkcolor=COLORS["border"],
            padding=8,
        )

    def _build_layout(self) -> None:
        """Pencere bileşenlerini yerleştir."""
        root = ttk.Frame(self, style="TFrame", padding=24)
        root.pack(fill=tk.BOTH, expand=True)

        ttk.Label(root, text="PHISHING URL DETECTOR", style="Title.TLabel").pack(
            anchor=tk.W
        )
        ttk.Label(
            root,
            text="Heuristic + WHOIS + HTML içerik analizi",
            style="Subtitle.TLabel",
        ).pack(anchor=tk.W, pady=(4, 18))

        # --- URL giriş satırı ---
        input_row = ttk.Frame(root, style="TFrame")
        input_row.pack(fill=tk.X, pady=(0, 12))

        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(input_row, textvariable=self.url_var, font=("Consolas", 11))
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.url_entry.bind("<Return>", lambda _event: self.start_analysis())

        self.analyze_btn = ttk.Button(
            input_row, text="Analiz Et", command=self.start_analysis
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.save_btn = ttk.Button(
            input_row, text="JSON Kaydet", command=self.save_report, state=tk.DISABLED
        )
        self.save_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.save_pdf_btn = ttk.Button(
            input_row, text="PDF Kaydet", command=self.save_pdf, state=tk.DISABLED
        )
        self.save_pdf_btn.pack(side=tk.LEFT)

        # --- Skor kartı ---
        score_card = ttk.Frame(root, style="Card.TFrame", padding=16)
        score_card.pack(fill=tk.X, pady=(8, 12))

        self.score_label = ttk.Label(score_card, text="Risk Skoru: —", style="Score.TLabel")
        self.score_label.pack(anchor=tk.W)

        self.level_label = ttk.Label(
            score_card, text="Durum: Bekleniyor", style="Card.TLabel"
        )
        self.level_label.pack(anchor=tk.W, pady=(6, 0))

        self.status_label = ttk.Label(
            root, text="URL girip Analiz Et'e basın.", style="Subtitle.TLabel"
        )
        self.status_label.pack(anchor=tk.W, pady=(0, 8))

        # --- Sonuç metin alanları ---
        body = ttk.Frame(root, style="TFrame")
        body.pack(fill=tk.BOTH, expand=True)

        left = self._build_text_panel(body, "Bulunan Problemler")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.problems_text = left.text_widget

        right = self._build_text_panel(body, "Öneriler")
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))
        self.recommendations_text = right.text_widget

    def _build_text_panel(self, parent: ttk.Frame, title: str) -> ttk.Frame:
        """Başlıklı salt okunur metin paneli üret."""
        panel = ttk.Frame(parent, style="Card.TFrame", padding=12)
        ttk.Label(panel, text=title, style="Card.TLabel").pack(anchor=tk.W, pady=(0, 8))

        text = tk.Text(
            panel,
            wrap=tk.WORD,
            height=18,
            bg=COLORS["input_bg"],
            fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief=tk.FLAT,
            bd=0,
            font=("Segoe UI", 10),
            padx=10,
            pady=10,
        )
        text.pack(fill=tk.BOTH, expand=True)
        text.configure(state=tk.DISABLED)
        panel.text_widget = text  # type: ignore[attr-defined]
        return panel

    def start_analysis(self) -> None:
        """Analizi arka plan thread'inde başlat."""
        if self._is_analyzing:
            return

        raw_url = self.url_var.get().strip()
        if not raw_url:
            messagebox.showwarning("Eksik URL", "Lütfen bir URL girin.")
            return

        self._is_analyzing = True
        self.analyze_btn.configure(state=tk.DISABLED)
        self.save_btn.configure(state=tk.DISABLED)
        self.save_pdf_btn.configure(state=tk.DISABLED)
        self.status_label.configure(text="Analiz ediliyor... (WHOIS/HTML biraz sürebilir)")
        self._set_text(self.problems_text, "Çalışıyor...")
        self._set_text(self.recommendations_text, "Çalışıyor...")

        thread = threading.Thread(
            target=self._run_analysis_worker,
            args=(raw_url,),
            daemon=True,
        )
        thread.start()

    def _run_analysis_worker(self, raw_url: str) -> None:
        """Worker thread: analyze_url çağır, sonucu UI thread'ine ilet."""
        try:
            result = analyze_url(raw_url)
            self.after(0, lambda: self._on_analysis_done(result, None))
        except Exception as exc:  # noqa: BLE001
            logger.exception("GUI analiz hatası")
            self.after(0, lambda: self._on_analysis_done(None, str(exc)))

    def _on_analysis_done(
        self, result: AnalysisResult | None, error: str | None
    ) -> None:
        """UI thread: sonucu ekrana bas."""
        self._is_analyzing = False
        self.analyze_btn.configure(state=tk.NORMAL)

        if error or result is None:
            self.status_label.configure(text=f"Hata: {error or 'bilinmeyen'}")
            self._paint_level("ERROR", COLORS["high_risk"])
            self._set_text(self.problems_text, error or "Analiz başarısız.")
            self._set_text(self.recommendations_text, "Tekrar deneyin.")
            return

        self._last_result = result
        self.save_btn.configure(state=tk.NORMAL)
        self.save_pdf_btn.configure(state=tk.NORMAL)

        if not result.is_valid:
            self.score_label.configure(text="Risk Skoru: —")
            self._paint_level("INVALID", COLORS["suspicious"])
            self.status_label.configure(text=result.error or "Geçersiz URL")
            self._set_text(self.problems_text, result.error or "URL geçersiz.")
            self._set_text(
                self.recommendations_text,
                "\n".join(f"• {tip}" for tip in result.recommendations),
            )
            return

        color = self._color_for_level(result.risk_level)
        self.score_label.configure(text=f"Risk Skoru: {result.risk_score}")
        self._paint_level(result.risk_level, color)
        self.status_label.configure(text=f"Analiz tamamlandı: {result.url}")

        problems = result.problems or ["Belirgin bir problem bulunamadı."]
        self._set_text(
            self.problems_text,
            "\n".join(f"❌ {item}" for item in problems),
        )
        self._set_text(
            self.recommendations_text,
            "\n".join(f"• {tip}" for tip in result.recommendations),
        )

    def save_report(self) -> None:
        """Son analizi JSON olarak kaydet."""
        if self._last_result is None:
            messagebox.showinfo("Kayıt", "Önce bir analiz yapın.")
            return
        try:
            path = save_json_report(self._last_result)
            messagebox.showinfo("Kayıt başarılı", f"JSON rapor kaydedildi:\n{path}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("JSON rapor kaydı başarısız")
            messagebox.showerror("Kayıt hatası", str(exc))

    def save_pdf(self) -> None:
        """Son analizi PDF olarak kaydet."""
        if self._last_result is None:
            messagebox.showinfo("Kayıt", "Önce bir analiz yapın.")
            return
        try:
            path = save_pdf_report(self._last_result)
            messagebox.showinfo("Kayıt başarılı", f"PDF rapor kaydedildi:\n{path}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("PDF rapor kaydı başarısız")
            messagebox.showerror("Kayıt hatası", str(exc))

    def _paint_level(self, level: str, color: str) -> None:
        """Durum etiketinin rengini güncelle."""
        self.level_label.configure(text=f"Durum: {level}", foreground=color)

    @staticmethod
    def _color_for_level(level: str) -> str:
        """Risk seviyesine renk eşle."""
        mapping = {
            "SAFE": COLORS["safe"],
            "SUSPICIOUS": COLORS["suspicious"],
            "HIGH_RISK": COLORS["high_risk"],
        }
        return mapping.get(level, COLORS["fg"])

    @staticmethod
    def _set_text(widget: tk.Text, content: str) -> None:
        """Salt okunur Text içeriğini güvenli şekilde değiştir."""
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, content)
        widget.configure(state=tk.DISABLED)


def run_app() -> None:
    """Uygulamayı başlat (main.py burayı çağırır)."""
    app = PhishingDetectorApp()
    app.mainloop()


if __name__ == "__main__":
    run_app()
