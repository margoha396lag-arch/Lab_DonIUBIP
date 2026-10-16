import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication
from protolab import gui
from test_core import frame, pcap, w


def test_async_state_and_errors(tmp_path):                   # BUG-009, 010, 011, 013
    app = QApplication.instance() or QApplication([]); win = gui.Win()
    def op(path): win.open_cap(path=path); win.wait()
    op(w(tmp_path, "a.pcap", pcap([frame(b"hello")]))); assert win.hex.toPlainText() and win.model.rowCount() == 1
    op(w(tmp_path, "e.pcap", pcap([]))); assert win.hex.toPlainText() == "" and win.model.rowCount() == 0
    op(w(tmp_path, "bad.pcap", b"junk")); assert win.log and win.job is None


def test_cancel_keeps_state(tmp_path):
    app = QApplication.instance() or QApplication([]); win = gui.Win()
    win.open_cap(path=w(tmp_path, "m.pcap", pcap([frame(b"A")] * 20000))); win.job.requestInterruption(); win.wait()
    assert win.job is None and win.model.rowCount() in (0, 20000)
