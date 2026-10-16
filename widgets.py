import os, sys
from pathlib import Path
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPropertyAnimation, QSize, Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QApplication, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QSplitter,
                               QStackedWidget, QTableView, QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)
from . import core
from .widgets import LAYERS, PAL, HypCard, Hex, Timeline, Toast, Welcome, dark, icon, layers


class PktModel(QAbstractTableModel):
    """Ленивая модель: строки создаются по требованию, поэтому большие захваты не раздувают память и UI."""
    H = ["№", "t, с", "src", "dst", "флаги", "длина", "payload", "поток"]

    def __init__(s): super().__init__(); s.pk = []
    def set(s, pk): s.beginResetModel(); s.pk = pk; s.endResetModel()
    def rowCount(s, p=QModelIndex()): return 0 if p.isValid() else len(s.pk)
    def columnCount(s, p=QModelIndex()): return 0 if p.isValid() else len(s.H)

    def headerData(s, i, o, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and o == Qt.Horizontal: return s.H[i]

    def data(s, ix, role=Qt.DisplayRole):
        p, c = s.pk[ix.row()], ix.column(); t = p.stream >= 0
        if role == Qt.DisplayRole:
            return [p.no, f"{p.ts:.6f}", f"{p.src}:{p.sport}" if t else "—", f"{p.dst}:{p.dport}" if t else "—", p.flags,
                    len(p.raw), p.pay_len, p.stream if t else ""][c]
        if role == Qt.BackgroundRole and t: return QColor(PAL[p.stream % 8]).darker(340)
        if role == Qt.ToolTipRole and p.note: return p.note


class Job(QThread):
    """Фоновая операция с прогрессом; отмена — requestInterruption() (проверяется в callback прогресса)."""
    progressed, ok, failed = Signal(int), Signal(object), Signal(str)

    def __init__(s, fn): super().__init__(); s.fn = fn

    def run(s):
        def cb(f):
            if s.isInterruptionRequested(): raise core.Cancelled()
            s.progressed.emit(int(f * 100))
        try: s.ok.emit(s.fn(cb))
        except core.Cancelled: s.failed.emit("")
        except (OSError, ValueError) as e: s.failed.emit(str(e))


class Win(QMainWindow):
    def __init__(s):
        super().__init__(); s.setWindowTitle("Лаборатория протоколов"); s.resize(1500, 850); s.setAcceptDrops(True)
        s.caps, s.hyps, s.pkts, s.cur, s.cur_id, s.ev, s.proj, s.job, s.log = [], [], [], None, None, [], None, None, []
        s.model = PktModel(); s.tbl = QTableView(); s.tbl.setModel(s.model); s.tbl.verticalHeader().hide()
        s.tbl.setSelectionBehavior(QTableView.SelectRows); s.tbl.setSelectionMode(QTableView.SingleSelection)
        s.tbl.setEditTriggers(QTableView.NoEditTriggers); s.tbl.horizontalHeader().setStretchLastSection(True)
        s.tbl.selectionModel().currentRowChanged.connect(lambda cur, _: s.on_pkt(cur.row()))
        s.hex, s.tl = Hex(), Timeline(s.goto_pkt); s.tree = QTreeWidget(); s.tree.setHeaderLabels(["Поле", "Значение"])
        s.tabs = QTabWidget(); s.tabs.addTab(s.tbl, "Пакеты"); s.tabs.addTab(s.tl, "Диаграмма потоков")
        s.stack = QStackedWidget(); s.stack.addWidget(Welcome()); s.stack.addWidget(s.tabs)
        s.hl = QListWidget(); s.hl.currentRowChanged.connect(s.on_hyp)
        s.name, s.pat, s.note = QLineEdit(), QLineEdit(), QPlainTextEdit(); s.note.setMaximumHeight(70)
        s.port = QSpinBox(); s.port.setRange(0, 65535); s.layer = QComboBox(); s.layer.addItems(["payload TCP", "кадр целиком"])
        s.pat.setPlaceholderText("hex через пробел, ?? = любой байт")
        s.sum = QPlainTextEdit(); s.sum.setReadOnly(True); s.sum.setMaximumHeight(80)
        s.res = QTableWidget(0, 4); s.res.setHorizontalHeaderLabels(["захват", "пакет №", "смещение", "байт"])
        s.res.horizontalHeader().setStretchLastSection(True); s.res.cellDoubleClicked.connect(s.goto)
        f = QFormLayout(); f.addRow("Имя", s.name); f.addRow("Порт", s.port); f.addRow("Область", s.layer); f.addRow("Паттерн", s.pat); f.addRow("Смысл", s.note)
        right = QWidget(); v = QVBoxLayout(right); v.addWidget(s.hl, 2); v.addLayout(f)
        for t, fn in [("Гипотеза из выделения в hex", s.from_sel), ("Сохранить гипотезу и проверить на текущем", s.add_hyp),
                      ("Проверить на дополнительных записях…", s.more)]:
            b = QPushButton(t); b.clicked.connect(fn); v.addWidget(b)
        v.addWidget(s.sum); v.addWidget(s.res, 3)
        cen = QWidget(); cv = QVBoxLayout(cen); cv.setContentsMargins(0, 0, 0, 0)
        cv.addWidget(QLabel("  ".join(f"<span style='color:{c}'>■</span> {n}" for n, c in LAYERS) + "   <span style='color:#ffd54f'>■</span> совпадение"))
        vs = QSplitter(Qt.Vertical); vs.addWidget(s.hex); vs.addWidget(s.tree); cv.addWidget(vs)
        mid = QSplitter(); mid.addWidget(s.stack); mid.addWidget(cen); mid.addWidget(right); mid.setSizes([560, 440, 500]); s.setCentralWidget(mid)
        s.pw = QWidget(); h = QHBoxLayout(s.pw); h.setContentsMargins(0, 0, 0, 0); s.pbar = QProgressBar(); s.pbar.setFixedWidth(280)
        cb = QPushButton("Отмена"); cb.clicked.connect(lambda: s.job and s.job.requestInterruption()); h.addWidget(s.pbar); h.addWidget(cb)
        s.statusBar().addPermanentWidget(s.pw); s.pw.hide(); s.toast_w = Toast(s)
        tb = s.addToolBar("main"); tb.setMovable(False); tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        for k, t, fn in [("cap", "Открыть захват", s.open_cap), ("proj", "Открыть проект", s.open_proj),
                         ("save", "Сохранить проект", s.save_proj), ("check", "Проверить гипотезу", s.more)]:
            tb.addAction(icon(k), t, fn)

    # --- UI-помощники ---
    def toast(s, m, kind="info"): s.toast_w.say(m, kind)

    def err(s, e, ctx): s.log.append(f"{ctx}: {e}"); s.toast(f"{ctx}: {e}", "err")

    def showEvent(s, e):
        super().showEvent(e)
        if not getattr(s, "_shown", False):
            s._shown = True; a = QPropertyAnimation(s, b"windowOpacity", s); a.setDuration(450); a.setStartValue(0.0); a.setEndValue(1.0); a.start()

    def dragEnterEvent(s, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()

    def dropEvent(s, e):
        for u in e.mimeData().urls():
            f = u.toLocalFile()
            if f.endswith(".json"): return s.open_proj(path=f)
            if f: return s.open_cap(path=f)

    # --- фоновые задачи (BUG-013) ---
    def run(s, label, fn, done):
        if s.job: return s.toast("Дождитесь завершения текущей операции", "info")
        s.pbar.setValue(0); s.pbar.setFormat(f"{label}  %p%"); s.pw.show()
        j = s.job = Job(fn); j.progressed.connect(s.pbar.setValue); j.ok.connect(done)
        j.failed.connect(lambda m: s.err(m, label) if m else s.toast("Операция отменена", "info"))
        j.finished.connect(s._end); j.start()

    def _end(s): s.job = None; s.pw.hide()

    def wait(s):
        while s.job:
            QApplication.processEvents(); j = s.job
            if j: j.wait(5)
        QApplication.processEvents()

    # --- захваты ---
    def open_cap(s, _=False, path=None, then=None):
        path = path or QFileDialog.getOpenFileName(s, "Захват", "", "PCAP (*.pcap *.pcapng)")[0]
        if path: s.run(f"Чтение {os.path.basename(path)}", lambda cb: core.read_capture(path, cb), lambda r: s._loaded(r, path, then))

    def _loaded(s, r, path, then):
        pk, info = r; s.pkts, s.cur, s.cur_id = pk, info["path"], info["id"]
        if not any(c["id"] == info["id"] for c in s.caps): s.caps.append(info)
        s.hex.show_bytes(b""); s.tree.clear(); s.model.set(pk); s.stack.setCurrentIndex(1)
        s.setWindowTitle(f"Лаборатория протоколов — {os.path.basename(path)}")
        s.statusBar().showMessage(f"{os.path.basename(path)}  ·  {len(pk)} пакетов  ·  {1 + max([q.stream for q in pk] + [-1])} TCP-потоков  ·  sha256 {info['sha256'][:16]}…")
        s.tl.set_data(pk); s.on_hyp(s.hl.currentRow())
        if pk: s.tbl.selectRow(0)
        s.toast(f"Загружено пакетов: {len(pk)}", "ok")
        if then: then()

    def on_pkt(s, r):
        if not 0 <= r < len(s.pkts): return
        p = s.pkts[r]; s.hex.show_bytes(p.raw); s.hex.fade()
        for n, a, b, col in layers(p): s.hex.mark(a, b, col, True)
        s.fill_tree(p)

    def fill_tree(s, p):
        s.tree.clear()
        for n, a, b, col in layers(p):
            it = QTreeWidgetItem([n, f"байты {a}–{b - 1}  ({b - a} B)"]); it.setForeground(0, QColor(col)); s.tree.addTopLevelItem(it)
            rows = {"IPv4": [("src → dst", f"{p.src} → {p.dst}")], "TCP": [("порты", f"{p.sport} → {p.dport}"), ("seq", p.seq), ("флаги", p.flags)],
                    "Payload": [("ASCII", "".join(chr(x) if 32 <= x < 127 else "." for x in p.payload[:60]))]}.get(n, [])
            for k, v in rows: QTreeWidgetItem(it, [k, str(v)])
        s.tree.expandAll()

    # --- гипотезы ---
    def add_item(s, h):
        it = QListWidgetItem(); s.hl.addItem(it); s.hl.setItemWidget(it, HypCard()); it.setSizeHint(QSize(0, 62)); s.paint(s.hl.count() - 1)

    def paint(s, i):
        h = s.hyps[i]; tot = sum(x["scope"] for x in h.results); hit = sum(x["hits"] for x in h.results); occ = sum(x["occurrences"] for x in h.results)
        s.hl.itemWidget(s.hl.item(i)).set(h.name, f"{hit}/{tot} пакетов · {occ} вхожд. · захватов: {len(h.results)}", hit / max(1, tot))

    def from_sel(s):
        r, sel = s.tbl.currentIndex().row(), s.hex.selected()
        if r < 0 or not sel: return s.toast("Выделите байты в hex-панели", "info")
        p = s.pkts[r]; a, b = sel; s.pat.setText(" ".join(f"{x:02x}" for x in p.raw[a:b]))
        inside = p.pay_len > 0 and a >= p.pay_off and b <= p.pay_off + p.pay_len
        s.layer.setCurrentIndex(0 if inside else 1); s.port.setValue(min(p.sport, p.dport) if p.stream >= 0 else 0)

    def add_hyp(s):
        if not s.cur: return s.toast("Сначала откройте захват", "info")
        h = core.Hyp(name=s.name.text() or f"H{len(s.hyps) + 1}", pattern=s.pat.text().strip(), port=s.port.value(),
                     note=s.note.toPlainText(), layer=["payload", "frame"][s.layer.currentIndex()])
        try: h.rx()
        except ValueError as e: return s.err(e, "Гипотеза")
        cur = s.cur; s.run("Проверка гипотезы", lambda cb: core.verify(h, cur, cb), lambda r: s._hyp_added(h, r))

    def _hyp_added(s, h, r):
        h.results = [r]; s.hyps.append(h); s.add_item(h); s.hl.setCurrentRow(len(s.hyps) - 1)
        s.toast(f"{h.name}: {r['hits']}/{r['scope']} пакетов", "ok")

    def more(s):
        i = s.hl.currentRow()
        if i < 0: return s.toast("Выберите гипотезу в списке", "info")
        files = QFileDialog.getOpenFileNames(s, "Дополнительные записи", "", "PCAP (*.pcap *.pcapng)")[0]
        if not files: return
        h = s.hyps[i]
        def fn(cb):
            out = []
            for k, p in enumerate(files):
                try: out.append((p, core.verify(h, p, lambda f, k=k: cb((k + f) / len(files))), ""))
                except (OSError, core.CaptureError) as e: out.append((p, None, f"{os.path.basename(p)}: {e}"))
            return out
        s.run("Проверка на записях", fn, lambda out: s._more_done(i, out))

    def _more_done(s, i, out):
        for p, r, e in out:
            if e: s.err(e, "Проверка"); continue
            if not any(c["id"] == r["capture_id"] for c in s.caps): s.caps.append(dict(id=r["capture_id"], path=str(Path(p).resolve()), sha256=r["sha256"]))
            s.hyps[i].results = [x for x in s.hyps[i].results if x["capture_id"] != r["capture_id"]] + [r]
        s.on_hyp(i); s.paint(i)

    def on_hyp(s, i):
        if i < 0: return
        h = s.hyps[i]; s.name.setText(h.name); s.pat.setText(h.pattern); s.port.setValue(h.port); s.note.setPlainText(h.note)
        s.layer.setCurrentIndex(int(h.layer == "frame")); lab = lambda r: f'{r["capture"]} [{r["capture_id"][:6]}]'
        s.sum.setPlainText("\n".join(f'{lab(r)}: {r["hits"]}/{r["scope"]} пакетов, вхождений: {r["occurrences"]}'
                                     f'{" (показаны не все)" if r["occurrences"] > len(r["evidence"]) else ""}' for r in h.results))
        s.ev = [(r["capture_id"], lab(r), e) for r in h.results for e in r["evidence"]]; s.res.setRowCount(len(s.ev))
        for k, (cid, nm, e) in enumerate(s.ev):
            for j, v in enumerate([nm, e["pkt"], e["off"], e["len"]]): s.res.setItem(k, j, QTableWidgetItem(str(v)))
        s.tl.set_data(s.pkts, [e["pkt"] for cid, nm, e in s.ev if cid == s.cur_id])

    def goto(s, row, _):
        cid, _n, e = s.ev[row]; cap = next((c for c in s.caps if c["id"] == cid), None)
        if not cap: return s.err("захват этого доказательства не загружен", "Доказательство")
        if cid != s.cur_id: s.open_cap(path=cap["path"], then=lambda: s._show_ev(cid, e))
        else: s._show_ev(cid, e)

    def _show_ev(s, cid, e):
        if s.cur_id != cid: return s.err("файл изменён после проверки (другой SHA-256)", "Доказательство")
        if not 1 <= e["pkt"] <= len(s.pkts): return s.err("номер пакета вне диапазона", "Доказательство")
        p = s.pkts[e["pkt"] - 1]; a = e["off"] - p.file_off
        if a < 0 or a + e["len"] > len(p.raw): return s.err("смещение вне кадра", "Доказательство")
        s.tabs.setCurrentIndex(0); s.tbl.selectRow(e["pkt"] - 1); s.hex.flash(a, a + e["len"])

    def goto_pkt(s, no): s.tbl.selectRow(no - 1)

    # --- проект ---
    def save_proj(s):
        p = s.proj or QFileDialog.getSaveFileName(s, "Проект", "", "JSON (*.json)")[0]
        if not p: return
        try: core.save(p, s.caps, s.hyps); s.proj = p; s.toast("Проект сохранён", "ok")
        except OSError as e: s.err(e, "Сохранение")

    def open_proj(s, _=False, path=None):
        p = path or QFileDialog.getOpenFileName(s, "Проект", "", "JSON (*.json)")[0]
        if not p: return
        def fn(cb):
            caps, hyps = core.load(p); bad = []
            for k, c in enumerate(caps):
                try:
                    if core.sha256(c["path"]) != c["sha256"]: bad.append(c["path"] + " (хеш не совпал)")
                except OSError as e: bad.append(f'{c["path"]} ({e.strerror or e})')
                cb((k + 1) / len(caps))
            return caps, hyps, bad
        s.run("Открытие проекта", fn, lambda r: s._proj_loaded(p, *r))

    def _proj_loaded(s, p, caps, hyps, bad):
        s.caps, s.hyps, s.proj = caps, hyps, p; s.hl.clear()
        for h in hyps: s.add_item(h)
        if bad: s.err("; ".join(bad), "Целостность")
        elif caps: s.open_cap(path=caps[0]["path"])


def main():
    a = QApplication(sys.argv); dark(a); w = Win(); w.show(); sys.exit(a.exec())
