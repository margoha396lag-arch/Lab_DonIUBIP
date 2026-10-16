import math
from PySide6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, QRectF, QSize, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QIcon, QLinearGradient, QPainter, QPalette, QPen, QPixmap, QPolygonF, QTextCursor
from PySide6.QtWidgets import QGraphicsOpacityEffect, QLabel, QPlainTextEdit, QTextEdit, QWidget

PAL = ["#4fc3f7", "#81c784", "#ffb74d", "#ba68c8", "#f06292", "#4db6ac", "#fff176", "#a1887f"]
LAYERS = [("Ethernet", "#3b6ea5"), ("IPv4", "#3f8f5b"), ("TCP", "#b9772f"), ("Payload", "#c9a227")]
QSS = """
QMainWindow,QWidget{background:#1b1d22;color:#e6e6e6;font-size:13px}
QToolBar{background:#23262d;border:0;padding:6px;spacing:6px}
QToolButton{background:#2c3038;border:1px solid #3a3f4a;border-radius:8px;padding:6px 12px}
QToolButton:hover{background:#3b4252;border-color:#5aa9ff}QToolButton:pressed{background:#2a62a8}
QPushButton{background:#2c3038;border:1px solid #3a3f4a;border-radius:8px;padding:7px 10px}
QPushButton:hover{background:#38507a;border-color:#5aa9ff}QPushButton:pressed{background:#2a62a8}
QLineEdit,QPlainTextEdit,QSpinBox,QComboBox,QTreeWidget,QTableView,QListWidget{background:#14161a;border:1px solid #30343d;border-radius:8px;selection-background-color:#2f6db5}
QLineEdit:focus,QPlainTextEdit:focus,QSpinBox:focus,QComboBox:focus{border-color:#5aa9ff}
QHeaderView::section{background:#23262d;border:0;padding:5px;color:#9aa4b2}
QTabBar::tab{background:#23262d;padding:7px 16px;border-top-left-radius:8px;border-top-right-radius:8px;margin-right:2px}
QTabBar::tab:hover{background:#2f3542}QTabBar::tab:selected{background:#2f6db5}
QTabWidget::pane{border:1px solid #30343d;border-radius:8px}
QScrollBar:vertical{background:transparent;width:10px}QScrollBar:horizontal{background:transparent;height:10px}
QScrollBar::handle{background:#3d4350;border-radius:5px;min-height:24px;min-width:24px}QScrollBar::handle:hover{background:#5aa9ff}
QScrollBar::add-line,QScrollBar::sub-line{height:0;width:0}
QProgressBar{background:#14161a;border:1px solid #30343d;border-radius:7px;text-align:center;min-height:16px}
QProgressBar::chunk{border-radius:6px;background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5aa9ff,stop:1 #8be9c0)}
QStatusBar{background:#23262d}QSplitter::handle{background:#23262d}QSplitter::handle:hover{background:#5aa9ff}
"""


def anim(parent, a, b, ms, slot, curve=QEasingCurve.OutCubic, loop=1):
    x = QVariantAnimation(parent); x.setStartValue(a); x.setEndValue(b); x.setDuration(ms)
    x.setEasingCurve(curve); x.setLoopCount(loop); x.valueChanged.connect(slot); return x


def layers(p):
    if p.stream < 0: return []
    bounds = [0, p.l3, p.t4, p.pay_off, p.pay_off + p.pay_len]
    return [(n, bounds[i], bounds[i + 1], c) for i, (n, c) in enumerate(LAYERS)]


def icon(kind):
    pm = QPixmap(32, 32); pm.fill(Qt.transparent)
    p = QPainter(pm); p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor("#e6e6e6"), 2.2)); p.setBrush(QColor(PAL[["cap", "proj", "save", "check"].index(kind)]))
    if kind == "cap": p.drawRoundedRect(4, 9, 24, 18, 3, 3); p.drawRect(4, 5, 10, 4)
    elif kind == "proj": p.drawRoundedRect(6, 4, 20, 24, 3, 3); p.drawLine(11, 12, 21, 12); p.drawLine(11, 18, 21, 18)
    elif kind == "save": p.drawRoundedRect(5, 5, 22, 22, 3, 3); p.drawRect(10, 5, 12, 8)
    else: p.drawEllipse(4, 4, 24, 24); p.setBrush(Qt.NoBrush); p.drawPolyline(QPolygonF([QPointF(10, 17), QPointF(14, 21), QPointF(22, 11)]))
    p.end(); return QIcon(pm)


def dark(app):
    app.setStyle("Fusion"); pal = QPalette()
    for r, c in [(QPalette.Window, "#1b1d22"), (QPalette.WindowText, "#e6e6e6"), (QPalette.Base, "#14161a"),
                 (QPalette.AlternateBase, "#25272b"), (QPalette.Text, "#e6e6e6"), (QPalette.Button, "#2c3038"),
                 (QPalette.ButtonText, "#e6e6e6"), (QPalette.Highlight, "#2f6db5"), (QPalette.HighlightedText, "#ffffff")]:
        pal.setColor(r, QColor(c))
    app.setPalette(pal); app.setStyleSheet(QSS)


class Hex(QPlainTextEdit):
    """Hex-просмотрщик: цветные слои, плавное появление и пульсирующая подсветка доказательства."""
    def __init__(s):
        super().__init__(); s.setReadOnly(True); s.setLineWrapMode(QPlainTextEdit.NoWrap); s.setFont(QFont("Monospace", 10))
        s.fx = QGraphicsOpacityEffect(s); s.fx.setOpacity(1.0); s.setGraphicsEffect(s.fx)
        s.fa = QPropertyAnimation(s.fx, b"opacity", s); s.fa.setDuration(220); s.fl = None

    def fade(s): s.fa.stop(); s.fa.setStartValue(0.3); s.fa.setEndValue(1.0); s.fa.start()

    def show_bytes(s, data):
        rows = []
        for i in range(0, len(data), 16):
            c = data[i:i + 16]
            rows.append(f"{i:08x}  " + " ".join(f"{b:02x}" for b in c).ljust(47) + "  " + "".join(chr(b) if 32 <= b < 127 else "." for b in c))
        s.setPlainText("\n".join(rows)); s.setExtraSelections([])

    def _sel(s, a, b, col, fg):
        sels = []
        for ln in range(a // 16, (b - 1) // 16 + 1) if b > a else []:
            lo, hi = max(a, ln * 16) - ln * 16, min(b, ln * 16 + 16) - ln * 16
            blk = s.document().findBlockByNumber(ln)
            c = QTextCursor(blk); c.setPosition(blk.position() + 10 + 3 * lo)
            c.setPosition(blk.position() + 10 + 3 * hi - 1, QTextCursor.KeepAnchor)
            e = QTextEdit.ExtraSelection(); e.cursor = c; e.format.setBackground(QColor(col)); e.format.setForeground(QColor(fg)); sels.append(e)
        return sels

    def mark(s, a, b, col="#ffd54f", keep=False):
        s.setExtraSelections((list(s.extraSelections()) if keep else []) + s._sel(a, b, col, "#000" if col == "#ffd54f" else "#fff"))

    def flash(s, a, b):
        base = list(s.extraSelections()); c1, c2 = QColor("#ffd54f"), QColor("#ff7043")
        def step(v):
            k = 0.5 + 0.5 * math.sin(v * 6 * math.pi)
            col = QColor(*(int(x + (y - x) * k) for x, y in ((c1.red(), c2.red()), (c1.green(), c2.green()), (c1.blue(), c2.blue()))))
            s.setExtraSelections(base + s._sel(a, b, col.name(), "#000"))
        if s.fl: s.fl.stop()
        s.fl = anim(s, 0.0, 1.0, 1100, step, QEasingCurve.Linear)
        s.fl.finished.connect(lambda: s.setExtraSelections(base + s._sel(a, b, "#ffd54f", "#000"))); s.fl.start()

    def selected(s):
        c = s.textCursor()
        if not c.hasSelection(): return None
        def idx(p):
            blk = s.document().findBlock(p)
            return blk.blockNumber() * 16 + min(15, max(0, (p - blk.position() - 10) // 3))
        a, b = idx(c.selectionStart()), idx(c.selectionEnd() - 1) + 1
        return (a, b) if b > a else None


class Timeline(QWidget):
    """Дорожки потоков: точки «вырастают» при загрузке, совпадения пульсируют, наведение показывает пакет."""
    def __init__(s, on_pick):
        super().__init__(); s.on_pick, s.pk, s.hits, s.pts, s.hov, s.grow, s.phase = on_pick, [], set(), [], None, 1.0, 0.0
        s.setMouseTracking(True); s.setMinimumHeight(160)
        s.ga = anim(s, 0.0, 1.0, 1000, s._g); s.pa = anim(s, 0.0, 1.0, 1500, s._p, QEasingCurve.Linear, -1); s.pa.start()

    def _g(s, v): s.grow = v; s.update()
    def _p(s, v):
        s.phase = v
        if s.hits and s.isVisible(): s.update()

    def set_data(s, pk, hits=()):
        new = pk is not s.pk; s.pk, s.hits = pk, set(hits)
        if new: s.ga.stop(); s.ga.start()
        s.update()

    def paintEvent(s, _):
        p = QPainter(s); p.setRenderHint(QPainter.Antialiasing); s.pts = []
        bg = QLinearGradient(0, 0, 0, s.height()); bg.setColorAt(0, QColor("#14161a")); bg.setColorAt(1, QColor("#1c2029")); p.fillRect(s.rect(), bg)
        if not s.pk: return
        r = s.rect().adjusted(44, 12, -14, -28); t0 = s.pk[0].ts; span = max(1e-9, s.pk[-1].ts - t0)
        n = max(1, 1 + max(q.stream for q in s.pk)); mx = max([q.pay_len for q in s.pk] + [1]); last = {}
        for k in range(n):
            y = r.top() + (k + .5) * r.height() / n
            p.setPen(QPen(QColor("#3a3f4a"), 1, Qt.DashLine)); p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))
            p.setPen(QColor(PAL[k % 8])); p.drawText(6, int(y) + 4, f"#{k}")
        pulse = math.sin(s.phase * 2 * math.pi)
        for q in s.pk:
            if q.stream < 0: continue
            xf = (q.ts - t0) / span; x = r.left() + xf * r.width(); y = r.top() + (q.stream + .5) * r.height() / n
            g = max(0.0, min(1.0, s.grow * 1.6 - xf * 0.6)); rad = (3 + 9 * q.pay_len / mx) * g; c = QColor(PAL[q.stream % 8])
            if q.stream in last:
                lc = QColor(c); lc.setAlpha(80); p.setPen(QPen(lc, 1.2)); p.drawLine(last[q.stream], QPointF(x, y))
            last[q.stream] = QPointF(x, y); s.pts.append((x, y, q.no, rad, q.pay_len))
            p.setPen(QPen(c, 1.6)); p.setBrush(c if q.pay_len else Qt.NoBrush); p.drawEllipse(QPointF(x, y), rad, rad)
            if q.no in s.hits and g > 0.9:
                w = QColor("#ffffff"); w.setAlphaF(0.65 + 0.35 * pulse); p.setPen(QPen(w, 2.2)); p.setBrush(Qt.NoBrush)
                p.drawEllipse(QPointF(x, y), rad + 5 + 2.5 * pulse, rad + 5 + 2.5 * pulse)
        h = next((t for t in s.pts if t[2] == s.hov), None)
        if h:
            p.setPen(QPen(QColor("#fff"), 2)); p.setBrush(Qt.NoBrush); p.drawEllipse(QPointF(h[0], h[1]), h[3] + 3, h[3] + 3)
            box = QRectF(min(h[0] + 10, s.width() - 110), max(2, h[1] - 34), 100, 22); p.setPen(Qt.NoPen); p.setBrush(QColor("#000000c0"))
            p.drawRoundedRect(box, 6, 6); p.setPen(QColor("#fff")); p.drawText(box, Qt.AlignCenter, f"№{h[2]} · {h[4]} B")
        p.setPen(QColor("#8a93a3")); p.drawText(r.left(), s.height() - 8, f"0 … {span:.3f} с    размер = payload,  пульсирующее кольцо = совпадение гипотезы")

    def _near(s, e, lim=1e9):
        if not s.pts: return None
        b = min(s.pts, key=lambda t: (t[0] - e.position().x()) ** 2 + (t[1] - e.position().y()) ** 2)
        return b if (b[0] - e.position().x()) ** 2 + (b[1] - e.position().y()) ** 2 <= lim else None

    def mouseMoveEvent(s, e):
        b = s._near(e, 18 ** 2); s.hov = b[2] if b else None
        s.setCursor(Qt.PointingHandCursor if b else Qt.ArrowCursor); s.update()

    def leaveEvent(s, _): s.hov = None; s.update()

    def mousePressEvent(s, e):
        b = s._near(e)
        if b: s.on_pick(b[2])


class Welcome(QWidget):
    """Пустое состояние: пульсирующие кольца и подсказка про drag&drop."""
    def __init__(s):
        super().__init__(); s.t = 0.0; s.a = anim(s, 0.0, 1.0, 3000, s._t, QEasingCurve.Linear, -1); s.a.start()

    def _t(s, v):
        s.t = v
        if s.isVisible(): s.update()

    def paintEvent(s, _):
        p = QPainter(s); p.setRenderHint(QPainter.Antialiasing); c = QPointF(s.width() / 2, s.height() / 2 - 40)
        for k in range(3):
            f = (s.t + k / 3) % 1; col = QColor("#5aa9ff"); col.setAlphaF((1 - f) * 0.55)
            p.setPen(QPen(col, 2)); p.setBrush(Qt.NoBrush); p.drawEllipse(c, 34 + 110 * f, 34 + 110 * f)
        p.setPen(Qt.NoPen); p.setBrush(QColor("#2f6db5")); p.drawEllipse(c, 34, 34)
        p.setPen(QPen(QColor("#fff"), 4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)); off = 3 * math.sin(s.t * 2 * math.pi)
        p.drawLine(QPointF(c.x(), c.y() - 12 + off), QPointF(c.x(), c.y() + 10 + off))
        p.drawPolyline(QPolygonF([QPointF(c.x() - 9, c.y() + 2 + off), QPointF(c.x(), c.y() + 12 + off), QPointF(c.x() + 9, c.y() + 2 + off)]))
        f = QFont(); f.setPointSize(15); p.setFont(f); p.setPen(QColor("#e6e6e6"))
        p.drawText(QRectF(0, c.y() + 90, s.width(), 30), Qt.AlignCenter, "Перетащите .pcap / .pcapng сюда")
        f.setPointSize(10); p.setFont(f); p.setPen(QColor("#8a93a3"))
        p.drawText(QRectF(0, c.y() + 124, s.width(), 24), Qt.AlignCenter, "или «Открыть захват» / «Открыть проект» на панели")


class HypCard(QWidget):
    """Карточка гипотезы: анимированная полоса доли совпадений и счётчик процентов."""
    def __init__(s):
        super().__init__(); s.name, s.sub, s.hit = "", "", 0.0; s.an = anim(s, 0.0, 0.0, 700, s._v)

    def _v(s, v): s.hit = v; s.update()
    def sizeHint(s): return QSize(220, 60)

    def set(s, name, sub, rate):
        s.name, s.sub = name, sub; s.an.stop(); s.an.setStartValue(s.hit); s.an.setEndValue(float(rate)); s.an.start()

    def paintEvent(s, _):
        p = QPainter(s); p.setRenderHint(QPainter.Antialiasing); r = QRectF(s.rect()).adjusted(2, 2, -2, -2)
        p.setPen(Qt.NoPen); p.setBrush(QColor(255, 255, 255, 14)); p.drawRoundedRect(r, 8, 8)
        col = QColor("#81c784" if s.hit >= .8 else "#ffb74d" if s.hit >= .4 else "#e57373")
        f = QFont(); f.setBold(True); p.setFont(f); p.setPen(QColor("#e6e6e6")); p.drawText(QRectF(r.left() + 10, r.top() + 4, r.width() - 70, 20), Qt.AlignLeft | Qt.AlignVCenter, s.name)
        p.setPen(col); p.drawText(QRectF(r.right() - 60, r.top() + 4, 52, 20), Qt.AlignRight | Qt.AlignVCenter, f"{int(s.hit * 100)}%")
        f.setBold(False); f.setPointSize(9); p.setFont(f); p.setPen(QColor("#8a93a3")); p.drawText(QRectF(r.left() + 10, r.top() + 24, r.width() - 20, 16), Qt.AlignLeft, s.sub)
        tr = QRectF(r.left() + 10, r.bottom() - 12, r.width() - 20, 6); p.setBrush(QColor("#0f1115")); p.drawRoundedRect(tr, 3, 3)
        g = QLinearGradient(tr.left(), 0, tr.right(), 0); g.setColorAt(0, col.darker(140)); g.setColorAt(1, col); p.setBrush(g)
        p.drawRoundedRect(QRectF(tr.left(), tr.top(), max(0.0, tr.width() * s.hit), tr.height()), 3, 3)


class Toast(QLabel):
    """Всплывающее уведомление: выезжает снизу, плавно исчезает."""
    def __init__(s, parent):
        super().__init__(parent); s.setWordWrap(True); s.hide(); s.fx = QGraphicsOpacityEffect(s); s.setGraphicsEffect(s.fx)
        s.oa = QPropertyAnimation(s.fx, b"opacity", s); s.pa = QPropertyAnimation(s, b"pos", s); s.pa.setEasingCurve(QEasingCurve.OutCubic)
        s.t = QTimer(s); s.t.setSingleShot(True); s.t.timeout.connect(s._fade); s.oa.finished.connect(s._end)

    def say(s, text, kind="info"):
        col = {"err": "#e5484d", "ok": "#30a46c", "info": "#3b82f6"}[kind]; s.oa.stop(); s.pa.stop(); s.t.stop()
        s.setStyleSheet(f"background:#23262d;border:1px solid {col};border-left:5px solid {col};border-radius:8px;padding:10px 14px;color:#fff")
        s.setText(text); s.setFixedWidth(min(480, max(200, s.parent().width() - 40))); s.adjustSize()
        end = QPointF(s.parent().width() - s.width() - 20, s.parent().height() - s.height() - 52); s.move(end.toPoint() + QPointF(0, 28).toPoint())
        s.fx.setOpacity(0.0); s.raise_(); s.show()
        s.pa.setDuration(260); s.pa.setStartValue(s.pos()); s.pa.setEndValue(end.toPoint()); s.pa.start()
        s.oa.setDuration(260); s.oa.setStartValue(0.0); s.oa.setEndValue(1.0); s.oa.start(); s.t.start(3800 if kind != "err" else 6000)

    def _fade(s): s.oa.setDuration(450); s.oa.setStartValue(1.0); s.oa.setEndValue(0.0); s.oa.start()
    def _end(s):
        if s.fx.opacity() == 0: s.hide()
