"""Ядро ProtoLab: PCAP/PCAPNG, Ethernet(+VLAN)/IPv4/TCP, гипотезы, проект."""
import hashlib, json, os, re, struct
from dataclasses import asdict, dataclass, field
from pathlib import Path

VERSION, MAX_EVIDENCE = 2, 2000


class CaptureError(ValueError):
    """Повреждённый или неподдерживаемый захват."""


class Cancelled(Exception):
    """Операция отменена пользователем (из callback прогресса)."""


class ProjectError(ValueError):
    """Некорректный файл проекта."""


@dataclass
class Pkt:
    no: int
    ts: float
    file_off: int          # смещение кадра в файле захвата
    raw: bytes
    src: str = ""; dst: str = ""; sport: int = 0; dport: int = 0
    flags: str = ""; seq: int = 0; pay_off: int = 0; pay_len: int = 0; stream: int = -1
    l3: int = 14; t4: int = 0; note: str = ""

    @property
    def payload(self):
        return self.raw[self.pay_off:self.pay_off + self.pay_len]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


_PCAP = {b"\xd4\xc3\xb2\xa1": ("<", 10**6), b"\xa1\xb2\xc3\xd4": (">", 10**6),
         b"\x4d\x3c\xb2\xa1": ("<", 10**9), b"\xa1\xb2\x3c\x4d": (">", 10**9)}


def _pcap(d):
    e, div = _PCAP[d[:4]]
    if len(d) < 24: raise CaptureError("Усечён глобальный заголовок PCAP")
    link, pos, n = struct.unpack_from(e + "I", d, 20)[0] & 0x0FFFFFFF, 24, 0
    while pos < len(d):
        n += 1
        if pos + 16 > len(d): raise CaptureError(f"Запись {n}: усечён заголовок (смещение {pos})")
        s, sub, cap, orig = struct.unpack_from(e + "IIII", d, pos)
        if cap > orig: raise CaptureError(f"Запись {n}: caplen {cap} > origlen {orig} (смещение {pos})")
        if pos + 16 + cap > len(d):
            raise CaptureError(f"Запись {n}: заявлено {cap} байт, в файле {len(d) - pos - 16} (смещение {pos})")
        yield pos + 16, s + sub / div, cap, link
        pos += 16 + cap


def _pcapng(d):
    pos, e, ifs, n = 0, "<", [], 0          # ifs: (linktype, делитель времени, snaplen) текущей секции
    while pos < len(d):
        n += 1
        if pos + 12 > len(d): raise CaptureError(f"Блок {n}: усечён заголовок (смещение {pos})")
        if d[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
            e = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(d[pos + 8:pos + 12])
            if not e: raise CaptureError(f"Блок {n}: неверный byte-order magic (смещение {pos})")
            ifs = []                         # новая секция — новая таблица интерфейсов
        t, ln = struct.unpack_from(e + "II", d, pos)
        if ln < 12 or ln % 4 or pos + ln > len(d): raise CaptureError(f"Блок {n}: недопустимая длина {ln} (смещение {pos})")
        if struct.unpack_from(e + "I", d, pos + ln - 4)[0] != ln:
            raise CaptureError(f"Блок {n}: завершающая длина не совпадает (смещение {pos})")
        end = pos + ln - 4
        if t == 1:                           # Interface Description Block
            if ln < 20: raise CaptureError(f"Блок {n}: слишком короткий IDB (смещение {pos})")
            lt, _, snap = struct.unpack_from(e + "HHI", d, pos + 8); div, o = 10**6, pos + 16
            while o + 4 <= end:
                code, ol = struct.unpack_from(e + "HH", d, o)
                if code == 0: break
                if o + 4 + ol > end: raise CaptureError(f"Блок {n}: опция выходит за блок (смещение {o})")
                if code == 9 and ol >= 1:    # if_tsresol
                    v = d[o + 4]; div = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                o += 4 + ol + (-ol % 4)
            ifs.append((lt, div, snap))
        elif t == 6:                         # Enhanced Packet Block
            if ln < 32: raise CaptureError(f"Блок {n}: слишком короткий EPB (смещение {pos})")
            i, hi, lo, cap, orig = struct.unpack_from(e + "IIIII", d, pos + 8)
            if i >= len(ifs): raise CaptureError(f"Блок {n}: неизвестный интерфейс {i} (смещение {pos})")
            if cap > orig or pos + 28 + cap > end: raise CaptureError(f"Блок {n}: неверный caplen {cap} (смещение {pos})")
            yield pos + 28, ((hi << 32) | lo) / ifs[i][1], cap, ifs[i][0]
        elif t == 3:                         # Simple Packet Block: без времени (ts=0.0), интерфейс 0
            if not ifs or ln < 16: raise CaptureError(f"Блок {n}: SPB без интерфейса или слишком короткий (смещение {pos})")
            orig = struct.unpack_from(e + "I", d, pos + 8)[0]; cap = min(orig, ifs[0][2] or orig)
            if pos + 12 + cap > end: raise CaptureError(f"Блок {n}: данные SPB выходят за блок (смещение {pos})")
            yield pos + 12, 0.0, cap, ifs[0][0]
        pos += ln


def _tcp(p, streams):
    """Разбор Ethernet(+VLAN)/IPv4/TCP с проверкой границ. Неразобранное остаётся stream=-1."""
    fr, l3 = p.raw, 14
    if len(fr) < 14: return
    et = fr[12:14]
    while et in (b"\x81\x00", b"\x88\xa8"):
        if len(fr) < l3 + 4: return
        et = fr[l3 + 2:l3 + 4]; l3 += 4
    if et != b"\x08\x00" or len(fr) < l3 + 20: return
    ihl = (fr[l3] & 15) * 4
    if fr[l3] >> 4 != 4 or ihl < 20 or fr[l3 + 9] != 6: return
    tot, = struct.unpack_from(">H", fr, l3 + 2); ff, = struct.unpack_from(">H", fr, l3 + 6)
    if ff & 0x3FFF:
        p.note = "IP-фрагмент: не анализируется"; return
    t, end = l3 + ihl, min(len(fr), l3 + tot)
    if tot < ihl + 20 or t + 20 > end: return
    doff = (fr[t + 12] >> 4) * 4
    if doff < 20 or t + doff > end: return
    p.l3, p.t4 = l3, t
    p.src, p.dst = ".".join(map(str, fr[l3 + 12:l3 + 16])), ".".join(map(str, fr[l3 + 16:l3 + 20]))
    p.sport, p.dport, p.seq = struct.unpack_from(">HHI", fr, t)
    p.flags = "".join(n for b, n in zip((2, 16, 8, 1, 4), "SAPFR") if fr[t + 13] & b)
    p.pay_off, p.pay_len = t + doff, end - (t + doff)
    p.stream = streams.setdefault(frozenset([(p.src, p.sport), (p.dst, p.dport)]), len(streams))


def parse_bytes(d, progress=None):
    """Кадры — memoryview-срезы исходного буфера (без копирования); progress(0..1) может бросить Cancelled."""
    if d[:4] == b"\x0a\x0d\x0d\x0a": recs = _pcapng(d)
    elif d[:4] in _PCAP: recs = _pcap(d)
    else: raise CaptureError("Не PCAP/PCAPNG (неизвестная сигнатура или пустой файл)")
    out, streams, mv, n = [], {}, memoryview(d), len(d) or 1
    try:
        for no, (off, ts, cap, lt) in enumerate(recs, 1):
            p = Pkt(no, ts, off, mv[off:off + cap])
            if lt == 1: _tcp(p, streams)
            out.append(p)
            if progress and no % 256 == 0: progress(off / n)
    except (struct.error, IndexError) as e:
        raise CaptureError(f"Повреждённая структура файла: {e}") from e
    if progress: progress(1.0)
    return out


def parse(path):
    return parse_bytes(Path(path).read_bytes())


def read_capture(path, progress=None):
    """Один проход по файлу: пакеты + описание захвата (id = начало SHA-256)."""
    d = Path(path).read_bytes(); sha = hashlib.sha256(d).hexdigest()
    return parse_bytes(d, progress), dict(id=sha[:16], path=str(Path(path).resolve()), sha256=sha)


def cap_info(path):
    return read_capture(path)[1]


@dataclass
class Hyp:
    name: str
    pattern: str            # hex-байты через пробел, "??" = любой байт
    port: int = 0           # 0 = любой TCP-порт
    note: str = ""
    results: list = field(default_factory=list)   # по одному результату на захват (capture_id)
    layer: str = "payload"  # область поиска: "payload" TCP или "frame" (весь кадр)

    def rx(self):
        toks = self.pattern.split()
        if not toks: raise ValueError("Паттерн пуст")
        if self.layer not in ("payload", "frame"): raise ValueError(f"Неизвестная область поиска: {self.layer}")
        if not (isinstance(self.port, int) and 0 <= self.port <= 65535): raise ValueError("Порт вне диапазона 0–65535")
        parts = []
        for t in toks:
            if t == "??": parts.append(b".")
            elif re.fullmatch(r"[0-9a-fA-F]{2}", t): parts.append(re.escape(bytes.fromhex(t)))
            else: raise ValueError(f"Недопустимый токен «{t}»: нужны байты вида 4d или ??")
        if all(t == "??" for t in toks): raise ValueError("Паттерн должен содержать хотя бы один конкретный байт")
        return re.compile(b"(?=(" + b"".join(parts) + b"))", re.S)   # lookahead: находит и перекрывающиеся


def verify(h, path, progress=None):
    """hits = пакеты с совпадением; occurrences = все вхождения; evidence = абсолютные смещения в файле."""
    rx = h.rx(); d = Path(path).read_bytes(); sha = hashlib.sha256(d).hexdigest()
    scope = hits = occ = 0; ev = []
    for p in parse_bytes(d, progress):
        if h.port and h.port not in (p.sport, p.dport): continue
        if h.layer == "payload":
            if not p.pay_len: continue
            buf, base = p.payload, p.pay_off
        else:
            buf, base = p.raw, 0
        scope += 1; found = 0
        for m in rx.finditer(buf):
            found += 1; occ += 1
            if len(ev) < MAX_EVIDENCE:
                ev.append(dict(pkt=p.no, off=p.file_off + base + m.start(1), len=m.end(1) - m.start(1)))
        hits += bool(found)
    return dict(capture_id=sha[:16], capture=Path(path).name, sha256=sha, scope=scope, hits=hits, occurrences=occ, evidence=ev)


def save(path, caps, hyps):
    base = Path(path).resolve().parent
    cs = [dict(id=c["id"], path=os.path.relpath(c["path"], base), sha256=c["sha256"]) for c in caps]
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(dict(version=VERSION, captures=cs, hyps=[asdict(h) for h in hyps]),
                              indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)                    # атомарно: старый проект не портится при сбое


_RES = dict(capture_id=str, capture=str, sha256=str, scope=int, hits=int, occurrences=int, evidence=list)


def _check_res(r):
    for k, t in _RES.items():
        if not isinstance(r[k], t) or isinstance(r[k], bool): raise TypeError(f"results.{k}")
    for e in r["evidence"]:
        if not all(isinstance(e[k], int) and e[k] >= 0 for k in ("pkt", "off", "len")) or e["len"] < 1 or e["pkt"] < 1:
            raise ValueError("evidence")


def load(path):
    try: d = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e: raise ProjectError(f"Некорректный JSON: {e}") from e
    if not isinstance(d, dict) or d.get("version") != VERSION:
        raise ProjectError(f"Неподдерживаемая версия проекта: {d.get('version') if isinstance(d, dict) else '?'} (нужна {VERSION}); пересоздайте проект")
    base, caps, hyps = Path(path).resolve().parent, [], []
    try:
        for c in d["captures"]:
            if not all(isinstance(c[k], str) for k in ("id", "path", "sha256")): raise TypeError("captures")
            caps.append(dict(id=c["id"], path=str(base / c["path"]), sha256=c["sha256"]))
        for h in d["hyps"]:
            hy = Hyp(**h); hy.rx()
            if not isinstance(hy.results, list): raise TypeError("results")
            for r in hy.results: _check_res(r)
            hyps.append(hy)
    except (KeyError, TypeError, ValueError) as e:
        raise ProjectError(f"Недопустимая структура проекта: {e!r}") from e
    return caps, hyps
