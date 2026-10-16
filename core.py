import sys

if len(sys.argv) >= 3 and sys.argv[1] == "verify":      # воспроизведение без GUI
    from . import core
    try: caps, hyps = core.load(sys.argv[2])
    except (OSError, core.ProjectError) as e:
        print("ОШИБКА ПРОЕКТА:", e); sys.exit(2)
    byid, bad = {c["id"]: c for c in caps}, 0
    for c in caps:
        try: ok = core.sha256(c["path"]) == c["sha256"]
        except OSError as e:
            print("НЕТ ФАЙЛА:", c["path"], e.strerror); bad += 1; continue
        if not ok: print("ХЕШ НЕ СОВПАЛ:", c["path"]); bad += 1
    for h in hyps:
        for r0 in h.results:
            c, r = byid.get(r0["capture_id"]), None
            if c:
                try: r = core.verify(h, c["path"])
                except (OSError, core.CaptureError) as e: print("ОШИБКА:", e)
            ok = r == r0; bad += not ok                  # сравнивается весь результат, включая sha256 и доказательства
            print("OK  " if ok else "DIFF", h.name, r0["capture"], f'{r0["hits"]}/{r0["scope"]}')
    sys.exit(1 if bad else 0)
from .gui import main
main()
