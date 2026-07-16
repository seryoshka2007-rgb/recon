"""
Local Recon Suite (Windows)
--------------------------------
Комплексный enumeration-скрипт для локальной машины: собирает информацию
по нескольким категориям сразу и складывает всё в один CSV с колонкой
"category" для удобной фильтрации.

ВАЖНО — что этот скрипт делает и чего НЕ делает:
- Делает: перечисление (enumeration) — что установлено, кто есть в системе,
  что в автозагрузке, какие шары/сессии/креды ИМЕНАМИ значатся в системе.
- НЕ делает: не расшифровывает пароли из Credential Manager, RDP, браузеров
  и т.п. через DPAPI. Это отдельная, гораздо более чувствительная категория
  инструментов (в духе Mimikatz/LaZagne) и сюда сознательно не включена.
  Исключение — Wi-Fi ключи через netsh (see wifi_password_viewer.py):
  это отдельный штатный, задокументированный Microsoft функционал ОС.

Категории:
  system      — версия ОС, хост, домен/рабочая группа, архитектура
  software    — установленное ПО (из реестра Uninstall)
  users       — локальные пользователи и группы
  autoruns    — автозагрузка (Run-ключи реестра) и задачи планировщика
  shares      — сетевые расшаренные папки
  creds_list  — ИМЕНА сохранённых записей в Credential Manager (без паролей)

Требования: Windows, Python 3.7+
Права: часть данных (некоторые задачи планировщика, доступ к чужим
профилям) требует запуска от администратора — без прав эти пункты
просто будут пропущены с пометкой в выводе, скрипт не упадёт.
"""

import subprocess
import re
import sys
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Кодировка / запуск внешних команд
# ---------------------------------------------------------------------------

def _decode_bytes(raw: bytes) -> str:
    """См. обоснование порядка попыток в wifi_password_viewer.py."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if sys.platform.startswith("win"):
        import ctypes
        for getter in (
            lambda: ctypes.windll.kernel32.GetConsoleOutputCP(),
            lambda: ctypes.windll.kernel32.GetOEMCP(),
        ):
            try:
                cp = getter()
                if cp:
                    return raw.decode(f"cp{cp}")
            except Exception:
                continue
    return raw.decode("utf-8", errors="replace")


def run_cmd(args: list[str], timeout: int = 30) -> str:
    """
    Запускает команду без shell=True. Не бросает исключение при ненулевом
    коде возврата — некоторые команды (например net localgroup без прав)
    возвращают ошибку, но это не должно останавливать весь recon.
    """
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout
        )
        return _decode_bytes(proc.stdout + proc.stderr)
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return "[команда не найдена]"
    except Exception as e:
        return f"[ошибка запуска: {e}]"


# ---------------------------------------------------------------------------
# Модули сбора данных — каждый изолирован try/except, чтобы падение одного
# модуля (например из-за нехватки прав) не убивало остальной recon
# ---------------------------------------------------------------------------

def collect_system() -> list[dict]:
    rows = []
    try:
        out = run_cmd(["systeminfo"])
        fields = [
            "OS Name", "OS Version", "System Boot Time", "Domain",
            "System Manufacturer", "System Model", "Total Physical Memory",
            "Имя ОС", "Версия ОС", "Время загрузки системы", "Домен",
        ]
        for line in out.splitlines():
            for f in fields:
                if line.strip().startswith(f):
                    key, _, val = line.partition(":")
                    rows.append({"category": "system", "item": key.strip(), "details": val.strip()})
                    break
    except Exception as e:
        rows.append({"category": "system", "item": "[ошибка]", "details": str(e)})
    return rows


def collect_software() -> list[dict]:
    """Установленное ПО из реестра (без WMI — быстрее и не требует прав)."""
    rows = []
    ps_script = (
        "Get-ItemProperty "
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName, DisplayVersion | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    out = run_cmd(["powershell", "-NoProfile", "-Command", ps_script], timeout=60)
    try:
        reader = csv.reader(out.splitlines())
        next(reader, None)  # заголовок
        for row in reader:
            if len(row) >= 2 and row[0].strip():
                rows.append({
                    "category": "software",
                    "item": row[0].strip(),
                    "details": f"version: {row[1].strip()}" if row[1].strip() else ""
                })
    except Exception as e:
        rows.append({"category": "software", "item": "[ошибка парсинга]", "details": str(e)})
    return rows


def collect_users() -> list[dict]:
    rows = []
    out = run_cmd(["net", "user"])
    started = False
    for line in out.splitlines():
        if re.search(r"-{5,}", line):
            started = not started
            continue
        if started and line.strip():
            for name in line.split():
                rows.append({"category": "users", "item": "local_user", "details": name})

    out = run_cmd(["net", "localgroup"])
    for line in out.splitlines():
        m = re.match(r"^\*(.+)$", line.strip())
        if m:
            rows.append({"category": "users", "item": "local_group", "details": m.group(1).strip()})
    return rows


def collect_autoruns() -> list[dict]:
    rows = []
    ps_script = (
        "Get-ItemProperty "
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object * -ExcludeProperty PS* | ConvertTo-Csv -NoTypeInformation"
    )
    out = run_cmd(["powershell", "-NoProfile", "-Command", ps_script], timeout=30)
    for line in out.splitlines():
        line = line.strip().strip('"')
        if line and not line.startswith("PS"):
            rows.append({"category": "autoruns", "item": "registry_run_key", "details": line})

    out = run_cmd(["schtasks", "/query", "/fo", "csv", "/nh"])
    try:
        reader = csv.reader(out.splitlines())
        for row in reader:
            if len(row) >= 2 and row[0].strip() and row[0] != "N/A":
                rows.append({"category": "autoruns", "item": "scheduled_task", "details": row[0].strip()})
    except Exception:
        pass
    return rows


def collect_shares() -> list[dict]:
    rows = []
    out = run_cmd(["net", "share"])
    started = False
    for line in out.splitlines():
        if re.search(r"-{5,}", line):
            started = True
            continue
        if started and line.strip():
            parts = line.split()
            if parts:
                rows.append({"category": "shares", "item": "share_name", "details": parts[0]})
    return rows


def collect_creds_list() -> list[dict]:
    """
    Только ИМЕНА записей из Credential Manager (cmdkey /list) — никакой
    расшифровки паролей, только what's there (например: 'сохранена запись
    для сервера X'). Это стандартный, безопасный enumeration-вывод.
    
    Парсит русский ("Конечный файл:") и английский ("Target:") форматы.
    """
    rows = []
    out = run_cmd(["cmdkey", "/list"])
    lines = out.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Ищем строку "Конечный файл:" или "Target:"
        if line.lower().startswith(("конечный файл:", "target:")):
            if ":" in line:
                _, _, target = line.partition(":")
                target = target.strip()
                
                # Смотрим следующие строки на user и storage info
                user = None
                storage_info = None
                j = i + 1
                while j < len(lines) and j < i + 5:  # смотрим макс 4 строки после target
                    next_line = lines[j].strip()
                    if not next_line or next_line.lower().startswith(("конечный файл:", "target:")):
                        break
                    if next_line.lower().startswith(("пользователь:", "user:")):
                        _, _, user = next_line.partition(":")
                        user = user.strip()
                    elif any(x in next_line.lower() for x in ["сохранено", "stored", "постоянное"]):
                        storage_info = next_line
                    j += 1
                
                details = target
                if user:
                    details += f" (user: {user})"
                if storage_info:
                    details += f" [{storage_info}]"
                
                rows.append({
                    "category": "creds_list",
                    "item": "saved_credential",
                    "details": details
                })
        
        i += 1
    
    return rows


MODULES = {
    "system": collect_system,
    "software": collect_software,
    "users": collect_users,
    "autoruns": collect_autoruns,
    "shares": collect_shares,
    "creds_list": collect_creds_list,
}


def collect_all(selected: list[str]) -> list[dict]:
    results = []
    for name in selected:
        func = MODULES.get(name)
        if not func:
            continue
        try:
            results.extend(func())
        except Exception as e:
            results.append({"category": name, "item": "[критическая ошибка модуля]", "details": str(e)})
    return results


def _own_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def save_results(results: list[dict], fmt: str, out_dir: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"local_recon_{stamp}.{fmt}"

    if fmt == "json":
        out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    elif fmt == "csv":
        with out_path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f, fieldnames=["category", "item", "details"],
                delimiter=";", quoting=csv.QUOTE_ALL
            )
            writer.writeheader()
            writer.writerows(results)
    else:  # txt, сгруппировано по категориям
        lines = []
        current_cat = None
        for r in sorted(results, key=lambda x: x["category"]):
            if r["category"] != current_cat:
                current_cat = r["category"]
                lines.append(f"\n=== {current_cat.upper()} ===")
            lines.append(f"{r['item']}: {r['details']}")
        out_path.write_text("\n".join(lines), encoding="utf-8")

    return out_path


def parse_args():
    parser = argparse.ArgumentParser(description="Local Recon Suite")
    parser.add_argument("--auto", action="store_true", help="Сохранить сразу, без вопросов")
    parser.add_argument("--format", choices=["txt", "csv", "json"], default="csv")
    parser.add_argument("--out-dir", type=str, default=None)
    parser.add_argument(
        "--modules", type=str, default=",".join(MODULES.keys()),
        help=f"Через запятую, какие модули запускать. Доступны: {', '.join(MODULES.keys())}"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else _own_dir()
    selected = [m.strip() for m in args.modules.split(",") if m.strip() in MODULES]

    if not args.auto:
        print("=== Local Recon Suite ===")
        print(f"Модули: {', '.join(selected)}\n")

    results = collect_all(selected)

    if not results:
        print("Данные не собраны (возможно, недостаточно прав).")
        return

    if args.auto:
        path = save_results(results, args.format, out_dir)
        print(f"Сохранено в: {path} ({len(results)} записей)")
        return

    by_cat = {}
    for r in results:
        by_cat.setdefault(r["category"], []).append(r)
    for cat, items in by_cat.items():
        print(f"[{cat}] — {len(items)} записей")

    choice = input("\nСохранить результат в файл? (txt/csv/json/нет): ").strip().lower()
    if choice in ("txt", "csv", "json"):
        path = save_results(results, choice, out_dir)
        print(f"Сохранено в: {path}")
    else:
        print("Файл не сохранён.")


if __name__ == "__main__":
    main()