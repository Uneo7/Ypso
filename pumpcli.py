import argparse
import asyncio
import json
import sys
from pathlib import Path

from bleak.exc import BleakError

from pump.cache import PumpCacheError
from pump.lock import lock_counters
from pump.sdk import (
    build_start_payload,
    build_stop_payload,
    build_tbr_start_payload,
    build_tbr_stop_payload,
    extract_snapshot,
    fetch_basal,
    fetch_history,
    fetch_status,
    load_session,
    send_bolus_payload,
    send_tbr_payload,
    watch_notifications,
)


def parse_args():
    parser = argparse.ArgumentParser(description="CLI unifiée pumpcli pour YpsoPump.")
    parser.add_argument("--force", action="store_true", help="Ignore l’expiration de la clé dans le cache.")
    parser.add_argument("--no-crypto", action="store_true", help="Force la lecture/écriture en clair.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="Démarrer un bolus")
    start.add_argument("--total", type=float, required=True, help="Total en UI")
    start.add_argument("--duration", type=int, default=0, help="Durée en minutes (0 = immédiat)")
    start.add_argument("--immediate", type=float, help="Part immédiate en UI")

    stop = sub.add_parser("stop", help="Arrêter un bolus")
    stop.add_argument("--type", choices=["fast", "extended", "combined"], required=True)

    sub.add_parser("status", help="Lire statut bolus/système")
    sub.add_parser("basal", help="Lire profil basal actif et programmes A/B")

    tbr_start = sub.add_parser("tbr-start", help="Démarrer un TBR (Temporary Basal Rate)")
    tbr_start.add_argument("--percent", type=int, required=True, help="Pourcentage du basal (0-200)")
    tbr_start.add_argument("--duration", type=int, default=30, help="Durée en minutes (15-1440, défaut: 30)")

    sub.add_parser("tbr-stop", help="Arrêter le TBR en cours")

    for name in ["events", "alerts", "system", "complaints"]:
        parser_hist = sub.add_parser(name, help=f"Lire historique {name}")
        parser_hist.add_argument("--limit", type=int, help="Limiter le nombre d'entrées")
        parser_hist.add_argument("--output", help="Fichier de sortie JSON")

    notify = sub.add_parser("notify", help="Écouter les notifications bolus")
    notify.add_argument("--timeout", type=int, help="Arrêt après N secondes")

    extract = sub.add_parser("extract", help="Dump complet historique/versions/datetime")
    extract.add_argument("--limit", type=int, help="Maximum d’entrées par catégorie")
    extract.add_argument("--output", help="Fichier de sortie JSON")
    extract.add_argument("--reset-counters", action="store_true", help="Reset compteurs cache avant session")
    extract.add_argument("--set-write-counter", type=int, help="Forcer le compteur d’écriture cache")

    return parser.parse_args()


async def run_start(args, pump, cryptor):
    payload = build_start_payload(args.total, args.duration, args.immediate)
    await send_bolus_payload(pump, payload, cryptor)
    print("Start command sent.")


async def run_stop(args, pump, cryptor):
    payload = build_stop_payload(args.type)
    await send_bolus_payload(pump, payload, cryptor)
    print("Stop command sent.")


async def run_status(pump, cryptor):
    result = await fetch_status(pump, cryptor)
    print(json.dumps(result, indent=2, ensure_ascii=False))


async def run_basal(pump, cryptor):
    result = await fetch_basal(pump, cryptor)
    print(json.dumps(result, indent=2, ensure_ascii=False))


async def run_tbr_start(args, pump, cryptor):
    payload = build_tbr_start_payload(args.percent, args.duration)
    await send_tbr_payload(pump, payload, cryptor)
    print(f"TBR started: {args.percent}% for {args.duration} minutes.")


async def run_tbr_stop(pump, cryptor):
    payload = build_tbr_stop_payload()
    await send_tbr_payload(pump, payload, cryptor)
    print("TBR stopped.")


async def run_history(kind: str, args, pump, cryptor):
    result = await fetch_history(pump, cryptor, kind, limit=args.limit)
    payload = {
        kind: result["entries"],
        "counts": {"total": result["total"], "returned": len(result["entries"])},
        "warnings": result["warnings"],
    }
    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(rendered)
        print(f"Écrit dans {args.output}")
    else:
        print(rendered)


async def run_notify(args, pump, cryptor):
    def on_event(evt: dict):
        print(json.dumps(evt, ensure_ascii=False))

    warnings = await watch_notifications(pump, cryptor, on_event, timeout=args.timeout)
    if warnings:
        print(json.dumps({"warnings": warnings}, ensure_ascii=False))


async def run_extract(args, data, pump, cryptor):
    result = await extract_snapshot(data, pump, cryptor, limit=args.limit)
    rendered = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(rendered)
        print(f"Saved data to {args.output}")
    else:
        print(rendered)


def main():
    args = parse_args()
    try:
        with lock_counters():
            data, pump, cryptor = load_session(
                allow_expired=args.force,
                allow_plain=args.no_crypto,
                reset_counters=getattr(args, "reset_counters", False),
                set_write_counter=getattr(args, "set_write_counter", None),
            )
            if args.command == "start":
                asyncio.run(run_start(args, pump, cryptor))
            elif args.command == "stop":
                asyncio.run(run_stop(args, pump, cryptor))
            elif args.command == "status":
                asyncio.run(run_status(pump, cryptor))
            elif args.command == "basal":
                asyncio.run(run_basal(pump, cryptor))
            elif args.command == "tbr-start":
                asyncio.run(run_tbr_start(args, pump, cryptor))
            elif args.command == "tbr-stop":
                asyncio.run(run_tbr_stop(pump, cryptor))
            elif args.command in ("events", "alerts", "system", "complaints"):
                asyncio.run(run_history(args.command, args, pump, cryptor))
            elif args.command == "notify":
                asyncio.run(run_notify(args, pump, cryptor))
            elif args.command == "extract":
                asyncio.run(run_extract(args, data, pump, cryptor))
    except PumpCacheError as exc:
        print(f"Cache error: {exc}")
        sys.exit(1)
    except BleakError as exc:
        print(f"BLE error: {exc}")
        sys.exit(2)
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(3)


if __name__ == "__main__":
    main()
