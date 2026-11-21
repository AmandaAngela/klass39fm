"""Interactive Wi-Fi dataset collection. Run from any working directory."""
import sys
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "recorder"))

if __name__ == "__main__":
    try:
        from collection import main
        raise SystemExit(main(ROOT))
    except ModuleNotFoundError as exc:
        raise SystemExit(f"Missing dependency {exc.name}. Use this Python's -m pip install -r requirements.txt.")
    except (OSError, ValueError, argparse.ArgumentTypeError, EOFError) as exc:
        raise SystemExit(f"Collection could not start: {exc}")
    except KeyboardInterrupt:
        raise SystemExit("Cancelled before capture.")
