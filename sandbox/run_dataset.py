import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from tqdm import tqdm

from sandbox import analyze_url


CURRENT_DIR = os.path.dirname(__file__)
URLS_PATH = os.path.join(CURRENT_DIR, "urls_labeled.csv")
RESULTS_PATH = os.path.join(CURRENT_DIR, "results_mass.json")
FAILED_PATH = os.path.join(CURRENT_DIR, "failed_urls.json")
CHECKPOINT_EVERY = 50
MAX_URLS = 4000
MAX_WORKERS = min(4, max(1, (os.cpu_count() or 1)))


def save_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)


def scan_one(index: int, url: str, label: int) -> tuple[dict | None, dict | None]:
    try:
        result = analyze_url(url)
        result["label"] = int(label)
        result["index"] = int(index)
        return result, None
    except Exception as exc:
        return None, {
            "index": int(index),
            "url": url,
            "label": int(label),
            "error": str(exc),
        }


def flush_checkpoint(results_by_index: dict[int, dict], failed_rows: list[dict], completed_count: int) -> None:
    ordered_results = [results_by_index[idx] for idx in sorted(results_by_index)]
    save_json(RESULTS_PATH, ordered_results)
    save_json(FAILED_PATH, failed_rows)
    print(f"Saved checkpoint at {completed_count} URLs")


def main():
    df = pd.read_csv(URLS_PATH)
    df = df.head(MAX_URLS)
    total = len(df)

    results_by_index: dict[int, dict] = {}
    failed_rows: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(scan_one, int(index), row["url"], row["label"]): int(index)
            for index, row in df.iterrows()
        }

        completed = 0
        with tqdm(total=total, desc=f"Scanning URLs ({MAX_WORKERS} workers)") as progress:
            for future in as_completed(futures):
                result, failure = future.result()
                completed += 1

                if result is not None:
                    results_by_index[result["index"]] = result
                if failure is not None:
                    failed_rows.append(failure)

                if completed % CHECKPOINT_EVERY == 0:
                    flush_checkpoint(results_by_index, failed_rows, completed)

                progress.update(1)

    flush_checkpoint(results_by_index, failed_rows, completed)
    print("\nDone -> results_mass.json")
    print(f"Failed scans logged -> {FAILED_PATH}")


if __name__ == "__main__":
    main()
