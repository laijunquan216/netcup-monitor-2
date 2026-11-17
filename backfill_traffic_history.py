#!/usr/bin/env python3
"""Conservative, opt-in backfill of legacy qB traffic deltas.

Default mode is read-only preview. Pass --apply to update only NULL up_delta/dl_delta
cells for adjacent, monotonic samples no more than 10 minutes apart. Raw totals,
timestamps, baselines, state events, and all other database content are untouched.
"""
import argparse
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "data" / "monitor.db"
MAX_BYTES_PER_5M = 100 * 1024 ** 3
MAX_GAP_SECONDS = 10 * 60


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DB_PATH, help="SQLite database path")
    parser.add_argument("--apply", action="store_true", help="write eligible deltas (default: dry run)")
    args = parser.parse_args()

    if not args.db.is_file():
        raise SystemExit(f"数据库不存在：{args.db}")

    conn = sqlite3.connect(str(args.db))
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(traffic_log)")}
        required = {"server_name", "timestamp", "up_total", "dl_total", "up_delta", "dl_delta"}
        if not required.issubset(columns):
            raise SystemExit("traffic_log 缺少所需字段；未执行任何修改")

        servers = [row[0] for row in conn.execute(
            "SELECT DISTINCT server_name FROM traffic_log ORDER BY server_name"
        )]
        updates = []
        rejected = {"gap": 0, "counter_reset": 0, "spike": 0, "already_filled": 0}
        total_up = total_dl = 0

        for server in servers:
            rows = conn.execute(
                """SELECT id, timestamp, up_total, dl_total, up_delta, dl_delta
                   FROM traffic_log WHERE server_name=? ORDER BY timestamp, id""",
                (server,),
            ).fetchall()
            previous = None
            for row in rows:
                row_id, ts, up, dl, up_delta, dl_delta = row
                if previous is not None and up is not None and dl is not None:
                    prev_id, prev_ts, prev_up, prev_dl = previous
                    if up_delta is not None or dl_delta is not None:
                        rejected["already_filled"] += 1
                    else:
                        gap = ts - prev_ts
                        if gap <= 0 or gap > MAX_GAP_SECONDS:
                            rejected["gap"] += 1
                        else:
                            du, dd = up - prev_up, dl - prev_dl
                            allowed = MAX_BYTES_PER_5M * max(1.0, gap / 300.0)
                            if du < 0 or dd < 0:
                                rejected["counter_reset"] += 1
                            elif du > allowed or dd > allowed:
                                rejected["spike"] += 1
                            else:
                                updates.append((int(du), int(dd), row_id))
                                total_up += du
                                total_dl += dd
                previous = (row_id, ts, up, dl) if up is not None and dl is not None else None

        print(f"数据库：{args.db}")
        print(f"模式：{'写入' if args.apply else '只读预览'}")
        print(f"符合条件的连续区间：{len(updates)} 条")
        print(f"拟回填上传：{total_up / 1024**3:.2f} GiB")
        print(f"拟回填下载：{total_dl / 1024**3:.2f} GiB")
        print("跳过统计：" + ", ".join(f"{k}={v}" for k, v in rejected.items()))

        if args.apply and updates:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany(
                """UPDATE traffic_log SET up_delta=?, dl_delta=?
                   WHERE id=? AND up_delta IS NULL AND dl_delta IS NULL""",
                updates,
            )
            conn.commit()
            print(f"已写入 {conn.total_changes} 条增量记录；原始累计值及其他表未修改。")
        elif args.apply:
            print("没有符合条件的记录，无需写入。")
        else:
            print("当前为只读预览。确认结果后，才使用 --apply 执行回填。")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
