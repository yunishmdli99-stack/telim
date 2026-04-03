#!/usr/bin/env python3
"""
Simple Log Filter Tool
Filters log entries by username from a log file.
"""

import argparse
import sys
from pathlib import Path


def filter_logs_by_user(log_file: str, username: str) -> None:
    """
    Reads a log file and prints only lines that contain the given username.
    """
    try:
        path = Path(log_file)
        if not path.exists():
            print(f"Error: Log file '{log_file}' not found.", file=sys.stderr)
            sys.exit(1)

        username_lower = username.lower()
        found = False

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Case-insensitive search for the username
                if username_lower in line.lower():
                    print(line.rstrip())
                    found = True

        if not found:
            print(f"No logs found for user: {username}", file=sys.stderr)

    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Simple Log Filter Tool - Filter logs by username"
    )
    parser.add_argument(
        "--user",
        required=True,
        help="Username to filter logs by (e.g. admin)"
    )
    parser.add_argument(
        "--file",
        default="app.log",
        help="Path to the log file (default: app.log)"
    )

    args = parser.parse_args()

    print(f"Filtering logs for user: {args.user}")
    print(f"Reading from: {args.file}\n")
    
    filter_logs_by_user(args.file, args.user)


if __name__ == "__main__":
    main()
