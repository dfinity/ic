import argparse
import os
import shutil
from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Tuple

import pytz
from slack_sdk import errors
from slack_sdk import WebClient
from util.print import eprint

LIVENESS_BOT_ID = "B037ZD5B2A3"

token = os.environ["SLACK_ACCESS_TOKEN"]

parser = argparse.ArgumentParser(
    description="Execute daily policy monitoring tasks",
)
parser.add_argument(
    "--artifact_expiration_days",
    "-e",
    type=int,
    default=3,
    help="Number of days after which policy monitoring " "artifacts should be removed (0 = delete all)",
)
parser.add_argument("--artifacts", "-a", type=str, help="Directory in which the pipeline artifacts are stored")
args = parser.parse_args()

client = WebClient(token)

TZ = pytz.timezone("Europe/Zurich")
CURRENT_TIMEPOINT = datetime.now(TZ)

try:
    response = client.conversations_list()
except errors.SlackApiError as e:
    raise e


def get_channel(name: str):
    try:
        channel = next(filter(lambda conv: conv["name"] == name, response.data["channels"]))
    except StopIteration as e:
        raise e
    return channel


liveness_channel = get_channel("ic-policy-alerts-liveness")
status_channel = get_channel("ic-policy-alerts")

try:
    response = client.conversations_history(channel=liveness_channel["id"])
except errors.SlackApiError as e:
    raise e

daily_count = len(
    list(
        filter(
            lambda m: "bot_id" in m
            and m["bot_id"] == LIVENESS_BOT_ID
            and (CURRENT_TIMEPOINT - datetime.fromtimestamp(round(float(m["ts"])), tz=TZ)) < timedelta(hours=24),
            response.data["messages"],
        )
    )
)

print(f"Daily liveness report count: {daily_count}")

# Set liveness status in Slack

common_details = "liveness reports in the past 24h"
if daily_count < 23:
    symbol = "🔥"
    details = f"{daily_count} is fewer than 23 {common_details}"
elif 23 <= daily_count <= 25:
    symbol = "🍏"
    details = f"{daily_count} {common_details}"
else:
    symbol = "🍊"
    details = f"{daily_count} is more than 25 {common_details}"

topic_text = (
    f"Status: {symbol} ({details})\n\n" f"Last updated: {CURRENT_TIMEPOINT.strftime('%A %b %d, %Y at %I:%M:%S (%Z)')}"
)

try:
    client.conversations_setTopic(channel=status_channel["id"], topic=topic_text)
except errors.SlackApiError as e:
    raise e


# Delete old artifacts
def handle_cleanup_errors(func, path, exc_info: Tuple[Any]):
    eprint(
        f"Failed to clean up outdated artifacts.\n"
        f"Command {str(func)} reported `{' '.join(map(lambda x: str(x), exc_info))}`"
        f" while processing path `{str(path)}`"
    )


if args.artifacts:
    artifacts = os.listdir(args.artifacts)
    print(f"Considering expired artifacts from {len(artifacts)} pipelines ...")
    for dir in artifacts:
        path = os.path.join(args.artifacts, dir)
        if os.path.isdir(path):
            dir_timestamp = os.stat(path).st_mtime
            dir_timepoint = datetime.fromtimestamp(dir_timestamp, tz=TZ)
            if CURRENT_TIMEPOINT - dir_timepoint > timedelta(days=args.artifact_expiration_days):
                print(f"Deleting outdated artifacts: {path}")
                shutil.rmtree(path, ignore_errors=False, onerror=handle_cleanup_errors)
