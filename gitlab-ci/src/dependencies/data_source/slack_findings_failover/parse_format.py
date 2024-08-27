import re
from datetime import datetime
from typing import Optional, Tuple

from integration.slack.slack_block_kit_utils import BlockKitListItem, BlockKitRichText


def get_current_iso_timestamp() -> str:
    return datetime.now().astimezone().replace(microsecond=0).isoformat()


def project_to_list_item(project: str, indent: int) -> BlockKitListItem:
    proj_parts = parse_finding_project(project)
    if proj_parts:
        if proj_parts[2]:
            prefix = proj_parts[0] if proj_parts[0] else ""
            return BlockKitListItem(text=[BlockKitRichText(text=prefix + proj_parts[1], url=proj_parts[2])], indent=indent)

        else:
            return BlockKitListItem(text=[BlockKitRichText(project)], indent=indent)
    else:
        raise RuntimeError(f"could not parse project {project}")


def parse_slack_field(string: str, field_name: str) -> Optional[str]:
    if match := re.match(fr"^\*{field_name}\*\n\s*(?P<field_value>.*)$", string):
        return match.group("field_value")
    return None


def parse_slack_optional_hyperlink(string: str) -> Optional[Tuple[str, Optional[str]]]:
    if string.startswith("<"):
        if match := re.match(r"^<(?P<href>[^|]+)\|(?P<label>.*)>$", string):
            return match.group("label"), match.group("href")
        else:
            return None
    else:
        return string, None


def parse_finding_project(string: str) -> Optional[Tuple[Optional[str], str, Optional[str]]]:
    if match := re.match(r"^(?P<prefix>\w+:\s*)?(?P<path>((?! \(http).)+)(\s+\((?P<suffix>.*)\))?$", string):
        return match.group("prefix"), match.group("path").strip(), match.group("suffix")
    return None
