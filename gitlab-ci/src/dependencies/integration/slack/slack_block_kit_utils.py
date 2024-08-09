from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def block_kit_header(headline: str) -> Dict[str, Any]:
    return {
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": headline
        }
    }


def block_kit_section_with_single_col(headline: str, content: str) -> Dict[str, Any]:
    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*{headline}*\n{content}"
        }
    }


def block_kit_section_with_two_cols(left_headline: str, left_content: str, right_headline: str, right_content: str) -> Dict[str, Any]:
    return {
        "type": "section",
        "fields": [
            {
                "type": "mrkdwn",
                "text": f"*{left_headline}*\n{left_content}"
            },
            {
                "type": "mrkdwn",
                "text": f"*{right_headline}*\n{right_content}"
            }
        ]
    }


@dataclass
class BlockKitRichText:
    text: str
    bold: bool = False
    url: Optional[str] = None


@dataclass
class BlockKitListHeadline:
    text: List[BlockKitRichText]

    @staticmethod
    def with_text(text: str, bold: bool = True):
        return BlockKitListHeadline([BlockKitRichText(text, bold)])


@dataclass
class BlockKitListItem(BlockKitListHeadline):
    indent: int = 0


def __rich_text_section_element_from(text: BlockKitRichText):
    if text.url:
        res = {
            "type": "link",
            "url": text.url
        }
    else:
        res = {
            "type": "text"
        }
    res["text"] = text.text
    if text.bold:
        res["style"] = {"bold": True}
    return res


def __rich_text_section_from(items: List[BlockKitRichText]):
    rich_text_section_elements = []
    for text in items:
        rich_text_section_elements.append(__rich_text_section_element_from(text))
    return {
        "type": "rich_text_section",
        "elements": rich_text_section_elements
    }


def block_kit_bullet_list_with_headline(headline: BlockKitListHeadline, bullets: List[BlockKitListItem]) -> Dict[str, Any]:
    rich_text_elements = [__rich_text_section_from(headline.text)]
    indent = bullets[0].indent if len(bullets) > 0 else 0
    rich_text_list_elements = []
    for item in bullets:
        if indent != item.indent:
            rich_text_elements.append({
                "type": "rich_text_list",
                "style": "bullet",
                "indent": indent,
                "elements": rich_text_list_elements
            })
            rich_text_list_elements = []
            indent = item.indent
        rich_text_list_elements.append(__rich_text_section_from(item.text))
    if len(rich_text_list_elements) > 0:
        rich_text_elements.append({
            "type": "rich_text_list",
            "style": "bullet",
            "indent": indent,
            "elements": rich_text_list_elements
        })
    return {
        "type": "rich_text",
        "elements": rich_text_elements
    }


def block_kit_divider() -> Dict[str, Any]:
    return {
        "type": "divider"
    }
