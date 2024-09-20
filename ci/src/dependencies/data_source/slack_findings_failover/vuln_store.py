import json
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from data_source.slack_findings_failover.data import (
    VULNERABILITY_MSG_FIXED_REACTION,
    SlackProjectInfo,
    SlackVulnerabilityEvent,
    SlackVulnerabilityEventType,
)
from data_source.slack_findings_failover.scan_result import SlackScanResult
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityInfo
from integration.slack.slack_api import SlackApi
from integration.slack.slack_block_kit_utils import (
    BlockKitListHeadline,
    BlockKitListItem,
    BlockKitRichText,
    block_kit_bullet_list_with_headline,
)


@dataclass
class SlackVulnerabilityStore:
    slack_api_by_channel: Dict[str, SlackApi]

    def __update_message_if_needed(self, channel_id: str, slack_vuln_info: SlackVulnerabilityInfo, updated_messages: Set[Tuple[str, str]], info_by_project: Dict[str, SlackProjectInfo]) -> str:
        slack_msg_id = slack_vuln_info.msg_id_by_channel.get(channel_id, None)
        if not slack_msg_id:
            raise RuntimeError(f"could not update slack message for channel {channel_id} for vuln {slack_vuln_info.vulnerability.id}: unknown message id")
        msg_key = (channel_id, slack_msg_id)
        if msg_key in updated_messages:
            return slack_msg_id

        slack_msg = slack_vuln_info.get_slack_msg_for(channel_id, info_by_project)
        if not slack_msg:
            raise RuntimeError(f"could not update slack message for channel {channel_id} for vuln {slack_vuln_info.vulnerability.id}: could not create message")
        self.slack_api_by_channel[channel_id].update_message(message=slack_msg, is_block_kit_message=True, message_id=slack_msg_id)
        updated_messages.add(msg_key)
        return slack_msg_id

    def handle_events(self, events: List[SlackVulnerabilityEvent], scan_result_by_channel: Dict[str, SlackScanResult], slack_vuln_info: SlackVulnerabilityInfo, info_by_project: Dict[str, SlackProjectInfo]):
        updated_messages: Set[Tuple[str, str]] = set()
        for event in events:
            if event.vulnerability_id != slack_vuln_info.vulnerability.id:
                raise RuntimeError(f"Event vuln id does not match vuln info id {slack_vuln_info.vulnerability.id}: {event}")
            t = event.type
            if t == SlackVulnerabilityEventType.VULN_ADDED:
                scan_result_by_channel[event.channel_id].new_vulnerabilities += 1
                slack_msg = slack_vuln_info.get_slack_msg_for(event.channel_id, info_by_project)
                if not slack_msg:
                    raise RuntimeError(f"could not create slack message for channel {event.channel_id} for vuln {slack_vuln_info.vulnerability.id}")
                slack_msg_id = self.slack_api_by_channel[event.channel_id].send_message(message=slack_msg, is_block_kit_message=True, thread_id=None)
                if not slack_msg_id:
                    raise RuntimeError(f"could not send slack message for channel {event.channel_id}")
                slack_vuln_info.msg_id_by_channel[event.channel_id] = slack_msg_id
                updated_messages.add((event.channel_id, slack_msg_id))
            elif t == SlackVulnerabilityEventType.VULN_REMOVED:
                scan_result_by_channel[event.channel_id].fixed_vulnerabilities += 1
                if event.channel_id not in slack_vuln_info.msg_id_by_channel:
                    raise RuntimeError(f"could not mark slack message as fixed for channel {event.channel_id} for vuln {slack_vuln_info.vulnerability.id}")
                self.slack_api_by_channel[event.channel_id].add_reaction(reaction=VULNERABILITY_MSG_FIXED_REACTION, message_id=slack_vuln_info.msg_id_by_channel[event.channel_id])
                updated_messages.add((event.channel_id, slack_vuln_info.msg_id_by_channel[event.channel_id]))
            elif t == SlackVulnerabilityEventType.VULN_CHANGED:
                scan_result_by_channel[event.channel_id].changed_vulnerabilities += 1
                slack_msg_id = self.__update_message_if_needed(event.channel_id, slack_vuln_info, updated_messages, info_by_project)
                list_items = []
                for field_name, field_value in event.updated_fields.items():
                    list_items.append(BlockKitListItem([BlockKitRichText(f"{field_name}: ", True), BlockKitRichText(f"{field_value}")]))
                vuln_chg_msg_blocks = [block_kit_bullet_list_with_headline(BlockKitListHeadline.with_text("The following fields of the vulnerability were updated (old values are provided):", False), list_items)]
                self.slack_api_by_channel[event.channel_id].send_message(message=json.dumps(vuln_chg_msg_blocks), is_block_kit_message=True, thread_id=slack_msg_id)
            elif t == SlackVulnerabilityEventType.DEP_ADDED:
                if event.finding_id not in scan_result_by_channel[event.channel_id].added_dependencies:
                    scan_result_by_channel[event.channel_id].added_dependencies[event.finding_id] = set()
                scan_result_by_channel[event.channel_id].added_dependencies[event.finding_id].update(event.added_projects)
                self.__update_message_if_needed(event.channel_id, slack_vuln_info, updated_messages, info_by_project)
            elif t == SlackVulnerabilityEventType.DEP_REMOVED:
                if event.finding_id not in scan_result_by_channel[event.channel_id].removed_dependencies:
                    scan_result_by_channel[event.channel_id].removed_dependencies[event.finding_id] = set()
                scan_result_by_channel[event.channel_id].removed_dependencies[event.finding_id].update(event.removed_projects)
                self.__update_message_if_needed(event.channel_id, slack_vuln_info, updated_messages, info_by_project)
            else:
                raise RuntimeError(f"event has unknown type: {event}")
