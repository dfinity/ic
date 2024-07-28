import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from data_source.slack_findings_failover.data import SlackProjectInfo, SlackVulnerabilityEvent, SlackVulnerabilityEventType, VULNERABILITY_MSG_FIXED_REACTION
from data_source.slack_findings_failover.scan_result import SlackScanResult
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityInfo
from integration.slack.slack_api import SlackApi
from integration.slack.slack_block_kit_utils import BlockKitListItem, block_kit_bullet_list_with_headline, BlockKitListHeadline, \
    BlockKitRichText


@dataclass
class SlackVulnerabilityStore:
    slack_api_by_channel: Dict[str, SlackApi]
    info_by_project: Dict[str, SlackProjectInfo]

    def __update_message_if_needed(self, channel_id: str, slack_vuln_info: SlackVulnerabilityInfo, updated_messages: Set[Tuple[str, str]]) -> str:
        slack_msg_id = slack_vuln_info.msg_id_by_channel.get(channel_id, None)
        if not slack_msg_id:
            raise RuntimeError(f"could not update slack message for channel {channel_id} for vuln {slack_vuln_info.vulnerability.id}: unknown message id")
        msg_key = (channel_id, slack_msg_id)
        if msg_key in updated_messages:
            return slack_msg_id

        slack_msg = slack_vuln_info.get_slack_msg_for(channel_id, self.info_by_project)
        if not slack_msg:
            raise RuntimeError(f"could not update slack message for channel {channel_id} for vuln {slack_vuln_info.vulnerability.id}: could not create message")
        self.slack_api_by_channel[channel_id].update_message(message=slack_msg, is_block_kit_message=True, message_id=slack_msg_id)
        updated_messages.add(msg_key)
        return slack_msg_id

    def handle_events(self, diffs: List[SlackVulnerabilityEvent], scan_result_by_channel: Dict[str, SlackScanResult], slack_vuln_info: Optional[SlackVulnerabilityInfo]):
        updated_messages: Set[Tuple[str, str]] = set()
        for diff in diffs:
            t = diff.type
            if t == SlackVulnerabilityEventType.VULN_ADDED:
                if not slack_vuln_info:
                    raise RuntimeError(f"VULN_ADDED event without slack vulnerability info: {diff}")

                scan_result_by_channel[diff.channel_id].new_vulnerabilities += 1
                slack_msg = slack_vuln_info.get_slack_msg_for(diff.channel_id, self.info_by_project)
                if not slack_msg:
                    raise RuntimeError(f"could not create slack message for channel {diff.channel_id} for vuln {slack_vuln_info.vulnerability.id}")
                slack_msg_id = self.slack_api_by_channel[diff.channel_id].send_message(message=slack_msg, is_block_kit_message=True, thread_id=None)
                if not slack_msg_id:
                    raise RuntimeError(f"could not send slack message for channel {diff.channel_id}")
                slack_vuln_info.msg_id_by_channel[diff.channel_id] = slack_msg_id
                updated_messages.add((diff.channel_id, slack_msg_id))
            elif t == SlackVulnerabilityEventType.VULN_REMOVED:
                if not slack_vuln_info:
                    raise RuntimeError(f"VULN_REMOVED event without slack vulnerability info: {diff}")

                scan_result_by_channel[diff.channel_id].fixed_vulnerabilities += 1
                if diff.channel_id not in slack_vuln_info.msg_id_by_channel:
                    raise RuntimeError(f"could not mark slack message as fixed for channel {diff.channel_id} for vuln {slack_vuln_info.vulnerability.id}")
                self.slack_api_by_channel[diff.channel_id].add_reaction(VULNERABILITY_MSG_FIXED_REACTION, slack_vuln_info.msg_id_by_channel[diff.channel_id])
                updated_messages.add((diff.channel_id, slack_vuln_info.msg_id_by_channel[diff.channel_id]))
            elif t == SlackVulnerabilityEventType.VULN_CHANGED:
                if not slack_vuln_info:
                    raise RuntimeError(f"VULN_CHANGED event without slack vulnerability info: {diff}")

                scan_result_by_channel[diff.channel_id].changed_vulnerabilities += 1
                slack_msg_id = self.__update_message_if_needed(diff.channel_id, slack_vuln_info, updated_messages)
                list_items = []
                for field_name, field_value in diff.updated_fields.items():
                    list_items.append(BlockKitListItem([BlockKitRichText(f"{field_name}: ", True), BlockKitRichText(f"{field_value}")]))
                vuln_chg_msg_blocks = [block_kit_bullet_list_with_headline(BlockKitListHeadline.with_text("The following fields of the vulnerability were updated (old values are provided):", False), list_items)]
                self.slack_api_by_channel[diff.channel_id].send_message(message=json.dumps(vuln_chg_msg_blocks), is_block_kit_message=True, thread_id=slack_msg_id)
            elif t == SlackVulnerabilityEventType.DEP_ADDED:
                if not slack_vuln_info:
                    raise RuntimeError(f"DEP_ADDED event without slack vulnerability info: {diff}")

                if diff.finding_id not in scan_result_by_channel[diff.channel_id].added_dependencies:
                    scan_result_by_channel[diff.channel_id].added_dependencies[diff.finding_id] = set()
                scan_result_by_channel[diff.channel_id].added_dependencies[diff.finding_id].update(diff.added_projects)
                self.__update_message_if_needed(diff.channel_id, slack_vuln_info, updated_messages)
            elif t == SlackVulnerabilityEventType.DEP_REMOVED:
                if not slack_vuln_info:
                    raise RuntimeError(f"DEP_REMOVED event without slack vulnerability info: {diff}")

                if diff.finding_id not in scan_result_by_channel[diff.channel_id].removed_dependencies:
                    scan_result_by_channel[diff.channel_id].removed_dependencies[diff.finding_id] = set()
                scan_result_by_channel[diff.channel_id].removed_dependencies[diff.finding_id].update(diff.removed_projects)
                self.__update_message_if_needed(diff.channel_id, slack_vuln_info, updated_messages)
            else:
                raise RuntimeError(f"event has unknown type: {diff}")
