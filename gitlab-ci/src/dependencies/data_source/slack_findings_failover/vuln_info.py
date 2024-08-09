import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from data_source.slack_findings_failover.data import (
    VULNERABILITY_HEADER,
    SlackFinding,
    SlackProjectInfo,
    SlackVulnerabilityEvent,
)
from data_source.slack_findings_failover.parse_format import get_current_iso_timestamp, project_to_list_item
from integration.slack.slack_block_kit_utils import (
    BlockKitListHeadline,
    block_kit_bullet_list_with_headline,
    block_kit_divider,
    block_kit_header,
    block_kit_section_with_single_col,
    block_kit_section_with_two_cols,
)
from model.finding import Finding
from model.vulnerability import Vulnerability


@dataclass
class VulnerabilityInfo:
    vulnerability: Vulnerability
    finding_by_id: Dict[Tuple[str, str, str, str], Finding]


@dataclass
class SlackVulnerabilityInfo:
    vulnerability: Vulnerability
    finding_by_id: Dict[Tuple[str, str, str, str], SlackFinding]
    msg_id_by_channel: Dict[str, str] = field(default_factory=lambda: {})

    @staticmethod
    def from_vuln_info(vuln_info: VulnerabilityInfo):
        finding_by_id = {}
        for finding in vuln_info.finding_by_id.values():
            si = SlackFinding.from_finding(finding)
            finding_by_id[si.id()] = si

        return SlackVulnerabilityInfo(vuln_info.vulnerability, finding_by_id)

    def __get_channel_ids_of_current_findings(self, info_by_project: Dict[str, SlackProjectInfo]) -> Set[str]:
        channel_ids = set()
        for finding in self.finding_by_id.values():
            for proj in finding.projects:
                channel_ids.update(info_by_project[proj].channels)
        return channel_ids

    def merge_with(self, findings: Dict[Tuple[str, str, str, str], SlackFinding], channel_id: str, message_id: str):
        if channel_id in self.msg_id_by_channel:
            raise RuntimeError(f"merging vuln info with vuln info from same channel: existing {self.msg_id_by_channel[channel_id]}, new {message_id}")
        self.msg_id_by_channel[channel_id] = message_id
        for s_finding in findings.values():
            if s_finding.id() in self.finding_by_id:
                add = set(s_finding.projects).difference(self.finding_by_id[s_finding.id()].projects)
                for proj in add:
                    self.finding_by_id[s_finding.id()].projects.append(proj)
                self.finding_by_id[s_finding.id()].projects.sort()
            else:
                self.finding_by_id[s_finding.id()] = s_finding

    def get_events_for_add(self, info_by_project: Dict[str, SlackProjectInfo]) -> List[SlackVulnerabilityEvent]:
        res = []
        all_channels = self.__get_channel_ids_of_current_findings(info_by_project)
        for channel in all_channels:
            res.append(SlackVulnerabilityEvent.vuln_added(self.vulnerability.id, channel))
        for s_finding in self.finding_by_id.values():
            projects_by_channel_id = {}
            for proj in s_finding.projects:
                for channel in info_by_project[proj].channels:
                    if channel not in projects_by_channel_id:
                        projects_by_channel_id[channel] = []
                    projects_by_channel_id[channel].append(proj)
            for channel, projects in projects_by_channel_id.items():
                res.append(SlackVulnerabilityEvent.dep_added(self.vulnerability.id, channel, s_finding.id(), projects))
        return res

    def get_events_for_remove(self, info_by_project: Dict[str, SlackProjectInfo], repository: str, scanner: str) -> List[SlackVulnerabilityEvent]:
        res = []
        channels_to_keep = set()
        for s_finding in self.finding_by_id.values():
            if s_finding.repository == repository and s_finding.scanner == scanner:
                projects_by_channel_id = {}
                for proj in s_finding.projects:
                    for channel in info_by_project[proj].channels:
                        if channel not in projects_by_channel_id:
                            projects_by_channel_id[channel] = []
                        projects_by_channel_id[channel].append(proj)
                for channel, projects in projects_by_channel_id.items():
                    res.append(SlackVulnerabilityEvent.dep_removed(self.vulnerability.id, channel, s_finding.id(), projects))
            else:
                # if the finding belongs to a different repo/scanner we have to keep the corresponding vuln in the corresponding channel
                for proj in s_finding.projects:
                    channels_to_keep.update(info_by_project[proj].channels)

        rm_events = []
        for channel in self.msg_id_by_channel.keys():
            if channel not in channels_to_keep:
                rm_events.append(SlackVulnerabilityEvent.vuln_removed(self.vulnerability.id, channel))
        return rm_events + res

    def update_with(self, other: VulnerabilityInfo, info_by_project: Dict[str, SlackProjectInfo], repository: str, scanner: str) -> List[SlackVulnerabilityEvent]:
        if self.vulnerability.id != other.vulnerability.id:
            raise RuntimeError(f"trying to merge different vulnerabilities {self.vulnerability.id} and {other.vulnerability.id}")
        vuln_id = self.vulnerability.id
        res = []

        for o_finding in other.finding_by_id.values():
            if o_finding.id() in self.finding_by_id:
                o_projs = set(o_finding.projects)
                projs = set(self.finding_by_id[o_finding.id()].projects)
                added = o_projs.difference(projs)
                removed = projs.difference(o_projs)
                if len(added) > 0:
                    projects_by_channel_id = {}
                    for proj in added:
                        for channel in info_by_project[proj].channels:
                            if channel not in projects_by_channel_id:
                                projects_by_channel_id[channel] = []
                            projects_by_channel_id[channel].append(proj)
                    for channel, projects in projects_by_channel_id.items():
                        res.append(SlackVulnerabilityEvent.dep_added(vuln_id, channel, o_finding.id(), projects))
                if len(removed) > 0:
                    projects_by_channel_id = {}
                    for proj in removed:
                        for channel in info_by_project[proj].channels:
                            if channel not in projects_by_channel_id:
                                projects_by_channel_id[channel] = []
                            projects_by_channel_id[channel].append(proj)
                    for channel, projects in projects_by_channel_id.items():
                        res.append(SlackVulnerabilityEvent.dep_removed(vuln_id, channel, o_finding.id(), projects))
                if len(added) > 0 or len(removed) > 0:
                    self.finding_by_id[o_finding.id()].projects = sorted(o_finding.projects)
            else:
                projects_by_channel_id = {}
                for proj in o_finding.projects:
                    for channel in info_by_project[proj].channels:
                        if channel not in projects_by_channel_id:
                            projects_by_channel_id[channel] = []
                        projects_by_channel_id[channel].append(proj)
                for channel, projects in projects_by_channel_id.items():
                    res.append(SlackVulnerabilityEvent.dep_added(vuln_id, channel, o_finding.id(), projects))
                self.finding_by_id[o_finding.id()] = SlackFinding.from_finding(o_finding)

        keys = list(self.finding_by_id.keys())
        for key in keys:
            s_finding = self.finding_by_id[key]
            if s_finding.repository != repository or s_finding.scanner != scanner:
                # we are only processing findings with matching repo & scanner
                continue
            if s_finding.id() not in other.finding_by_id:
                projects_by_channel_id = {}
                for proj in s_finding.projects:
                    for channel in info_by_project[proj].channels:
                        if channel not in projects_by_channel_id:
                            projects_by_channel_id[channel] = []
                        projects_by_channel_id[channel].append(proj)
                for channel, projects in projects_by_channel_id.items():
                    res.append(SlackVulnerabilityEvent.dep_removed(vuln_id, channel, s_finding.id(), projects))
                del self.finding_by_id[key]

        channels_before_update = set(self.msg_id_by_channel.keys())
        channels_after_update = self.__get_channel_ids_of_current_findings(info_by_project)
        channels_vuln_added = channels_after_update.difference(channels_before_update)
        channels_vuln_removed = channels_before_update.difference(channels_after_update)

        vuln_events = []
        for channel in channels_vuln_added:
            vuln_events.append(SlackVulnerabilityEvent.vuln_added(vuln_id, channel))
        for channel in channels_vuln_removed:
            vuln_events.append(SlackVulnerabilityEvent.vuln_removed(vuln_id, channel))

        vuln_updated_fields = {}
        # we set name = id if the id is not a link
        if self.vulnerability.name != other.vulnerability.name and self.vulnerability.id.startswith("http"):
            vuln_updated_fields["Name"] = self.vulnerability.name
            self.vulnerability.name = other.vulnerability.name
        if self.vulnerability.description != other.vulnerability.description:
            vuln_updated_fields["Description"] = self.vulnerability.description
            self.vulnerability.description = other.vulnerability.description
        if self.vulnerability.score != other.vulnerability.score:
            vuln_updated_fields["Score"] = str(self.vulnerability.score) if self.vulnerability.score != -1 else "n/a"
            self.vulnerability.score = other.vulnerability.score
        if len(vuln_updated_fields) > 0:
            for channel in self.msg_id_by_channel.keys():
                if channel not in channels_vuln_removed:
                    vuln_events.append(SlackVulnerabilityEvent.vuln_changed(vuln_id, channel, vuln_updated_fields))
        return vuln_events + res

    def get_slack_msg_for(self, channel_id: str, info_by_project: Dict[str, SlackProjectInfo]) -> Optional[str]:
        block_kit_msg = [block_kit_header(VULNERABILITY_HEADER)]
        if self.vulnerability.id.startswith("http"):
            vuln_id = f"<{self.vulnerability.id}|{self.vulnerability.name}>"
        else:
            vuln_id = self.vulnerability.id
        vuln_score = str(self.vulnerability.score) if self.vulnerability.score != -1 else "n/a"
        block_kit_msg.append(block_kit_section_with_two_cols("ID", vuln_id, "Score", vuln_score))

        risk_assessors = set()
        filtered_findings = []
        for finding in self.finding_by_id.values():
            is_filtered = False
            for proj in finding.projects:
                if channel_id in info_by_project[proj].channels:
                    if not is_filtered:
                        filtered_findings.append(finding)
                        is_filtered = True
                    risk_assessors.update(info_by_project[proj].risk_assessors_by_channel[channel_id])
        if len(filtered_findings) == 0:
            return None

        block_kit_msg.append(block_kit_section_with_two_cols("Risk Assessor", ", ".join(sorted(list(risk_assessors))), "Last Update", get_current_iso_timestamp()))
        block_kit_msg.append(block_kit_section_with_single_col("Description", self.vulnerability.description))

        block_kit_msg.append(block_kit_header("Findings"))

        filtered_findings.sort(key=lambda x: x.id())
        for finding in filtered_findings:
            block_kit_msg.append(block_kit_divider())
            block_kit_msg.append(block_kit_section_with_two_cols("Repository", finding.repository, "Scanner", finding.scanner))
            block_kit_msg.append(block_kit_section_with_two_cols("Dependency", finding.dependency_id, "Version", finding.dependency_version))
            list_items = []
            for proj in finding.projects:
                if channel_id in info_by_project[proj].channels:
                    list_items.append(project_to_list_item(proj, 0))
            block_kit_msg.append(block_kit_bullet_list_with_headline(BlockKitListHeadline.with_text("Projects"), list_items))

        return json.dumps(block_kit_msg)
