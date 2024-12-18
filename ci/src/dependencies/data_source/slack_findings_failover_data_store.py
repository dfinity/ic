import logging
import os
import re
from copy import deepcopy
from typing import Dict, List, Set

from data_source.findings_failover_data_store import FindingsFailoverDataStore
from data_source.slack_findings_failover.data import VULNERABILITY_THRESHOLD_SCORE, SlackProjectInfo, SlackRiskAssessor
from data_source.slack_findings_failover.scan_result import SlackScanResult
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityInfo, VulnerabilityInfo
from data_source.slack_findings_failover.vuln_load import SlackVulnerabilityLoader
from data_source.slack_findings_failover.vuln_store import SlackVulnerabilityStore
from integration.slack.slack_api import SlackApi
from integration.slack.slack_channel_config import SlackChannelConfig
from model.finding import Finding
from model.project import Project
from model.team import Team
from resources import resource_reader
from resources.resource_reader import IgnoreList

SUPPORTED_TEAMS = (Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM)
SLACK_CHANNEL_CONFIG_BY_TEAM = {
    Team.NODE_TEAM: SlackChannelConfig(channel_id="C05CYLM94KU", channel="#eng-node-psec"),
    Team.BOUNDARY_NODE_TEAM: SlackChannelConfig(channel_id="C06KQKZ3EBW", channel="#eng-boundary-nodes-psec"),
}
SLACK_TEAM_RISK_ASSESSOR = {
    Team.NODE_TEAM: SlackRiskAssessor(name="<!subteam^S05FTRNRC5A>", wants_assessment_reminder=True),
    Team.BOUNDARY_NODE_TEAM: SlackRiskAssessor(name="<!subteam^S0313LYB9FZ>", wants_assessment_reminder=False),
}

SLACK_LOG_TO_CONSOLE = False

SLACK_OAUTH_TOKEN = os.environ.get("SLACK_PSEC_BOT_OAUTH_TOKEN")
if SLACK_OAUTH_TOKEN is None:
    logging.error("SLACK_OAUTH_TOKEN not set, can't use slack failover store")

FAILOVER_FINDING_PREFIXES = {
    ("ic", "BAZEL_TRIVY_CS"): ["linux-libc-dev", "linux-modules"],
}

IGNORE_LIST_BY_PROJECT = {
    "OSP: ic/ic-os/boundary-guestos/envs/prod (https://github.com/dfinity/ic/tree/master/ic-os/boundary-guestos/context)": resource_reader.read_ignore_list(
        IgnoreList.BOUNDARY_GUEST_OS
    ),
    "OSP: ic/ic-os/guestos/envs/prod (https://github.com/dfinity/ic/tree/master/ic-os/guestos/context)": resource_reader.read_ignore_list(
        IgnoreList.GUEST_OS
    ),
}


class SlackFindingsFailoverDataStore(FindingsFailoverDataStore):
    slack_api_by_channel: Dict[str, SlackApi] = {}
    project_by_path: Dict[str, Project] = {}
    slack_loader: SlackVulnerabilityLoader
    slack_store: SlackVulnerabilityStore

    def __init__(
        self,
        projects: List[Project],
        slack_api: SlackApi = None,
        slack_loader: SlackVulnerabilityLoader = None,
        slack_store: SlackVulnerabilityStore = None,
    ):
        for proj in projects:
            if proj.owner and proj.owner not in SUPPORTED_TEAMS:
                raise RuntimeError(f"Project {proj.name} has owner {proj.owner} which is not supported")
            for owners in proj.owner_by_path.values():
                for owner in owners:
                    if owner not in SUPPORTED_TEAMS:
                        raise RuntimeError(f"Project {proj.name} has path owner {owner} which is not supported")
        for proj in projects:
            self.project_by_path[proj.path] = deepcopy(proj)

        for channel in SLACK_CHANNEL_CONFIG_BY_TEAM.values():
            if slack_api:
                self.slack_api_by_channel[channel.channel_id] = slack_api
            elif channel.channel_id not in self.slack_api_by_channel:
                self.slack_api_by_channel[channel.channel_id] = SlackApi(
                    channel, SLACK_LOG_TO_CONSOLE, SLACK_OAUTH_TOKEN
                )

        self.slack_loader = slack_loader if slack_loader else SlackVulnerabilityLoader(self.slack_api_by_channel)
        self.slack_store = slack_store if slack_store else SlackVulnerabilityStore(self.slack_api_by_channel)

    def __info_by_project(self, projects: Set[str]) -> Dict[str, SlackProjectInfo]:
        res = {}
        for finding_proj in projects:
            channels = set()
            risk_assessors = {}
            # some dependency managers add prefixes before the actual project path -> remove them
            transformed_proj = re.sub(r"^\w+:\s*", "", finding_proj)
            for proj in self.project_by_path.values():
                if not transformed_proj.startswith(proj.path):
                    continue
                if proj.owner:
                    cid = SLACK_CHANNEL_CONFIG_BY_TEAM[proj.owner].channel_id
                    channels.add(cid)
                    if cid not in risk_assessors:
                        risk_assessors[cid] = set()
                    risk_assessors[cid].add(SLACK_TEAM_RISK_ASSESSOR[proj.owner])
                for sub_path, teams in proj.owner_by_path.items():
                    if not transformed_proj.startswith(sub_path):
                        continue
                    for team in teams:
                        cid = SLACK_CHANNEL_CONFIG_BY_TEAM[team].channel_id
                        channels.add(cid)
                        if cid not in risk_assessors:
                            risk_assessors[cid] = set()
                        risk_assessors[cid].add(SLACK_TEAM_RISK_ASSESSOR[team])
            if len(channels) == 0 or len(risk_assessors) == 0:
                raise RuntimeError(f"cannot determine channel for project: {finding_proj}")
            risk_assessors_sorted = {}
            for k, v in risk_assessors.items():
                risk_assessors_sorted[k] = sorted(list(v))
            res[finding_proj] = SlackProjectInfo(finding_proj, channels, risk_assessors_sorted)
        return res

    @staticmethod
    def _filter_vulns(vuln_by_vuln_id: Dict[str, VulnerabilityInfo], ignore_list_by_project: Dict[str, Set[str]]):
        # remove vulns with too low score
        vuln_ids = list(vuln_by_vuln_id.keys())
        for vid in vuln_ids:
            if vuln_by_vuln_id[vid].vulnerability.score < VULNERABILITY_THRESHOLD_SCORE:
                del vuln_by_vuln_id[vid]

        # remove vulns that contain words on ignore list or adapt findings
        vulns_to_delete = set()
        for vi in vuln_by_vuln_id.values():
            findings_to_delete = set()
            for finding in vi.finding_by_id.values():
                filtered_projects = []
                for proj in finding.projects:
                    add_proj = True
                    if proj in ignore_list_by_project:
                        for expr in ignore_list_by_project[proj]:
                            if expr.lower() in vi.vulnerability.description.lower():
                                add_proj = False
                                break
                    if add_proj:
                        filtered_projects.append(proj)
                if len(filtered_projects) == 0:
                    findings_to_delete.add(finding.id())
                else:
                    finding.projects = filtered_projects
            if len(findings_to_delete) == len(vi.finding_by_id):
                vulns_to_delete.add(vi.vulnerability.id)
            else:
                for finding_id in findings_to_delete:
                    del vi.finding_by_id[finding_id]
        for vuln_id in vulns_to_delete:
            del vuln_by_vuln_id[vuln_id]

    def can_handle(self, finding: Finding) -> bool:
        is_failover_finding = False
        key = (finding.repository, finding.scanner)
        if key in FAILOVER_FINDING_PREFIXES:
            for dep_id_prefix in FAILOVER_FINDING_PREFIXES[key]:
                if finding.vulnerable_dependency.id.startswith(dep_id_prefix):
                    is_failover_finding = True
                    break
        if is_failover_finding:
            # check that all projects are known if not raise an exception (configuration error)
            self.__info_by_project(set(finding.projects))
        return is_failover_finding

    def store_findings(self, repository: str, scanner: str, current_findings: List[Finding]):
        vuln_by_vuln_id: Dict[str, VulnerabilityInfo] = {}
        projects: Set[str] = set()

        for finding in current_findings:
            projects.update(finding.projects)
            for vuln in finding.vulnerabilities:
                if vuln.id not in vuln_by_vuln_id:
                    vuln_by_vuln_id[vuln.id] = VulnerabilityInfo(vulnerability=vuln, finding_by_id={})
                if vuln_by_vuln_id[vuln.id].vulnerability != vuln:
                    raise RuntimeError(
                        f"vulnerability with same id but different values found in current findings: {vuln} {vuln_by_vuln_id[vuln.id].vulnerability}"
                    )
                vuln_by_vuln_id[vuln.id].finding_by_id[finding.id()] = deepcopy(finding)

        self._filter_vulns(vuln_by_vuln_id, IGNORE_LIST_BY_PROJECT)

        slack_vuln_by_vuln_id = self.slack_loader.load_findings()
        for vuln_info in slack_vuln_by_vuln_id.values():
            for finding in vuln_info.finding_by_id.values():
                projects.update(finding.projects)

        info_by_project = self.__info_by_project(projects)
        scan_result_by_channel: Dict[str, SlackScanResult] = {}
        for proj_info in info_by_project.values():
            for chan in proj_info.channels:
                if chan not in scan_result_by_channel:
                    scan_result_by_channel[chan] = SlackScanResult()

        # check found vulns against stored vulns to find added or changed vulns
        for vuln_info in vuln_by_vuln_id.values():
            if vuln_info.vulnerability.id in slack_vuln_by_vuln_id:
                events = slack_vuln_by_vuln_id[vuln_info.vulnerability.id].update_with(
                    vuln_info, info_by_project, repository, scanner
                )
                self.slack_store.handle_events(
                    events, scan_result_by_channel, slack_vuln_by_vuln_id[vuln_info.vulnerability.id], info_by_project
                )
            else:
                svi = SlackVulnerabilityInfo.from_vuln_info(vuln_info)
                self.slack_store.handle_events(
                    svi.get_events_for_add(info_by_project), scan_result_by_channel, svi, info_by_project
                )

        # check stored vulns against found vulns to find removed vulns
        for slack_vuln_info in slack_vuln_by_vuln_id.values():
            if slack_vuln_info.vulnerability.id not in vuln_by_vuln_id:
                self.slack_store.handle_events(
                    slack_vuln_info.get_events_for_remove(info_by_project, repository, scanner),
                    scan_result_by_channel,
                    slack_vuln_info,
                    info_by_project,
                )

        # publish scan results for each channel
        for channel_id, scan_result in scan_result_by_channel.items():
            if scan_result.has_updates():
                slack_msg_id = self.slack_api_by_channel[channel_id].send_message(
                    message=scan_result.get_slack_msg(repository, scanner), is_block_kit_message=True
                )
                reminders = scan_result.get_slack_thread_msgs_for_reminder()
                for reminder in reminders:
                    self.slack_api_by_channel[channel_id].send_message(
                        message=reminder, thread_id=slack_msg_id, show_link_preview=False
                    )
