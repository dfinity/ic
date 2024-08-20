from dataclasses import dataclass
from html import unescape
from typing import Dict, List, Tuple

from data_source.slack_findings_failover.data import (
    VULNERABILITY_HEADER,
    VULNERABILITY_MSG_AUTHOR,
    VULNERABILITY_MSG_FIXED_REACTION,
    SlackFinding,
)
from data_source.slack_findings_failover.parse_format import parse_slack_field, parse_slack_optional_hyperlink
from data_source.slack_findings_failover.vuln_info import SlackVulnerabilityInfo
from integration.slack.slack_api import SlackApi
from model.vulnerability import Vulnerability


@dataclass
class SlackVulnerabilityLoader:
    slack_api_by_channel: Dict[str, SlackApi]

    def load_findings(self) -> Dict[str, SlackVulnerabilityInfo]:
        vuln_by_vuln_id: Dict[str, SlackVulnerabilityInfo] = {}
        for slack_api in self.slack_api_by_channel.values():
            channel_id = slack_api.channel_config.channel_id
            history = slack_api.get_channel_history(prefix=VULNERABILITY_HEADER, ignore_reaction=VULNERABILITY_MSG_FIXED_REACTION, author=VULNERABILITY_MSG_AUTHOR)
            for slack_msg in history:
                block_iter = iter(slack_msg.blocks)
                assert next(block_iter)["type"] == "header"
                cur_block = next(block_iter)
                assert cur_block["type"] == "section" and len(cur_block["fields"]) == 2
                match = parse_slack_field(cur_block["fields"][0]["text"], "ID")
                if vuln_info := parse_slack_optional_hyperlink(match):
                    vuln_id = vuln_name = vuln_info[0]
                    if vuln_info[1]:
                        vuln_id = vuln_info[1]
                else:
                    raise RuntimeError(f"could not parse Vulnerability hyperlink from string: {match}")
                match = parse_slack_field(cur_block["fields"][1]["text"], "Score")
                vuln_score = -1 if match == "n/a" else int(match)
                # skip the risk assessor and last update section, these are computed attributes
                next(block_iter)
                cur_block = next(block_iter)
                assert cur_block["type"] == "section" and cur_block["text"] and cur_block["text"]["text"]
                vuln_desc = unescape(parse_slack_field(cur_block["text"]["text"], "Description"))
                slack_vuln = Vulnerability(id=vuln_id, name=vuln_name, description=vuln_desc, score=vuln_score)

                findings_by_id: Dict[Tuple[str, str, str, str], SlackFinding] = {}
                assert next(block_iter)["type"] == "header"
                while cur_block := next(block_iter, None):
                    assert cur_block["type"] == "divider"
                    cur_block = next(block_iter)
                    assert cur_block["type"] == "section" and len(cur_block["fields"]) == 2
                    finding_repo = parse_slack_field(cur_block["fields"][0]["text"], "Repository")
                    finding_scanner = parse_slack_field(cur_block["fields"][1]["text"], "Scanner")
                    cur_block = next(block_iter)
                    assert cur_block["type"] == "section" and len(cur_block["fields"]) == 2
                    finding_dep = parse_slack_field(cur_block["fields"][0]["text"], "Dependency")
                    finding_vers = parse_slack_field(cur_block["fields"][1]["text"], "Version")

                    projects: List[str] = []
                    cur_block = next(block_iter)
                    assert cur_block["type"] == "rich_text" and len(cur_block["elements"]) == 2
                    assert cur_block["elements"][1]["type"] == "rich_text_list" and len(cur_block["elements"][1]["elements"]) > 0
                    for proj_block in cur_block["elements"][1]["elements"]:
                        assert proj_block["type"] == "rich_text_section" and len(proj_block["elements"]) == 1 and proj_block["elements"][0]["type"] in ["link", "text"]
                        url = " ({})".format(proj_block["elements"][0]["url"]) if proj_block["elements"][0]["type"] == "link" else ""
                        text = proj_block["elements"][0]["text"]
                        projects.append(f"{text}{url}")

                    slack_finding = SlackFinding(repository=finding_repo, scanner=finding_scanner, dependency_id=finding_dep, dependency_version=finding_vers, projects=projects)
                    findings_by_id[slack_finding.id()] = slack_finding

                if slack_vuln.id in vuln_by_vuln_id:
                    if slack_vuln != vuln_by_vuln_id[slack_vuln.id].vulnerability:
                        raise RuntimeError(f"vulnerability with same id but different values found in slack findings: {slack_vuln} {vuln_by_vuln_id[slack_vuln.id].vulnerability}")
                    vuln_by_vuln_id[slack_vuln.id].merge_with(findings_by_id, channel_id, slack_msg.id)
                else:
                    vuln_by_vuln_id[slack_vuln.id] = SlackVulnerabilityInfo(vulnerability=slack_vuln, finding_by_id=findings_by_id, msg_id_by_channel={channel_id: slack_msg.id})
        return vuln_by_vuln_id
