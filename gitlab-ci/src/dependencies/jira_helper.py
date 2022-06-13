"""
The class allows an interface to perform JIRA actions useful for tracking dependencies
which introduce vulnerability in the codebase

No suitable Markup generator found for JIRA. Creating a dictionary of JIRA markup which can be used
to create the issue text.
"""
import hashlib
import json
import logging
import os
from io import StringIO

from jira import JIRA

JIRA_OPTIONS = {"server": "https://dfinity.atlassian.net"}
JIRA_USER = "vuln-mgmt@dfinity.org"
JIRA_BOARD_KEY = "VMT"
JIRA_ISSUE_TYPE = "MR Scan"
BRANCH_NAME = os.environ.get("CI_COMMIT_REF_NAME", "")


JIRA_API_KEY = os.environ.get("JIRA_API_TOKEN", "")
if JIRA_API_KEY is None:
    logging.error("JIRA_API_KEY is not set, can't write to JIRA")


JIRA_MARKUP = {
    "bold": "*{text}*",
    "italics": "_{text}_",
    "heading1": "h1. {title}",
    "heading2": "h2. {title}",
    "heading3": "h3. {title}",
    "linebreak": "\n",
    "line2break": "\n\n",
    "link": "[{anchor}|{url}]",
    "bookmark": "[{anchor}:{anchorname}]",
    "list1": "* {line}",
    "list2": "** {line}",
    "blockquote": "bq. {line}",
}


def auth():
    logging.info("Trying to authenticate JIRA for {user} with {options}".format(user=JIRA_USER, options=JIRA_OPTIONS))
    try:
        jira = JIRA(JIRA_OPTIONS, basic_auth=(JIRA_USER, JIRA_API_KEY))
        return jira
    except Exception as e:
        logging.error("JIRA auth didn't succeed " + str(e))


def create_description(data):
    description = ""

    if "modified_crates" in data and data["modified_crates"]:
        modified_crates = JIRA_MARKUP["linebreak"].join(
            JIRA_MARKUP["list1"].format(line=str(x)) for x in data["modified_crates"]
        )
        description = description + "The following internal crates have been modified : \n\n" + modified_crates

    if "vulnerable_crates" in data and data["vulnerable_crates"]:
        vuln_deps = JIRA_MARKUP["linebreak"].join(
            JIRA_MARKUP["list1"].format(line=str(x)) for x in data["vulnerable_crates"]
        )
        description = (
            description
            + "\n\nVulnerability scan complete - The following dependencies are vulnerable. \n\n"
            + vuln_deps
        )

    if "vulnerability_scan" in data and data["vulnerability_scan"]:
        vuln_scan = JIRA_MARKUP["linebreak"].join(
            JIRA_MARKUP["list1"].format(line=str(x)) for x in data["vulnerability_scan"].keys()
        )
        description = description + "\n\nThe following internal crates are affected by : \n\n" + vuln_scan

    if "whitelist_status" in data and data["whitelist_status"]:
        whitelist_status = JIRA_MARKUP["linebreak"].join(
            JIRA_MARKUP["list1"].format(line=str(x)) for x in data["whitelist_status"]
        )
        description = description + "\n\nWhitelist status \n\n" + whitelist_status

    return description


def create_ticket(data) -> str:
    url = ""
    try:
        jira = auth()
        new_ticket_data = {
            "project": {"key": JIRA_BOARD_KEY},
            "summary": BRANCH_NAME
            + " MR dependency scan @ "
            + hashlib.sha256(BRANCH_NAME.encode("ascii")).hexdigest()[:12],
            "description": create_description(data=data),
            "issuetype": {"name": JIRA_ISSUE_TYPE},
        }
        new_issue = jira.create_issue(fields=new_ticket_data)
        url = new_issue.permalink()
        logging.info("JIRA ticket was created. Please check " + url)

        attachment = StringIO()
        attachment.write(json.dumps(data, indent=4, sort_keys=True, default=str))
        jira.add_attachment(issue=new_issue, attachment=attachment, filename="scan.json")
        logging.info("Raw scan data attached to the JIRA ticket")

    except Exception as err:
        raise Exception("JIRA ticket was not created " + str(err))
    finally:
        return url


def update_ticket(data):
    # JIRA doesn't allow exact word matching.
    # It's query works with word stemming, and we can't map MR names directly as a unique qeuryable identifier.
    # Adding a SHA256 trimmed has until the feature is added
    name = hashlib.sha256(BRANCH_NAME.encode("ascii")).hexdigest()[:12]
    query = 'project = "{project}" and summary ~ "\\"{summary}\\""'.format(project=JIRA_BOARD_KEY, summary=name)
    try:
        jira = auth()
        search_issues = jira.search_issues(query)
        if search_issues:
            jira.add_comment(search_issues[0], create_description(data=data))
        return
    except Exception as err:
        raise Exception("JIRA comment was not added " + str(err))


def check_ticket_exists() -> bool:
    # JIRA doesn't allow exact word matching.
    # It's query works with word stemming, and we can't map MR names directly as a unique qeuryable identifier.
    # Adding a SHA256 trimmed has until the feature is added
    name = hashlib.sha256(BRANCH_NAME.encode("ascii")).hexdigest()[:12]
    query = 'project = "{project}" and summary ~ "\\"{summary}\\""'.format(project=JIRA_BOARD_KEY, summary=name)
    try:
        jira = auth()
        search_issues = jira.search_issues(query)
        if search_issues:
            return True
        return False
    except Exception as err:
        raise Exception("Check ticket failed " + str(err))
