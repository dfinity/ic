"""
RC_HOOK - This is the main process script for handling vulnerable dependencies in a release candidate cut

The script will flag any vulnerable dependency in the IC codebase.

Job failing conditions :
    - Vulnerable dependencies (direct and indirect) are not updated to fixed versions or not in the whitelist

    Whitelist structure :
    [{
            "name" : # package name,
            "version" : # package version,
            "date_added" : # dd/mm/yyyy,
            "date_updated" : # dd/mm/yyyy,
            "expiry_days" : # days until whitlelist expires.
    },]

    Whitelist file : .dependencies/vulnerable_crates_whitelist.json

To pass the CI job, the vulnerable crate needs to approved by Product Security for Whitelisting and needs be included
in the Whitelist with a valid expiry. The whitelist file is owned by Dependency owners.
"""
