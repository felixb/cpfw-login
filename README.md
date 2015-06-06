# Checkpoint Firewall Login

Command line agent for checkpoint firewall authentication

# Install

Download the [latest release](https://github.com/felixb/cpfw-login/releases/latest).
Make sure to pick the right OS.

# Usage

Run the agent on your command line like this:

    ./cpfw-login --url <cp fw url> --user <username> --password <password>

The following parameters are available:

 * **-url // CPFW_AUTH_URL** required: base url of your checkpoint firewall login form without '/PortalMain'
 * **-user // CPFW_AUTH_USER** required: your user name
 * **-password // CPFW_AUTH_PASSWORD** required: your password
 * **-check // CPFW_AUTH_CHECK_URL** optional: any http url, used for checking before and after login. should be behind your firewall.
 * **-interval** optional: recheck/relogin every X seconds

The agent fails/dies on any unexpected error.

# Build

    go build

# Contributing

 1. fork
 2. commit
 3. send PR
