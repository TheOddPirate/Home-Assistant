#!/usr/bin/env python
# ldap authentication for home assistan
# Tested and working with Authenik
# Original can be found at 
# https://github.com/panteLx/HASS-LDAP-Auth
# i updated it to auto install missing pip modules
# and support groups from authentik so it sets me as admin
# and my guests as regular users
# goto line 131 for group info
import os
import sys
import pip

#function to install missing pip packages
def install(package):
  if hasattr(pip, 'main'):
    pip.main(['install', package])
  else:
    pip._internal.main(['install', package])

try:
  from ldap3 import Server, Connection, ALL
  from ldap3.utils.conv import escape_bytes, escape_filter_chars
except:
  install('ldap3')
  from ldap3 import Server, Connection, ALL
  from ldap3.utils.conv import escape_bytes, escape_filter_chars

# Quick and dirty print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# XXX: Update these with settings apropriate to your environment:
# (mine below are based on Active Directory and a security group)
SERVER = "ldap://192.168.86.3:389"

# We need to search by SAM/UPN to find the DN, so we use a helper account
# This account should be unprivileged and blocked from interactive logon
HELPERDN = "cn=ldapservice,ou=users,DC=ldap,DC=goauthentik,DC=io"
#Orginal string 
#"CN=LDAP Helper,OU=Service Accounts,OU=Accounts,DC=ad,DC=example,DC=com"
HELPERPASS = "N0tMyPassword"

TIMEOUT = 3
BASEDN = "DC=ldap,DC=goauthentik,DC=io"

# Attributes to retrieve during LDAP search
# examples "cn", "uid"
ATTRS = "cn"

# Base filter for LDAP search (you can add a group filter here as well)
#
# this is the part to find the groups for my guest and me, needs to be changed here and at the bottom
#(|(memberof=cn=admin,ou=groups,dc=ldap,dc=goauthentik,dc=io)(memberof=cn=guest,ou=groups,dc=ldap,dc=goauthentik,dc=io))
BASE_FILTER = """
    (&
        (objectClass=person)
        (|
            (sAMAccountName={})
            (cn={})
        )
        
        (|(memberof=cn=admin,ou=groups,dc=ldap,dc=goauthentik,dc=io)
        
        (memberof=cn=guest,ou=groups,dc=ldap,dc=goauthentik,dc=io))
    )"""
#########################
### CONFIGURATION END ###
#########################

# Check if required environment variables are set
if "username" not in os.environ or "password" not in os.environ:
    eprint("Need username and password environment variables!")
    exit(1)

# Escape special characters in the username for LDAP search
safe_username = escape_filter_chars(os.environ["username"])

# LDAP filter for user search
FILTER =  BASE_FILTER.format(safe_username, safe_username)

#¤"(&{}({}={}))".format(BASE_FILTER, ATTRS, safe_username)

# Initialize LDAP server connection
server = Server(SERVER, get_info=ALL)
try:
    # Attempt to bind to the LDAP server with helper credentials
    conn = Connection(
        server, HELPERDN, password=HELPERPASS, auto_bind=True, raise_exceptions=True
    )
except Exception as e:
    eprint("initial bind failed: {}".format(e))
    exit(1)

# Perform LDAP search for the user
search = conn.search(BASEDN, FILTER,attributes=['displayName','memberof', 'sAMAccountName'])

# Check if the search returned any results
if len(conn.entries) > 0:
    eprint(
        "search success: username {}, result {}".format(
            os.environ["username"], conn.entries
        )
    )
    # Extract user DN and displayName from search results
    user_dn = conn.entries[0].entry_dn
    user_name = conn.entries[0].entry_dn
    user_displayName = conn.entries[0].displayName
    user_memberof = conn.entries[0].memberOf
else:
    eprint("search for username {} yielded empty result".format(os.environ["username"]))
    exit(1)

# Unbind (close) the initial LDAP connection
conn.unbind()

# Initialize a new LDAP server connection using user credentials
server = Server(SERVER, get_info=ALL)
try:
    conn = Connection(
        server,
        user_dn,
        password=os.environ["password"],
        auto_bind=True,
        raise_exceptions=True,
    )
except Exception as e:
    eprint("bind as {} failed: {}".format(os.environ["username"], e))
    exit(1)

#This part here sets the user access
#I think it checks the authenik users for grups named
# admin
# or 
# guest
#groups
if "cn=admin,ou=groups,dc=ldap,dc=goauthentik,dc=io" in user_memberof:
    print("name = {}".format(user_displayName), "group = system-admin", "local_only = false" ,sep=os.linesep)
#groups
if "cn=guest,ou=groups,dc=ldap,dc=goauthentik,dc=io" in user_memberof:
    print("name = {}".format(user_displayName), "group = system-users", "local_only = true " ,  sep=os.linesep)

# Print success message to standard error
eprint("{} authenticated successfully".format(os.environ["username"]))

# Exit with a success status code
exit(0)
