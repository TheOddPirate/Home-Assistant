#!/usr/bin/env python3
"""
LDAP-autentisering for Home Assistant.
Testet og tilpasset for bruk med Authentik.



Funksjoner:
- Automatisk installasjon av manglende pip-pakker
- Bruk av helper-konto for å gjøre initialt søk
- Autentisering av bruker mot Authentik LDAP
- Sjekk for grupper (admin/guest)

Original med instrukser: 
https://github.com/panteLx/HASS-LDAP-Auth
"""

import os
import sys
import subprocess

# Automatisk installer manglende pakker
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    from ldap3 import Server, Connection, ALL
    from ldap3.utils.conv import escape_filter_chars
except ImportError:
    install("ldap3")
    from ldap3 import Server, Connection, ALL
    from ldap3.utils.conv import escape_filter_chars

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# === LDAP KONFIGURASJON (tilpass disse til ditt miljø) ===
# === Brukerne må vøre medlem av enten "admin" eller "guest" grupppe ===
SERVER = "ldap://192.168.86.3:389"
HELPERDN = "cn=ldapservice,ou=users,DC=ldap,DC=goauthentik,DC=io"
HELPERPASS = "ldapservice"
BASEDN = "dc=ldap,dc=goauthentik,dc=io"
TIMEOUT = 3

# LDAP-filter for å søke etter brukere som tilhører admin/guest
BASE_FILTER = """
(&
    (objectClass=person)
    (|
        (cn={})
    )
    (|
        (memberof=cn=admin,ou=groups,dc=ldap,dc=goauthentik,dc=io)
        (memberof=cn=guest,ou=groups,dc=ldap,dc=goauthentik,dc=io)
    )
)
"""
# ==========================================================

# Sjekk at miljøvariabler finnes (Home Assistant sender dem inn)
if "username" not in os.environ or "password" not in os.environ:
    eprint("Error: Mangler miljøvariablene 'username' og/eller 'password'.")
    sys.exit(1)

safe_username = escape_filter_chars(os.environ["username"])
FILTER = BASE_FILTER.format(safe_username)

# Koble til LDAP-server som helper-bruker
try:
    server = Server(SERVER, get_info=ALL)
    conn = Connection(server, HELPERDN, HELPERPASS, auto_bind=True, raise_exceptions=True)
except Exception as e:
    eprint(f"Feil ved initial bind: {e}")
    sys.exit(1)

# Gjør søk etter brukeren
if not conn.search(BASEDN, FILTER, attributes=["cn", "displayName", "memberOf"]):
    eprint(f"Fant ingen bruker som matcher '{os.environ['username']}'")
    sys.exit(1)
    
# Lagrer litt info om brukeren
entry = conn.entries[0]
user_dn = entry.entry_dn
user_cn = str(entry.cn)  # Brukernavn
user_displayName = str(entry.displayName) if "displayName" in entry else user_cn
user_memberof = [str(group) for group in entry.memberOf] if "memberOf" in entry else []

conn.unbind()

# Prøv autentisering med brukerens eget passord
server = Server(SERVER, get_info=ALL)
try:
    conn = Connection(server, user=user_dn, password=os.environ["password"], auto_bind=True, raise_exceptions=True)
except Exception as e:
    eprint(f"Feil ved innlogging som {user_cn}: {e}")
    sys.exit(1)

# Skriv ut autentiseringsinfo for Home Assistant
if "cn=admin,ou=groups,dc=ldap,dc=goauthentik,dc=io" in user_memberof:
    print(f"name = {user_displayName}")
    print("group = system-admin")
    print("local_only = false")
elif "cn=guest,ou=groups,dc=ldap,dc=goauthentik,dc=io" in user_memberof:
    print(f"name = {user_displayName}")
    print("group = system-users")
    print("local_only = true")
else:
    eprint(f"Bruker {user_cn} tilhører ingen godkjente grupper.")
    sys.exit(1)

eprint(f"{user_cn} autentisert OK.")
sys.exit(0)
