FROM osixia/openldap:1.5.0

# Copy bootstrap file to the correct location
COPY bootstrap.ldif /container/service/slapd/assets/config/bootstrap/ldif/custom/01-bootstrap.ldif

# Set environment variables
ENV LDAP_ORGANISATION="Example Inc." \
    LDAP_DOMAIN="example.org" \
    LDAP_BASE_DN="dc=example,dc=org" \
    LDAP_ADMIN_PASSWORD="adminpassword" \
    LDAP_CONFIG_PASSWORD="configpassword" \
    LDAP_READONLY_USER="false" \
    LDAP_RFC2307BIS_SCHEMA="false" \
    LDAP_BACKEND="mdb" \
    LDAP_TLS="true" \
    LDAP_TLS_CRT_FILENAME="ldap.crt" \
    LDAP_TLS_KEY_FILENAME="ldap.key" \
    LDAP_TLS_DH_PARAM_FILENAME="dhparam.pem" \
    LDAP_TLS_CA_CRT_FILENAME="ca.crt" \
    LDAP_TLS_ENFORCE="false" \
    LDAP_TLS_VERIFY_CLIENT="never" \
    LDAP_REPLICATION="false"

EXPOSE 389 636 