#!/bin/bash

# Start OpenLDAP in background
/container/tool/run --copy-service &
LDAP_PID=$!

# Wait for LDAP to be ready
echo "Waiting for LDAP server to start..."
sleep 15

# Add test users using ldapadd
echo "Adding test users to LDAP..."

# Create organizational units
ldapadd -x -D "cn=admin,dc=example,dc=org" -w adminpassword << EOF
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups
EOF

# Add test users
ldapadd -x -D "cn=admin,dc=example,dc=org" -w adminpassword << EOF
dn: cn=user1,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: user1
sn: User1
givenName: Test
displayName: Test User1
mail: user1@example.org
uid: user1
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/user1
loginShell: /bin/bash
userPassword: password1

dn: cn=user2,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: user2
sn: User2
givenName: Test
displayName: Test User2
mail: user2@example.org
uid: user2
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/user2
loginShell: /bin/bash
userPassword: password2

dn: cn=user3,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: user3
sn: User3
givenName: Test
displayName: Test User3
mail: user3@example.org
uid: user3
uidNumber: 1003
gidNumber: 1003
homeDirectory: /home/user3
loginShell: /bin/bash
userPassword: password3

dn: cn=user4,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: user4
sn: User4
givenName: Test
displayName: Test User4
mail: user4@example.org
uid: user4
uidNumber: 1004
gidNumber: 1004
homeDirectory: /home/user4
loginShell: /bin/bash
userPassword: password4
EOF

# Add groups
ldapadd -x -D "cn=admin,dc=example,dc=org" -w adminpassword << EOF
dn: cn=users,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: users
member: cn=user1,ou=people,dc=example,dc=org
member: cn=user2,ou=people,dc=example,dc=org
member: cn=user3,ou=people,dc=example,dc=org
member: cn=user4,ou=people,dc=example,dc=org
EOF

echo "Test users added successfully!"

# Keep the container running by waiting for the LDAP process
wait $LDAP_PID 