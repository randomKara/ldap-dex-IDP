# Guide d'utilisation - Flask LDAP-DEX IDP

## 🚀 Démarrage rapide

```bash
# Lancer tous les services
docker compose up --build -d

# Vérifier que tous les services fonctionnent
docker compose ps
```

## ✅ Tests de vérification

### 1. Test du serveur LDAP
```bash
# Vérifier que les utilisateurs existent
docker exec ldap-server ldapsearch -x -H ldap://localhost -b "dc=example,dc=org" -D "cn=admin,dc=example,dc=org" -w adminpassword "(objectClass=inetOrgPerson)" uid

# Tester l'authentification d'un utilisateur
docker exec ldap-server ldapsearch -x -H ldap://localhost -b "dc=example,dc=org" -D "cn=user1,ou=people,dc=example,dc=org" -w password1 "(uid=user1)"
```

### 2. Test de l'application Flask
```bash
# Vérifier que Flask répond
curl -s http://localhost:5000 | grep -o "<title>.*</title>"

# Tester la redirection de login
curl -s http://localhost:5000/login 2>&1 | head -5
```

### 3. Test du serveur DEX
```bash
# Vérifier que DEX écoute
docker compose logs dex --tail 5

# Test direct de DEX
curl -s http://localhost:5556/.well-known/openid_configuration
```

## 👥 Utilisateurs disponibles

| Username | Password | Email | DN |
|----------|----------|-------|-----|
| user1 | password1 | user1@example.org | cn=user1,ou=people,dc=example,dc=org |
| user2 | password2 | user2@example.org | cn=user2,ou=people,dc=example,dc=org |
| user3 | password3 | user3@example.org | cn=user3,ou=people,dc=example,dc=org |
| user4 | password4 | user4@example.org | cn=user4,ou=people,dc=example,dc=org |

## 🛠️ Dépannage

### Problème : Services ne démarrent pas
```bash
# Arrêter et nettoyer
docker compose down -v
docker system prune -f

# Redémarrer
docker compose up --build -d
```

### Problème : LDAP ne répond pas
```bash
# Vérifier les logs LDAP
docker compose logs openldap

# Redémarrer seulement LDAP
docker compose restart openldap
```

### Problème : DEX ne répond pas
```bash
# Vérifier les logs DEX
docker compose logs dex

# Vérifier la configuration
docker exec dex-server cat /etc/dex/config.yaml
```

## 📁 Structure du projet

```
ldap-dex-IDP/
├── flask-app/           # Application Flask avec OIDC
│   ├── app.py          # Code principal
│   ├── requirements.txt # Dépendances Python
│   └── Dockerfile      # Configuration Docker
├── dex/                # Serveur DEX OIDC
│   ├── config.yaml     # Configuration DEX
│   └── Dockerfile      # Configuration Docker
├── LDAP/               # Serveur OpenLDAP
│   ├── bootstrap.ldif  # Données utilisateurs
│   ├── setup-users.sh  # Script d'initialisation
│   └── Dockerfile      # Configuration Docker
├── docker-compose.yml  # Orchestration des services
└── README.md          # Documentation
```

## 🔗 URLs importantes

- **Application Flask** : http://localhost:5000
- **Serveur LDAP** : ldap://localhost:1389
- **Serveur DEX** : http://localhost:5556
- **Admin LDAP** : cn=admin,dc=example,dc=org (mot de passe: adminpassword)

## 🔧 Commandes utiles

```bash
# Voir tous les logs
docker compose logs -f

# Redémarrer un service spécifique
docker compose restart <service-name>

# Entrer dans un conteneur
docker exec -it <container-name> /bin/bash

# Supprimer tout et recommencer
docker compose down -v && docker compose up --build -d
``` 