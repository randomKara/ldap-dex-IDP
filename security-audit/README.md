# 🔒 OAuth2/OIDC Zero Trust Security Audit Tools

Ce dossier contient les outils d'audit de sécurité pour valider l'architecture OAuth2/OIDC Zero Trust.

## 📁 Structure

```
security-audit/
├── security_audit.py           # Script principal d'audit (Python)
├── run_security_audit.sh       # Runner shell avec interface utilisateur
├── security_audit_config.yaml  # Configuration des tests
├── requirements.txt             # Dépendances Python
├── README_Security_Audit.md    # Documentation technique complète
├── SECURITY_TESTING.md         # Guide utilisateur en français
├── PROJECT_SUMMARY.md          # Résumé du projet
└── README.md                   # Ce fichier
```

## 🚀 Utilisation Rapide

### Depuis le répertoire racine du projet
```bash
# Audit complet
./run_security_audit.sh

# Avec logs détaillés  
./run_security_audit.sh audit --verbose

# Vérification système
./run_security_audit.sh check
```

### Depuis ce dossier
```bash
cd security-audit/

# Audit complet
./run_security_audit.sh

# Vérification des prérequis
./run_security_audit.sh check

# Nettoyage des anciens rapports
./run_security_audit.sh clean
```

## 📊 Tests Effectués

- **Infrastructure** : Connectivité et disponibilité des services
- **Authentication Flow** : Validation du flow OAuth2/OIDC complet
- **Access Control** : Tests de contournement et contrôle d'accès Zero Trust
- **Session Management** : Sécurité des sessions et cookies
- **Input Validation** : Protection contre les injections (SQL, XSS)
- **Network Security** : Isolation réseau et segmentation
- **HTTPS/TLS** : Configuration du transport sécurisé
- **Security Headers** : Headers de sécurité HTTP
- **Information Disclosure** : Protection contre les fuites d'information
- **Zero Trust Compliance** : Conformité aux principes Zero Trust

## 📋 Rapports Générés

Les rapports sont automatiquement générés dans ce dossier :

- `security_audit_report_YYYYMMDD_HHMMSS.json` - Rapport JSON pour intégration
- `security_audit_report_YYYYMMDD_HHMMSS.html` - Rapport HTML visuel
- `security_audit.log` - Logs détaillés d'exécution

## ⚙️ Configuration

Editez `security_audit_config.yaml` pour personnaliser :

- Endpoints cibles
- Timeouts et retry
- Payloads de test
- Headers de conformité requis
- Formats de rapport

## 🔄 Intégration CI/CD

### GitLab CI
```yaml
security_audit:
  stage: security
  script:
    - ./run_security_audit.sh audit --verbose
  artifacts:
    paths:
      - security-audit/security_audit_report_*.html
```

### GitHub Actions
```yaml
- name: Security Audit
  run: ./run_security_audit.sh audit --verbose
```

## 📖 Documentation

- **Guide technique** : `README_Security_Audit.md`
- **Guide utilisateur** : `SECURITY_TESTING.md`
- **Résumé projet** : `PROJECT_SUMMARY.md`

---

**⚠️ Avertissement** : Ces outils sont conçus pour les tests de sécurité autorisés uniquement. 