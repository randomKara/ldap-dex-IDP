# 🔒 Guide de Test de Sécurité OAuth2/OIDC Zero Trust

## Vue d'ensemble

Ce guide vous permet d'exécuter des tests de sécurité complets sur votre architecture OAuth2/OIDC Zero Trust pour valider la conformité et identifier les vulnérabilités.

## Utilisation Rapide

### Exécution Basique
```bash
# Audit de sécurité complet
./run_security_audit.sh

# Avec logs détaillés
./run_security_audit.sh audit --verbose

# Vérification des prérequis
./run_security_audit.sh check
```

### Commandes Disponibles

#### 🔍 **Audit Complet**
```bash
./run_security_audit.sh audit
```
- Teste tous les aspects de sécurité
- Génère des rapports JSON et HTML
- Calcule un score Zero Trust (0-100)
- Fournit des recommandations prioritaires

#### ✅ **Vérification Système**
```bash
./run_security_audit.sh check
```
- Vérifie que tous les services sont opérationnels
- Valide la connectivité réseau
- Contrôle les prérequis

#### 📊 **Consultation des Rapports**
```bash
./run_security_audit.sh report
```
- Ouvre le dernier rapport HTML dans le navigateur
- Présentation visuelle des résultats
- Navigation interactive par catégorie

#### 🧹 **Nettoyage**
```bash
./run_security_audit.sh clean
```
- Supprime les anciens rapports
- Garde les 5 rapports les plus récents
- Compresse les logs volumineux

## Catégories de Tests

### 🛡️ **Tests d'Infrastructure**
- ✅ Disponibilité des services
- ✅ Connectivité réseau
- ✅ Isolation des composants

### 🔐 **Tests d'Authentification**
- ✅ Flow OAuth2/OIDC complet
- ✅ Découverte OIDC
- ✅ Validation des redirections
- ✅ Contrôle des tokens

### 🚫 **Tests de Contrôle d'Accès**
- ✅ Enforcement Zero Trust
- ✅ Prévention des accès directs
- ✅ Injection de headers malveillants
- ✅ Bypass d'authentification

### 🍪 **Tests de Gestion de Session**
- ✅ Sécurité des cookies
- ✅ Protection contre la fixation
- ✅ Expiration des sessions
- ✅ Régénération sécurisée

### 💉 **Tests de Validation d'Entrée**
- ✅ Injection SQL
- ✅ Cross-Site Scripting (XSS)
- ✅ Manipulation de paramètres
- ✅ Path traversal

### 🌐 **Tests de Sécurité Réseau**
- ✅ Énumération de ports
- ✅ Isolation des services
- ✅ Segmentation réseau
- ✅ Protocoles sécurisés

### 🔒 **Tests HTTPS/TLS**
- ✅ Disponibilité HTTPS
- ✅ Redirection HTTP → HTTPS
- ✅ Configuration des certificats
- ✅ Suites de chiffrement

### 📋 **Tests des Headers de Sécurité**
- ✅ Content Security Policy
- ✅ X-Frame-Options
- ✅ Strict-Transport-Security
- ✅ X-Content-Type-Options

### 📢 **Tests de Divulgation d'Information**
- ✅ Fichiers sensibles cachés
- ✅ Headers de serveur masqués
- ✅ Messages d'erreur sécurisés
- ✅ Endpoints administratifs protégés

### 🎯 **Tests de Conformité Zero Trust**
- ✅ "Never Trust, Always Verify"
- ✅ Principe du moindre privilège
- ✅ Micro-segmentation
- ✅ Monitoring continu

## Interprétation des Résultats

### Score Zero Trust
| Score | Niveau | Description |
|-------|--------|-------------|
| 90-100 | 🟢 **EXCELLENT** | Architecture Zero Trust optimale |
| 80-89  | 🟡 **BON** | Quelques améliorations mineures |
| 70-79  | 🟠 **CORRECT** | Améliorations recommandées |
| 60-69  | 🔴 **FAIBLE** | Lacunes importantes à corriger |
| <60    | ⚫ **CRITIQUE** | Refonte sécuritaire nécessaire |

### Niveaux de Posture Sécuritaire
- **LOW_RISK** : Posture acceptable, monitoring de routine
- **MEDIUM_RISK** : Quelques problèmes, surveillance renforcée
- **HIGH_RISK** : Vulnérabilités significatives, action urgente
- **CRITICAL** : Menaces immédiates, intervention d'urgence

### Classification des Sévérités
- **CRITICAL** : Vulnérabilité exploitable immédiatement
- **HIGH** : Risque élevé, correction urgente requise
- **MEDIUM** : Risque modéré, correction lors de la prochaine maintenance
- **LOW** : Amélioration mineure de sécurité
- **INFO** : Information, aucune action immédiate

## Exemple de Rapport

```json
{
  "summary": {
    "total_tests": 38,
    "success_rate": 76.32,
    "zero_trust_score": 71,
    "overall_security_posture": "HIGH_RISK",
    "severity_breakdown": {
      "CRITICAL": 0,
      "HIGH": 3,
      "MEDIUM": 5,
      "LOW": 1
    }
  },
  "recommendations": [
    "Implement HTTPS with proper TLS configuration",
    "Configure HTTP to HTTPS redirect", 
    "Add security headers (CSP, HSTS, X-Frame-Options)",
    "Remove or mask Server header"
  ]
}
```

## Configuration Personnalisée

### Fichier `security_audit_config.yaml`
```yaml
targets:
  pep_endpoint: "http://localhost:5000"
  oidc_provider: "http://localhost:5556" 
  backend_app: "http://localhost:8080"
  https_endpoint: "https://localhost:5443"

security_tests:
  timeout: 10
  max_retries: 3
  rate_limit_requests: 20

compliance:
  required_headers:
    - "X-Content-Type-Options"
    - "X-Frame-Options"
    - "Strict-Transport-Security"
    - "Content-Security-Policy"
```

## Intégration CI/CD

### Pipeline GitLab CI
```yaml
security_audit:
  stage: security
  script:
    - ./run_security_audit.sh audit --verbose
  artifacts:
    reports:
      junit: security_audit_report_*.json
    paths:
      - security_audit_report_*.html
  only:
    - main
    - develop
```

### Pipeline GitHub Actions
```yaml
- name: Security Audit
  run: |
    ./run_security_audit.sh audit --verbose
    # Fail if security posture is CRITICAL
    if grep -q '"overall_security_posture": "CRITICAL"' security_audit_report_*.json; then
      exit 1
    fi
```

## Dépannage

### Erreurs Communes

#### Services Non Accessibles
```bash
# Vérifier que Docker Compose est démarré
docker compose ps

# Redémarrer les services si nécessaire  
docker compose up -d
```

#### Timeouts de Connexion
```yaml
# Dans security_audit_config.yaml
security_tests:
  timeout: 30  # Augmenter le timeout
  max_retries: 5
```

#### Problèmes de Permissions
```bash
# Donner les permissions d'exécution
chmod +x run_security_audit.sh
chmod +x security_audit.py
```

## Bonnes Pratiques

### Avant l'Audit
1. ✅ Vérifier que tous les services sont démarrés
2. ✅ S'assurer d'avoir les permissions nécessaires
3. ✅ Sauvegarder la configuration actuelle
4. ✅ Documenter l'environnement de test

### Pendant l'Audit
1. 📊 Surveiller les performances du système
2. 📝 Analyser les logs en temps réel
3. 🔍 Observer les patterns de trafic réseau
4. ⚠️ Noter toute anomalie ou échec de test

### Après l'Audit
1. 📋 Analyser tous les résultats en détail
2. 🎯 Prioriser les corrections par sévérité
3. 📅 Planifier la remédiation des problèmes
4. ✅ Valider les corrections avec de nouveaux tests

## Automatisation

### Test Quotidien
```bash
# Ajouter à crontab pour exécution quotidienne à 2h
0 2 * * * cd /path/to/project && ./run_security_audit.sh audit > /dev/null 2>&1
```

### Monitoring Continu
```bash
# Script de surveillance
#!/bin/bash
while true; do
  ./run_security_audit.sh audit
  if [ $? -ne 0 ]; then
    # Envoyer alerte (email, Slack, etc.)
    echo "ALERT: Security audit failed!" | mail admin@company.com
  fi
  sleep 3600  # Test toutes les heures
done
```

## Support et Documentation

- 📖 **Documentation complète** : `README_Security_Audit.md`
- 🐛 **Rapports de bugs** : Issues GitHub
- 💬 **Questions** : Discussions GitHub
- 🔒 **Sécurité** : Security Policy

---

**⚠️ Avertissement Sécurité** : Ce tool est conçu exclusivement pour les tests de sécurité autorisés. Assurez-vous d'avoir les permissions appropriées avant de l'exécuter sur des systèmes de production. 