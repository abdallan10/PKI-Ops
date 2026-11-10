# PKI-Ops — projet de cryptographie appliquée

Prototype de gestion d'une infrastructure à clés publiques (PKI), sujet 4.

## État du projet
**Version de développement, non finalisée pour la remise.** Le moteur déterministe a été testé localement (13 tests réussis). Les agents LLM locaux, OCSP et certaines expériences restent à implémenter et à valider.

## Fonctions implémentées
- Autorités racine et intermédiaire, certificats X.509.
- Contrôles de demandes CSR et politique de sécurité.
- Émission, révocation par CRL, renouvellement.
- Démonstration mTLS locale avec contrôle applicatif de révocation.
- Registre chaîné et signé, campagne de demandes et tests automatisés.

## Installation prévue
Python 3.11+, Linux ou WSL.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
make reproduce
```

Les secrets de laboratoire sont exclusivement destinés aux tests. Ne pas les réutiliser en production.

**Attention :** ce dépôt est en cours de publication ; l'existence de ce README ne signifie pas que l'ensemble des fichiers a été transféré.
