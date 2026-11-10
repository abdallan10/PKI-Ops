# PKI-Ops — projet de cryptographie appliquée

Prototype de gestion d'une infrastructure à clés publiques (PKI), sujet 4.

## État du projet
**Version de développement, non finalisée pour la remise.** Le moteur déterministe a été testé localement (13 tests réussis). Les agents LLM locaux, OCSP et certaines expériences restent à implémenter et à valider. La validation de GitHub Actions sur le dépôt publié reste à confirmer.

## Fonctions implémentées
- Autorités racine et intermédiaire, certificats X.509.
- Contrôles de demandes CSR et politique de sécurité.
- Émission, révocation par CRL, renouvellement.
- Démonstration mTLS locale avec contrôle applicatif de révocation.
- Registre chaîné et signé, campagne de demandes et tests automatisés.

## Installation
Python 3.11+, Linux ou WSL, et make.

```bash
git clone https://github.com/abdallan10/PKI-Ops.git
cd PKI-Ops
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
make reproduce
```

Les secrets de laboratoire sont exclusivement destinés aux tests. Ne pas les réutiliser en production.

## Limites
Les cinq rôles d'agents sont déterministes : ils ne constituent pas encore des agents LLM. La campagne d'injections est une simulation de données hostiles, non une évaluation d'un modèle. Aucun OCSP n'est implémenté. Ne pas utiliser comme PKI de production.
