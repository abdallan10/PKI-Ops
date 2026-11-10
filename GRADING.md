# Guide de vérification automatisée — PKI-Ops

Ce dépôt est un **prototype déterministe**, et non la version finale du sujet avec agents LLM et OCSP. Il ne doit pas être évalué comme si ces composants existaient.

## Environnement

- Linux (Ubuntu recommandé)
- Python 3.11 ou supérieur
- `make`
- Accès à PyPI pour installer les dépendances

## Depuis un clonage neuf

```bash
git clone https://github.com/abdallan10/PKI-Ops.git
cd PKI-Ops
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
make reproduce
```

Le code de sortie attendu de `make reproduce` est `0`. Le programme doit afficher une suite de tests réussie, puis générer `results/raw/campaign.json` et `results/raw/metrics.json`.

La campagne déterministe contient 60 demandes : 30 légitimes et 30 non conformes. Le fichier `metrics.json` expose les nombres réellement obtenus. **Ne pas présenter ces chiffres comme des performances d'un LLM.**

## Commandes de diagnostic

```bash
python -m pytest -v
python -m pytest -q --cov=pkiops --cov-report=term-missing --cov-fail-under=70
```

## Sécurité et limites

- Les clés de laboratoire sont générées dans `.lab/`, ignoré par Git.
- Le mot de passe par défaut du Makefile est uniquement un secret de démonstration.
- La commande `init` nécessite `--approve-root` pour confirmer la signature de la racine.
- Les fichiers de test mTLS contiennent temporairement des clés non chiffrées dans un répertoire de test local : ne pas utiliser en production.
- La vérification de révocation mTLS est un précontrôle applicatif, pas un service OCSP.
- Les cinq rôles sont des modules déterministes, pas des agents IA génératifs.

## Vérification continue

La configuration est dans `.github/workflows/tests.yml`. Les exécutions sont visibles dans l'onglet Actions du dépôt. Une réussite locale ne prouve pas à elle seule que l'exécution distante est réussie.
