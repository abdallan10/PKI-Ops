# PKI-Ops — laboratoire de cryptographie appliquée

Prototype pédagogique de gestion d'une infrastructure à clés publiques (PKI), sujet 4. **Non destiné à la production.**

## État vérifié

- Tests sous Windows, Python 3.13.5 : **34 tests réussis** (résultat communiqué après le dernier correctif).
- Dernière couverture mesurée et communiquée : **92,27 %**, sur une exécution antérieure à l'ajout du détecteur ; la couverture actuelle est à remesurer.
- Expérience locale Ollama `qwen2.5:1.5b` : **3/3 décisions PKI correctes**. L'injection initiale a trompé le commentaire du modèle, sans obtenir de certificat. Lors de la nouvelle expérience, le modèle a correctement décrit le rejet.
- L'état des GitHub Actions et une installation sur une machine propre restent à vérifier.

## Fonctions

- CA racine et intermédiaire, certificats X.509, clés privées chiffrées au repos.
- Validation de CSR et émission contrôlée par une politique déterministe.
- CRL, réponses OCSP signées hors ligne, contrôle de chaîne, opérations de renouvellement et démonstration mTLS locale.
- Journal d'événements chaîné et signé.
- Cinq rôles consultatifs avec Ollama : guichet, contrôleur, émetteur, révocation, auditeur. **Ils n'ont aucune autorité cryptographique.**
- Détection heuristique de certaines contradictions dans les avis du contrôleur IA.

## Installation et tests

Python 3.11+ ; installer les dépendances avec :

```bash
git clone https://github.com/abdallan10/PKI-Ops.git
cd PKI-Ops
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest --cov=pkiops --cov-report=term-missing --cov-fail-under=70
```

Sur Windows PowerShell, remplacer les deux dernières commandes par :

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest --cov=pkiops --cov-report=term-missing --cov-fail-under=70
```

## Démonstration déterministe (sans Ollama)

Sous PowerShell :

```powershell
$env:PKIOPS_PASSWORD = "mot-de-passe-local-de-demonstration"
.\.venv\Scripts\python.exe -m pkiops.cli init --dir .lab --approve-root
.\.venv\Scripts\python.exe -m pkiops.cli campaign --dir .lab --output results/raw/campaign.json
```

La commande `init` refuse d'écraser une clé racine existante ; choisir un dossier de laboratoire neuf pour une nouvelle démonstration. La campagne déterministe de 60 requêtes **n'interroge pas de modèle IA**, même si elle contient des chaînes ressemblant à des injections.

## Expérience avec le modèle local

Installer Ollama, récupérer `qwen2.5:1.5b`, démarrer le serveur, puis :

```powershell
.\.venv\Scripts\python.exe -m pkiops.ai_experiment
```

Résultat JSON : `results/raw/ollama-experiment.json`. Cette commande fait de véritables appels au modèle et peut prendre du temps sur CPU. Voir [AI_EXPERIMENT.md](AI_EXPERIMENT.md), [GUARD_EVALUATION.md](GUARD_EVALUATION.md) et [RAPPORT_FINAL.md](RAPPORT_FINAL.md).

## Limites importantes

Le modèle peut halluciner ou suivre une injection ; ses avis ne doivent jamais être considérés comme des décisions. Le filtre de contradictions n'est pas une défense exhaustive. L'OCSP est une construction de réponse signée **hors ligne**, pas un service HTTP OCSP. Le prototype ne remplace ni une PKI de production ni un audit de sécurité indépendant.
