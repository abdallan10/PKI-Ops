# PKI-Ops — laboratoire de cryptographie appliquée

Prototype pédagogique de gestion d'une infrastructure à clés publiques (PKI), sujet 4. **Non destiné à la production.**

## État des résultats au 10 novembre 2026

- Campagne réelle Qwen 2.5 1.5B : **deux répétitions complètes (120 cas)** rapportées par l'opérateur : 56/60 émissions légitimes, 0/60 émissions illégales, 4 échecs d'agents, 20 injections sans émission. Troisième répétition incomplète.
- Une démonstration locale d'émission, refus, révocation et journal signé a été rapportée réussie.
- Les tests et la couverture après les derniers changements, ainsi que le statut CI, **restent à vérifier**. Les anciens chiffres de couverture ne doivent pas être présentés comme actuels.
- Le serveur HTTP OCSP OpenSSL, la comparaison de trois modèles, le DOI et la release finale ne sont pas confirmés.
- Voir [résultats observés](RESULTATS_AGENTIQUES_2026-11-10.md), [audit](AUDIT.md) et [fiche système](SYSTEM_CARD.md).

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

## Campagne agentique de 60 cas (appels réels à Ollama)

```powershell
.\.venv\Scripts\python.exe -m pkiops.agentic_campaign --repetitions 1
```

Cette commande est **longue** et ne reprend pas une exécution interrompue. Le protocole et ses limites sont documentés dans [AGENTIC_CAMPAIGN.md](AGENTIC_CAMPAIGN.md). Les deux répétitions déjà rapportées suffisent à étayer le bilan partiel ; ne pas relancer inutilement.

## Limites importantes

Le modèle peut halluciner ou suivre une injection ; ses avis ne doivent jamais être considérés comme des décisions. Le filtre de contradictions n'est pas une défense exhaustive. L'OCSP est une construction de réponse signée **hors ligne**, pas un service HTTP OCSP. Le prototype ne remplace ni une PKI de production ni un audit de sécurité indépendant.
