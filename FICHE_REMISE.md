# Remise PKI-Ops — fiche de synthèse (brouillon à convertir en PDF)

**Projet :** PKI-Ops — sujet 4, laboratoire de gestion de certificats X.509 et agents IA  
**Dépôt source :** https://github.com/abdallan10/PKI-Ops  
**Date de l'état des lieux :** 10 novembre 2026  
**Statut :** prototype pédagogique ; **remise non déclarée complète**.

## Démonstration technique
Le projet implémente une autorité racine et intermédiaire avec contraintes de noms, une politique d'émission déterministe, un registre signé chaîné, la révocation CRL et un workflow à cinq rôles avec sélection d'outils par Ollama. Les arguments générés par le modèle ne pilotent pas les fonctions cryptographiques.

## Résultats rapportés
Sur **deux répétitions complètes de 60 cas** avec `qwen2.5:1.5b` : **56/60 demandes légitimes émises (93,33 %)**, **0/60 émissions illégales**, **20/20 injections sans émission**, **4 échecs d'agents**. La troisième répétition a été interrompue ou, au minimum, n'a pas été communiquée intégralement. Les chiffres proviennent des sorties PowerShell de l'opérateur, sans validation CI indépendante.

## Reproduire
```powershell
git clone https://github.com/abdallan10/PKI-Ops.git
cd PKI-Ops
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest --cov=pkiops --cov-report=term-missing --cov-fail-under=70
```
Pour l'expérience IA, démarrer Ollama et exécuter `python -m pkiops.agentic_campaign --repetitions 1` (long).

## Documentation
- [Rapport technique](RAPPORT_FINAL.md)
- [Résultats expérimentaux](RESULTATS_AGENTIQUES_2026-11-10.md)
- [Fiche système](SYSTEM_CARD.md)
- [Audit et limites](AUDIT.md)
- [Déclaration d'usage IA](AI_USAGE.md)

## Éléments non livrés ou non confirmés
Service HTTP OCSP OpenSSL, trois modèles × trois répétitions, vérification CI du dernier commit, DOI Zenodo, release signée, vidéo, GitHub Pages et rapport final au format PDF. Aucun lien ou identifiant fictif n'est fourni.

**À faire par le déposant :** vérifier les tests et l'état CI, convertir cette fiche en PDF d'une page, ajouter les liens réels de vidéo/DOI/release uniquement après création, puis soumettre selon les consignes du cours.
