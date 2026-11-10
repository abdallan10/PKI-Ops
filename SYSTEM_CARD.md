# Fiche système — PKI-Ops (10 novembre 2026)

## Usage prévu
Laboratoire pédagogique de PKI X.509 avec rôles agentiques Ollama. **Interdit en production**.

## Architecture et frontières de confiance
- `pkiops/core.py` : création de CA racine et intermédiaire, Name Constraints DNS, CSR, certificats, CRL, vérification de chaîne, journal signé.
- `pkiops/agents.py` : politique déterministe d'émission, révocation, audit et allowlist de cinq rôles.
- `pkiops/agentic.py` et `pkiops/agentic_workflow.py` : sélection de l'outil par le LLM, contrôle de rôle et d'étape, arguments générés par le modèle ignorés, fonctions Python liées aux entrées de confiance. Le LLM n'est pas une autorité d'émission.
- `pkiops/llm.py` : appels au serveur Ollama local ; aucune clé privée n'est envoyée au modèle.
- `pkiops/ocsp.py` : réponses OCSP signées **hors ligne** ; absence de service HTTP OCSP réel.

## Risques
Injections de prompt, hallucinations, refus indus dus aux erreurs de modèle, indisponibilité/timeout, publication accidentelle de traces, compromission de clés de laboratoire, interprétation abusive de métriques.

## Contrôles
Validation déterministe du CSR avant signature et de nouveau à l'émission ; allowlists par rôle et étape ; révocation indépendante du LLM ; clés enregistrées chiffrées ; traces expurgées dans la boucle agentique ; journal chaîné signé.

## Observations
Deux campagnes complètes de 60 cas avec Qwen 2.5 1.5B ont été rapportées : 56/60 demandes légitimes émises, 0/60 émissions illégales, 4 échecs d'agents, 20 cas injectés sans émission. Ce sont des observations locales fournies par l'opérateur, non vérifiées indépendamment. Voir [résultats](RESULTATS_AGENTIQUES_2026-11-10.md).

## Limites
Pas de preuve de résistance générale du LLM aux injections ; pas de serveur HTTP OCSP ; trois configurations de modèles non comparées ; aucune certification ou validation de production ; troisième répétition partielle.
