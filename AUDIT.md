# Audit de sécurité — état au 10 novembre 2026

**Périmètre : revue documentaire du code et des sorties locales rapportées, non audit indépendant.**

| Contrôle | État | Preuve / limite |
|---|---|---|
| Politique avant émission | Implémenté | `validate_csr`, `Orchestrator.request`, `issue` |
| Séparation modèle / clés privées | Implémenté dans le workflow agentique | Arguments du LLM ignorés dans les closures de `AgenticPKIWorkflow` |
| Outils par rôle | Implémenté | `ALLOWLIST` et outils autorisés par étape |
| Contraintes de noms X.509 | Implémenté | `create_intermediate`, `verify_chain` |
| CRL / révocation | Implémenté | `Orchestrator.revoke`, `core.crl` |
| Journal signé et chaîné | Implémenté | `append_ledger`, `verify_ledger` |
| OCSP HTTP avec OpenSSL | **Non confirmé / non livré** | Réponses OCSP signées hors ligne seulement |
| Rejet mTLS après révocation | À confirmer par test bout en bout | Démonstration mTLS présente, pas de preuve complète ici |
| Résistance aux injections | **Partielle** | 20 cas injectés sans émission illégale, mais sorties textuelles non auditées |
| Résilience du modèle | **Insuffisante** | 4 échecs sur 60 demandes légitimes dans deux répétitions |
| Trois modèles / trois répétitions | **Non satisfait** | Un modèle, deux répétitions complètes |
| CI, couverture actuelle | **Non vérifiées** | Workflow GitHub présent, exécution non confirmée |
| Signature de release, DOI, vidéo | **Non confirmés** | Nécessitent des actions et preuves externes |

## Menaces résiduelles
Un modèle peut produire des instructions ou justifications trompeuses ; ses sorties ne doivent pas être traitées comme autorisations. Les timeouts dégradent la disponibilité. Les outils exécutent des opérations déterministes mais l'intégration n'a pas subi d'audit de production. Les journaux locaux peuvent contenir des données opérationnelles ; les relire avant publication.

## Conclusion
Aucune émission illégale rapportée dans 120 cas observés. **Ce résultat n'est pas une preuve de sécurité exhaustive.** Voir [bilan](RESULTATS_AGENTIQUES_2026-11-10.md).
