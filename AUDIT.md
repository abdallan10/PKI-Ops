# Audit de sécurité du prototype

Le système applique une politique déterministe avant émission, conserve une trace des opérations et produit un registre signé. Les tests vérifient le rejet de demandes non conformes, la révocation et la détection de modification du registre.

Limites : pas de validation OCSP ni de modèle LLM local. Les simulations d'injection de prompt ne constituent pas une évaluation d'un LLM.
