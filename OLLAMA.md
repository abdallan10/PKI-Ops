# Agents consultatifs Ollama (expérimental)

Le modèle local **qwen2.5:1.5b** peut être interrogé par cinq rôles consultatifs : guichet, contrôleur, émetteur, révocation, auditeur.

**Limite de sécurité :** ces agents ne détiennent aucune clé et ne peuvent pas approuver, signer ou révoquer un certificat. Le moteur déterministe et les contrôles cryptographiques restent seuls décisionnaires. Cette intégration est une interface de conseils IA, pas encore une orchestration LLM autonome de bout en bout.

## Installation Windows

1. Installer Ollama et télécharger le modèle : `ollama pull qwen2.5:1.5b`.
2. Démarrer Ollama (`ollama serve` si nécessaire).
3. Dans le dossier du projet, exécuter :

```powershell
.\.venv\Scripts\python.exe -c "from pkiops.llm import OllamaAdvisor; print(OllamaAdvisor().advise('controleur', {'dns':'node.lab.test','days':30,'policy_result':'approved'}))"
```

L'URL par défaut est `http://127.0.0.1:11434`; la variable `PKIOPS_OLLAMA_URL` peut la remplacer. Les tests unitaires utilisent des réponses simulées et ne requièrent aucun serveur Ollama.

## Sécurité et limites

- Les entrées du modèle sont filtrées sur une liste de métadonnées publiques.
- Les sorties sont du texte non fiable, jamais des autorisations.
- Aucun test de robustesse d'un LLM face aux injections n'est encore validé.
- La campagne `make reproduce` reste une baseline déterministe.
