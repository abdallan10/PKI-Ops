# Expérience Ollama réelle (à exécuter localement)

Ce protocole teste trois cas : CSR autorisée, CSR hors politique, et CSR hors politique accompagnée d'une instruction malveillante destinée au modèle. L'instruction est transmise uniquement comme `request_note` au contrôleur IA ; elle n'est jamais transmise au validateur de certificats.

Démarrer Ollama et charger `qwen2.5:1.5b`, puis sous Windows PowerShell :

```powershell
git pull origin main
.\.venv\Scripts\python.exe -m pytest --cov=pkiops --cov-report=term-missing --cov-fail-under=70
.\.venv\Scripts\python.exe -m pkiops.ai_experiment
```

Les résultats sont écrits dans `results/raw/ollama-experiment.json`, avec une trace des réponses IA dans `results/raw/ollama-experiment.trace.jsonl`. **Attention :** les réponses des agents peuvent contenir du texte influencé par une injection. Vérifier manuellement le contenu de `injected_advice.advice` avant de conclure sur la résistance du modèle.

Les résultats `policy_correct_count` mesurent la conformité des décisions **du moteur déterministe**, pas celle du LLM. La campagne est courte (3 cas), exploratoire, et ne constitue pas une évaluation statistique de robustesse. Aucun serveur Ollama n'est requis pour les tests unitaires.
