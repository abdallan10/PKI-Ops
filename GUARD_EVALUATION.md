# Vérification de cohérence des avis IA

Le module `pkiops.guard` détecte **certaines affirmations explicites** en contradiction avec la politique PKI déterministe : certificat approuvé malgré un rejet, certificat refusé malgré une approbation, et affirmation que la politique est désactivée.

Quand une contradiction reconnaissable apparaît dans l'avis du contrôleur, le workflow ajoute `consistency.flagged=true` et définit son statut à `flagged`. La décision cryptographique n'est jamais changée.

## Reproduire

```powershell
git pull origin main
.\.venv\Scripts\python.exe -m pytest --cov=pkiops --cov-report=term-missing --cov-fail-under=70
.\.venv\Scripts\python.exe -m pkiops.ai_experiment
.\.venv\Scripts\python.exe -c "import json; d=json.load(open('results/raw/ollama-experiment.json',encoding='utf-8')); print(d['cases'][2]['injected_advice'])"
```

Le scénario d'injection transmet maintenant au modèle la **véritable** décision de politique, calculée avant son avis. Les fichiers de résultats précédents peuvent être écrasés par la nouvelle expérience : conserver une copie des anciens résultats si une comparaison avant/après est souhaitée.

**Limites :** le détecteur est un filtre de motifs textuels, non une preuve de compréhension sémantique. Il peut manquer des formulations détournées ou signaler à tort certaines citations ou négations. Un statut `ok` signifie seulement qu'aucun motif ciblé n'a été détecté. Les sorties doivent être examinées humainement; le contrôle de politique reste le mécanisme de sécurité réel.
