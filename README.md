# SBOM & Vulnerability Triage — Priorisation multi-facteurs pour la conformité CRA

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white) ![Tests](https://img.shields.io/badge/tests-20%20passed-brightgreen) ![Licence](https://img.shields.io/badge/licence-MIT-blue)

**Génération de SBOM (CycloneDX), correspondance avec une base de vulnérabilités, et priorisation multi-facteurs (CVSS + EPSS + KEV) plutôt que par CVSS seul — avec synthèse de remédiation par agent IA.**

> **En bref** — trier les vulnérabilités par score CVSS fait traiter en premier des failles qui ne sont presque jamais exploitées. Ce projet génère la SBOM d'un projet (CycloneDX), retrouve ses CVE, puis les classe en combinant CVSS, probabilité d'exploitation (EPSS), exploitation confirmée (catalogue CISA KEV) et exposition, comme l'exige le suivi du Cyber Resilience Act.
>
> **La faille réellement exploitée passe de la 2ᵉ à la 1ʳᵉ place (couverture KEV du top-1 : 0 % → 100 %)** · synthèse de remédiation par agent IA · 20 tests.

Le projet s'appuie explicitement sur la littérature récente sur la priorisation de vulnérabilités (voir `docs/methodology_notes.md`).

---

## 🎯 Le problème traité

Le CRA impose de suivre et corriger les vulnérabilités des composants logiciels tout au long du cycle de vie produit, via une SBOM (Software Bill of Materials) à jour. Mais une fois la SBOM générée et les CVE identifiées, se pose une question opérationnelle cruciale : **par laquelle commencer ?**

L'approche naïve (trier par score CVSS) est trompeuse : le CVSS mesure la sévérité technique potentielle, pas la probabilité réelle d'exploitation. Moins de 5 % des CVE publiées sont un jour effectivement exploitées. Ce projet démontre, avec des chiffres mesurés, qu'une priorisation multi-facteurs (CVSS + EPSS + KEV + contexte d'exposition) identifie mieux les vraies urgences.

---

## 🏗️ Architecture

```
requirements.txt (dépendances du projet)
      │
      ▼
┌──────────────────┐     ┌───────────────────────┐     ┌──────────────────────┐
│ Génération SBOM     │────▶│ Correspondance          │────▶│ Triage multi-facteurs   │
│ (format CycloneDX)  │     │ composants ↔ CVE        │     │ CVSS + EPSS + KEV +    │
└──────────────────┘     │ (base de vulnérabilités)│     │ contexte d'exposition  │
                          └───────────────────────┘     └──────────────────────┘
                                                                      │
                                              ┌───────────────────────┴───────────────────────┐
                                              ▼                                                 ▼
                                  Rapport Markdown + synthèse IA                    Dashboard HTML interactif
                                  (agent de remédiation)                             (style tableau de bord CRA)
```

---

## 📂 Structure du projet

```
sbom-vuln-triage/
├── data/
│   ├── sample_project/requirements.txt  # projet exemple à scanner
│   └── vulnerability_db.json             # base de vulnérabilités synthétique (généré)
├── docs/
│   └── methodology_notes.md              # références de recherche, limites assumées
├── src/
│   ├── sbom/
│   │   ├── parser.py                     # parse requirements.txt -> composants
│   │   └── generator.py                  # génère le SBOM (CycloneDX)
│   ├── vulnerability/
│   │   ├── vulnerability_db.py           # correspondance composants <-> CVE
│   │   ├── epss_client.py                # client EPSS (mock/live, API FIRST.org documentée)
│   │   └── kev_client.py                 # client CISA KEV (mock/live)
│   ├── triage/
│   │   ├── models.py                     # contexte d'exposition, résultat de triage
│   │   └── engine.py                     # scoring CVSS seul vs multi-facteurs
│   ├── evaluation/
│   │   └── metrics.py                    # couverture KEV dans le top-N, changements de rang
│   ├── dashboard/
│   │   └── dashboard_builder.py          # dashboard HTML interactif (Plotly)
│   └── reporting/
│       ├── report_generator.py           # rapport Markdown de conformité
│       └── ai_remediation_agent.py       # synthèse de remédiation par agent IA (mock/réel)
├── scripts/
│   ├── generate_vulnerability_db.py
│   └── run_pipeline.py                   # pipeline complet
├── tests/                                # 20 tests unitaires
└── requirements.txt
```

---

## 🚀 Installation et démarrage rapide

```bash
git clone https://github.com/FatimaZahraRH/sbom-vuln-triage.git
cd sbom-vuln-triage

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 1. Générer la base de vulnérabilités synthétique
python scripts/generate_vulnerability_db.py

# 2. Lancer le pipeline complet (SBOM -> triage -> rapport + dashboard)
python scripts/run_pipeline.py

# 3. Ouvrir dashboard.html, consulter rapport_cra.md

# 4. Tests (nécessite la base de vulnérabilités générée à l'étape 1)
pytest tests/ -v
```

Aucune clé API, aucun accès réseau requis : tout tourne en local avec des données synthétiques (voir `docs/methodology_notes.md` pour la justification).

---

## 📊 Résultats mesurés

### Le résultat clé : couverture KEV dans le top-1

| | Classement CVSS seul | Classement multi-facteurs |
|---|---|---|
| Priorité n°1 | `pyyaml` (CVSS 9.8, EPSS 2.7 %) | `pillow` (CVSS 9.1, EPSS 63 %, **KEV confirmé**) |
| **Couverture KEV dans le top-1** | **0 %** | **100 %** |

Sur 13 vulnérabilités détectées dans le projet exemple, le classement CVSS seul aurait fait traiter en premier une bibliothèque (`pyyaml`) dont la vulnérabilité, bien que critique en théorie, n'est quasiment jamais exploitée en pratique dans ce scénario — pendant qu'une vulnérabilité réellement exploitée (`pillow`, présente au catalogue CISA KEV) attendait en 2ᵉ position.

### Changements de priorité observés

| CVE | Composant | Rang CVSS seul | Rang multi-facteurs |
|---|---|---|---|
| DEMO-2026-0004 | pyyaml | 1 | 4 (⬇️ 3 places) |
| DEMO-2026-0013 | sqlalchemy | 3 | 5 (⬇️ 2 places) |
| DEMO-2026-0009 | pillow | 2 | 1 (⬆️ 1 place) |
| DEMO-2026-0007 | urllib3 | 4 | 2 (⬆️ 2 places) |
| DEMO-2026-0002 | jinja2 | 5 | 3 (⬆️ 2 places) |

### Tests unitaires

20 tests couvrant : le parseur SBOM, la génération CycloneDX, la correspondance vulnérabilités, le moteur de scoring multi-facteurs (dont le cas central : CVSS élevé/EPSS faible vs CVSS modéré/EPSS élevé+KEV), et les métriques de comparaison.

```bash
pytest tests/ -v
# 20 passed
```

---

## 🧠 Choix de conception à retenir

- **Séparation stricte entre signal technique (CVSS) et signal de risque réel (EPSS+KEV)** : chaque composant du triage a une responsabilité unique, testable indépendamment — cohérent avec l'architecture de mes autres projets (classification vs contexte).
- **KEV assigné de façon déterministe** dans le jeu de données de démonstration (pas aléatoire) : garantit une démonstration reproductible plutôt que dépendante du hasard.
- **Architecture "mock/live" pour les clients EPSS/KEV** : même pattern que le fournisseur LLM du Governance RAG Copilot. Le code est prêt pour une vraie API sans modification, le mode mock est utilisé par défaut pour que la démonstration tourne hors-ligne et reste reproductible.
- **Agent IA de synthèse réutilisant l'abstraction LLM déjà construite** : plutôt que de recoder une intégration LLM from scratch, ce module documente explicitement comment brancher le même mécanisme que `GovernanceChatbot` (projet Governance RAG Copilot).
- **Métrique d'évaluation reprise directement de la littérature** (couverture KEV dans le top-N) plutôt qu'inventée : permet une comparaison honnête avec les résultats publiés, plutôt qu'une métrique choisie pour bien paraître.

---

## ⚠️ Limites assumées

- **CVE et scores CVSS/EPSS synthétiques** — voir `docs/methodology_notes.md` pour le détail complet de cette limitation et de ce qui est réellement vérifiable.
- **Correspondance composant/version exacte**, pas par plage de versions (une vraie base de vulnérabilités comme OSV.dev gère des plages complexes, ex. "toutes les versions < 2.4.1").
- **Pas de résolution de dépendances transitives** : seules les dépendances directement listées dans `requirements.txt` sont scannées, pas leurs propres dépendances.
- **Agent IA en mode mock uniquement dans cette démonstration** : l'intégration réelle (Azure OpenAI) est documentée mais non exécutée ici (cohérent avec le reste du portfolio).

---

## 🛠️ Stack technique

Python 3.12 · Plotly (dashboard) · pytest

---

## Licence

Distribué sous licence MIT (voir [`LICENSE`](LICENSE)). Projet personnel à but pédagogique et de démonstration. Toutes les CVE, scores et données de vulnérabilité sont synthétiques.
