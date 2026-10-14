# Notes méthodologiques et références

## 1. Le problème : pourquoi le CVSS seul ne suffit pas

Le CVSS (Common Vulnerability Scoring System) mesure la **sévérité technique potentielle** d'une vulnérabilité -- l'ampleur des dégâts *si* elle était exploitée. Il ne dit rien sur la probabilité qu'elle le soit *réellement*. Selon les données citées par plusieurs sources spécialisées (FIRST/EPSS), moins de 5 % des CVE publiées sont un jour effectivement exploitées dans la nature. Trier uniquement par CVSS conduit donc à traiter en priorité des vulnérabilités théoriquement graves mais jamais attaquées, au détriment de vulnérabilités moins spectaculaires mais activement exploitées.

## 2. L'approche multi-facteurs (CVSS + EPSS + KEV)

- **CVSS** (Mell, Scarfone, Romanosky ; NIST IR 7435) : sévérité technique, 0 à 10.
- **EPSS** (Exploit Prediction Scoring System) -- Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., Adjerid, I. (2019). *"Exploit Prediction Scoring System (EPSS)"*, arXiv:1908.04856. Modèle de machine learning entraîné sur des données de menace réelles, prédisant la probabilité d'exploitation d'une CVE dans les 30 jours. Mis à jour quotidiennement par FIRST.org (modèle v4, mars 2025).
- **KEV** (CISA Known Exploited Vulnerabilities) : catalogue public listant les CVE dont l'exploitation active a été confirmée -- signal binaire mais très fort.

Ce projet reprend la combinaison des trois signaux explicitement décrite dans :

> O'Donoghue et al. (2026). *"Automated SBOM-Driven Vulnerability Triage for IoT Firmware: A Lightweight Pipeline for Risk Prioritization"*, arXiv:2601.01308. Pipeline combinant CVSS, EPSS et catalogue KEV pour prioriser les vulnérabilités identifiées via SBOM.

et s'inspire de la méthodologie d'évaluation de :

> *"SBOM-Based Vulnerability Prioritization in Software Supply Chain Using Machine Learning"*, Advanced Information Technology, 2025/2026. Utilise la **couverture KEV dans le top-N** comme métrique d'évaluation (+31 % rapporté vs baseline CVSS), reprise telle quelle dans ce projet (`src/evaluation/metrics.py`).

## 3. Résultat mesuré sur le jeu de démonstration

Sur les 13 vulnérabilités synthétiques du projet exemple :
- Classement **CVSS seul** : priorité n°1 = `pyyaml` (CVSS 9.8, EPSS 2.7 %) -- jamais réellement exploité dans ce scénario.
- Classement **multi-facteurs** : priorité n°1 = `pillow` (CVSS 9.1, EPSS 63 %, présent au catalogue KEV) -- la vraie urgence.
- **Couverture KEV dans le top-1 : 0 % (CVSS seul) → 100 % (multi-facteurs).**

## 4. Portée et honnêteté sur les données utilisées

- Les identifiants CVE (`DEMO-2026-XXXX`), les scores CVSS/EPSS et les descriptions de vulnérabilité sont **synthétiques**, générés pour cette démonstration -- ils ne correspondent à aucune vraie CVE. Les classes de vulnérabilité (désérialisation YAML, ReDoS, SSTI...) s'inspirent de types de failles réellement documentés historiquement pour ces familles de paquets, sans prétendre reproduire un incident réel précis.
- Les clients `epss_client.py` et `kev_client.py` documentent et implémentent l'intégration aux vraies APIs publiques (FIRST.org EPSS API, flux CISA KEV), mais tournent en **mode mock** par défaut : cet environnement de développement n'a pas d'accès réseau vers ces domaines. Passer en mode "live" ne nécessite aucune autre modification de code.
- Format SBOM inspiré de **CycloneDX** (OWASP Foundation), standard largement utilisé et compatible avec les exigences de traçabilité du Cyber Resilience Act.

## Références complètes

- Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., Adjerid, I. (2019). *Exploit Prediction Scoring System (EPSS)*. arXiv:1908.04856.
- O'Donoghue, E. et al. (2026). *Automated SBOM-Driven Vulnerability Triage for IoT Firmware*. arXiv:2601.01308.
- *SBOM-Based Vulnerability Prioritization in Software Supply Chain Using Machine Learning*. Advanced Information Technology, 1(2(5)), 2025/2026.
- Mell, P., Scarfone, K., Romanosky, S. *The Common Vulnerability Scoring System (CVSS) and its Applicability to Federal Agency Systems*. NIST IR 7435.
- CycloneDX Specification, OWASP Foundation. https://cyclonedx.org/specification/overview/
