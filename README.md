### 📄 `README.md` – Script PowerShell de Sauvegarde

#### 🧾 Description
Ce script PowerShell avancé effectue des sauvegardes automatisées avec des fonctionnalités robustes et professionnelles :
- Journalisation complète (log)
- Vérification de l’espace disque
- Compression ZIP
- Rotation des sauvegardes (suppression des anciennes)
- Notification par email
- Mode simulation (dry-run)
- Modulaire, personnalisable
- Chargement dynamique de la configuration
- Prêt à être intégré dans des processus d’automatisation (CI/CD)
- Compatible avec le Planificateur de tâches Windows

---

#### ⚙️ Configuration

La configuration est externalisée dans un fichier `config.ps1` situé dans le même dossier que le script principal. Exemple de contenu :

```powershell
$SourcePaths = @("C:\DossierA", "D:\DossierB")
$BackupDestination = "E:\Sauvegardes"
$LogFile = "E:\Logs\backup.log"
$MinFreeGB = 5
$RetentionDays = 15
$EnableCompression = $true
$EnableDryRun = $false
$EnableMail = $true
$MailFrom = "backup@domain.com"
$MailTo = "admin@domain.com"
$SmtpServer = "smtp.domain.com"
$Date = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
```

---

#### 🧪 Fonctionnalités clés

| Fonction                  | Description |
|---------------------------|-------------|
| `Write-Log`               | Log avec horodatage dans un fichier externe |
| `Check-FreeSpace`         | Vérifie l’espace disque disponible |
| `Rotate-Backups`          | Supprime les sauvegardes obsolètes |
| `Compress-Backup`         | Compresse en .zip puis supprime la source |
| `Send-Notification`       | Envoie un email de notification (SMTP) |
| `Backup-Folder`           | Sauvegarde un dossier source |
| `Start-Backup`            | Lance toutes les étapes du processus |
| Chargement `config.ps1`   | Paramètres centralisés |
| `DryRun`                  | Mode simulation sécurisé |

---

#### 🛠️ Utilisation

1. **Exécuter manuellement** :
   - Ouvrir PowerShell en tant qu’administrateur
   - Lancer :
     ```powershell
     .\backup-script.ps1
     ```

2. **Planification avec le Planificateur de tâches Windows** :
   - Créer une tâche qui appelle :
     ```powershell
     powershell.exe -ExecutionPolicy Bypass -File "C:\Chemin\Vers\backup-script.ps1"
     ```

3. **Exécution dans un pipeline CI/CD (optionnel)** :
   - Ajoutez des tests PowerShell (Pester) pour valider la configuration ou le bon déroulement
   - Intégrez la sortie du log au système de logs de votre pipeline

---

#### 💡 Bonnes pratiques

- Gardez `config.ps1` versionné dans Git (sans credentials sensibles !)
- Testez avec `$EnableDryRun = $true` avant une première exécution réelle
- Assurez-vous que l'utilisateur qui exécute la tâche a les droits nécessaires
- Surveillez l’espace disque et automatisez les alertes via `Send-Notification`

  ---

  ### 📄 Script PowerShell de Sauvegarde (Fonctionnalités ajoutées)

#### 🆕 Nouvelles fonctionnalités

##### Vérification d'intégrité des sauvegardes
Le script inclut maintenant une vérification d'intégrité des données sauvegardées via des calculs de hachage (checksums) :
- Génération automatique de hash SHA-256 pour chaque fichier sauvegardé
- Stockage des checksums dans un fichier manifeste (`manifest.json`)
- Vérification facultative post-sauvegarde pour confirmer l'intégrité des données
- Journalisation des résultats de vérification pour audit

##### Modes de sauvegarde avancés
Trois modes de sauvegarde sont désormais disponibles :
- **Complète** : Copie intégrale de tous les fichiers (comportement d'origine)
- **Différentielle** : Sauvegarde uniquement les fichiers modifiés depuis la dernière sauvegarde complète
- **Incrémentielle** : Ne sauvegarde que les fichiers modifiés depuis la dernière sauvegarde (complète ou incrémentielle)

##### Traitement parallèle
Pour améliorer les performances sur les systèmes multi-cœurs :
- Utilisation de jobs PowerShell pour paralléliser les sauvegardes de plusieurs sources
- Paramètre configurable pour limiter le nombre de processus parallèles
- Agrégation automatique des logs des processus parallèles

##### Métriques de performance
Le script capture et rapporte des métriques détaillées sur chaque opération :
- Temps d'exécution total et par dossier source
- Vitesse de transfert (Mo/s)
- Taux de compression
- Espace économisé par rapport à une sauvegarde complète (modes différentiel/incrémentiel)
- Exportation des métriques au format CSV pour analyse historique

##### Gestion sécurisée des identifiants
Protection renforcée pour les informations sensibles :
- Intégration avec le système de gestion des secrets Windows
- Support des identifiants chiffrés via SecureString
- Option pour stocker les paramètres SMTP dans le Gestionnaire d'informations d'identification de Windows

##### Gestion avancée des erreurs
Amélioration de la résilience du script :
- Système de reprise après échec pour les transferts interrompus
- Mécanisme de nouvelle tentative configurable (nombre d'essais, délai entre les tentatives)
- Classification des erreurs par gravité
- Rapport détaillé des erreurs dans les notifications

---

#### ⚙️ Configuration mise à jour

Voici les nouveaux paramètres disponibles dans `config.ps1` :

```powershell
# Paramètres originaux
$SourcePaths = @("C:\DossierA", "D:\DossierB")
$BackupDestination = "E:\Sauvegardes"
$LogFile = "E:\Logs\backup.log"
$MinFreeGB = 5
$RetentionDays = 15
$EnableCompression = $true
$EnableDryRun = $false
$EnableMail = $true
$MailFrom = "backup@domain.com"
$MailTo = "admin@domain.com"
$SmtpServer = "smtp.domain.com"
$Date = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

# Nouveaux paramètres
$BackupMode = "Complete"  # Options: "Complete", "Differential", "Incremental"
$EnableIntegrityCheck = $true
$ParallelProcessing = $true
$MaxParallelJobs = 4
$RetryCount = 3
$RetryDelay = 30  # secondes
$CollectMetrics = $true
$MetricsOutputPath = "E:\Logs\metrics.csv"
$UseSecureCredentials = $false  # Utiliser le gestionnaire de credentials Windows
$CredentialName = "BackupSMTP"  # Nom de l'identifiant stocké
```

---

#### 🛠️ Utilisation des nouvelles fonctionnalités

##### Vérification d'intégrité
```powershell
# Vérifier l'intégrité d'une sauvegarde spécifique
.\verify-backup.ps1 -BackupPath "E:\Sauvegardes\DossierA-2025-04-22_14-30-00"

# Vérifier toutes les sauvegardes des 7 derniers jours
.\verify-backup.ps1 -Days 7
```

##### Sauvegardes différentielles/incrémentielles
```powershell
# Définir dans config.ps1 ou en paramètre
.\backup-script.ps1 -BackupMode Differential
.\backup-script.ps1 -BackupMode Incremental
```

##### Utilisation des identifiants sécurisés
```powershell
# Enregistrer des identifiants (à faire une seule fois)
.\credential-manager.ps1 -StoreSMTP

# Utiliser les identifiants stockés
.\backup-script.ps1 -UseSecureCredentials
```

---

#### 📊 Rapports et métriques

Le script génère désormais des rapports détaillés accessibles via :

1. **Journal des métriques** : Fichier CSV avec l'historique des performances
2. **Tableau de bord HTML** : Visualisation des tendances de sauvegarde (généré par `.\generate-dashboard.ps1`)
3. **Rapport d'intégrité** : Résumé des vérifications d'intégrité avec statut par fichier
4. **Alertes intelligentes** : Notifications conditionnelles basées sur des seuils personnalisables

---

#### 🔄 Mise à jour et migration

Pour mettre à jour votre installation existante :

1. Sauvegardez votre fichier `config.ps1` actuel
2. Téléchargez la dernière version depuis le dépôt
3. Exécutez `.\update-config.ps1` pour fusionner vos paramètres existants avec les nouveaux paramètres
4. Vérifiez la configuration avec `.\validate-config.ps1`
