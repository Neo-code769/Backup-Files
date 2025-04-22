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
