# ============================================
# Configuration du script de sauvegarde avancée
# ============================================

# =============================
# PARAMÈTRES ORIGINAUX
# =============================
# Dossiers source à sauvegarder (tableau)
$SourcePaths = @(
    "C:\Users\Public\Documents", 
    "C:\Projets"
)

# Destination des sauvegardes
$BackupDestination = "D:\Sauvegardes"

# Fichier de journalisation
$LogFile = "D:\Logs\backup.log"

# Espace disque minimum requis (en Go)
$MinFreeGB = 5

# Nombre de jours de conservation des sauvegardes
$RetentionDays = 15

# Activer la compression des sauvegardes
$EnableCompression = $true

# Mode simulation (aucune modification réelle)
$EnableDryRun = $false

# Activer les notifications par email
$EnableMail = $true

# Configuration email
$MailFrom = "backup@domain.com"
$MailTo = "admin@domain.com"
$SmtpServer = "smtp.domain.com"

# Format de date pour les noms de dossiers
$Date = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

# =============================
# NOUVEAUX PARAMÈTRES
# =============================
# Mode de sauvegarde (Complete, Differential, Incremental)
$BackupMode = "Complete"

# Activer la vérification d'intégrité des fichiers
$EnableIntegrityCheck = $true

# Activer le traitement parallèle des dossiers source
$ParallelProcessing = $true

# Nombre maximum de jobs parallèles
$MaxParallelJobs = 4

# Nombre de tentatives en cas d'échec
$RetryCount = 3

# Délai entre les tentatives (en secondes)
$RetryDelay = 30

# Collecter les métriques de performance
$CollectMetrics = $true

# Chemin pour l'export des métriques
$MetricsOutputPath = "D:\Logs\metrics.csv"

# Utiliser des identifiants sécurisés pour SMTP
$UseSecureCredentials = $false

# Nom de l'identifiant stocké dans le gestionnaire Windows
$CredentialName = "BackupSMTP"

# Fichier d'historique des sauvegardes
$BackupHistoryFile = "D:\Logs\backup_history.json"
