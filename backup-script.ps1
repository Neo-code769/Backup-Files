# ============================================
# Script PowerShell de sauvegarde avancée
# Auteur : [TRUBLEREAU PIERRE]
# Date de création initiale : [22/04/2025]
# Date de dernière mise à jour : [22/04/2025]
# Version : 2.0
# Description : Script complet avec log, rotation, compression, vérifications, notifications, modularité,
# externalisation de la configuration, compatibilité planificateur de tâches, vérification d'intégrité,
# sauvegardes différentielles/incrémentielles, traitement parallèle, métriques de performance, et gestion avancée des erreurs.
# ============================================

#Requires -RunAsAdministrator
#Requires -Version 5.1

# =============================
# IMPORT DU FICHIER DE CONFIGURATION EXTERNE
# =============================
try {
    $configPath = "$PSScriptRoot\config.ps1"
    if (Test-Path $configPath) {
        . $configPath
        Write-Output "Configuration chargée depuis $configPath"
    } else {
        throw "Fichier de configuration non trouvé : $configPath"
    } # Closing brace added here
} catch {
    Write-Error "Erreur lors du chargement de la configuration : $_"
    Exit 1
} finally {
    Write-Output "Bloc Finally exécuté après le chargement de la configuration."

# =============================
# CONFIGURATION PAR DÉFAUT SI NON DÉFINIE DANS CONFIG.PS1
# =============================
if (-not $SourcePaths) {
    $SourcePaths = @("C:\Windows\Temp")
}
if (-not $BackupDestination) {
    $BackupDestination = "C:\Backup"
} 
if (-not $LogFile) {
    $LogFile = "$PSScriptRoot\backup.log"
}
if (-not $MinFreeGB) {
    $MinFreeGB = 5
}
if (-not $RetentionDays) {
    $RetentionDays = 15
}
if ($null -eq $EnableCompression) { $EnableCompression = $true }
$EnableDryRun = if ($null -eq $EnableDryRun) { $false } else { $EnableDryRun }
$EnableMail = if ($null -eq $EnableMail) { $false } else { $EnableMail }
$MailFrom = if ($null -eq $MailFrom) { "backup@domain.com" } else { $MailFrom }
$MailTo = if ($null -eq $MailTo) { "admin@domain.com" } else { $MailTo }
if (-not $SmtpServer) { $SmtpServer = "smtp.domain.com" }
$Date = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

# Nouveaux paramètres
if (-not $BackupMode) { $BackupMode = "Complete" } # Options: "Complete", "Differential", "Incremental"
$EnableIntegrityCheck = if ($null -eq $EnableIntegrityCheck) { $true } else { $EnableIntegrityCheck }
$ParallelProcessing = if ($null -eq $ParallelProcessing) { $false } else { $ParallelProcessing }
if (-not $MaxParallelJobs) { $MaxParallelJobs = 4 }
if ($null -eq $RetryCount) { $RetryCount = 3 }
if (-not $RetryDelay) { $RetryDelay = 30 }  # secondes
if ($null -eq $CollectMetrics) { $CollectMetrics = $true }
if (-not $MetricsOutputPath) { $MetricsOutputPath = "$PSScriptRoot\metrics.csv" }
$UseSecureCredentials = if ($null -eq $UseSecureCredentials) { $false } else { $UseSecureCredentials }
if (-not $CredentialName) { $CredentialName = "BackupSMTP" }
if (-not $BackupHistoryFile) {
    $BackupHistoryFile = "$PSScriptRoot\backup_history.json"
}

# =============================
# VARIABLES GLOBALES
# =============================
$script:TotalFilesCopied = 0
$script:TotalFilesSize = 0
$script:StartTime = Get-Date
$script:MetricsData = @()
$script:BackupSuccess = $true
$script:ErrorCount = 0
$script:LastFullBackupPath = $null

# =============================
# FONCTION DE LOG
# =============================
Function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Type = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    # Création du dossier de log si nécessaire
    $logDir = Split-Path -Path $LogFile -Parent
    if (!(Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Type] : $Message"
    
    # Couleur selon le type de message
    $color = switch ($Type) {
        "INFO"    { "White" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "DEBUG"   { "Cyan" }
        default   { "White" }
    }
    
    # Affichage dans la console sauf si NoConsole spécifié
    if (!$NoConsole) {
        Write-Host $logMessage -ForegroundColor $color
    }
    
    # Ajout au fichier de log
    try {
        Add-Content -Path $LogFile -Value $logMessage -ErrorAction Stop
    } catch {
        Write-Host "ERREUR: Impossible d'écrire dans le fichier log: $_" -ForegroundColor Red
    }
    
    # Incrémentation du compteur d'erreur si nécessaire
    if ($Type -eq "ERROR") {
        $script:ErrorCount++
    }
}

# =============================
# VÉRIFICATION DES DROITS ADMIN
# =============================
Function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Log "Ce script doit être exécuté en tant qu'administrateur." -Type "ERROR"
    Exit 1
}

# =============================
# VÉRIFICATION ESPACE DISQUE
# =============================
Function Test-FreeSpace {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter, 
        
        [Parameter(Mandatory=$true)]
        [int]$MinFreeGB
    )

    try {
        $drive = Get-PSDrive $DriveLetter -ErrorAction Stop
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        
        if ($drive.Free -lt ($MinFreeGB * 1GB)) {
            Write-Log "Espace disque insuffisant sur $DriveLetter. $freeSpaceGB Go disponibles (minimum requis: $MinFreeGB Go)." -Type "ERROR"
            return $false
        } else {
            Write-Log "Espace disque disponible : $freeSpaceGB Go sur $DriveLetter (minimum requis: $MinFreeGB Go)" -Type "INFO"
            return $true
        }
    } catch {
        Write-Log "Erreur lors de la vérification de l'espace disque sur $DriveLetter : $_" -Type "ERROR"
        return $false
    }
}

# =============================
# CALCUL HASH (CHECKSUM) POUR VÉRIFICATION D'INTÉGRITÉ
# =============================
Function Get-FileHash256 {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        Write-Log "Impossible de calculer le hash pour '$FilePath': $_" -Type "ERROR" -NoConsole
        return $null
    }
}

# =============================
# CRÉER UN MANIFESTE D'INTÉGRITÉ
# =============================
Function New-IntegrityManifest {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )
    
    if (!$EnableIntegrityCheck) {
        return
    }
    
    Write-Log "Création du manifeste d'intégrité pour $BackupPath..." -Type "INFO"
    
    $manifestPath = Join-Path -Path $BackupPath -ChildPath "integrity_manifest.json"
    $manifest = @{}
    $totalFiles = 0
    $processedFiles = 0
    
    # Compter le nombre total de fichiers pour afficher la progression
    $totalFiles = (Get-ChildItem -Path $BackupPath -Recurse -File | Measure-Object).Count
    
    Get-ChildItem -Path $BackupPath -Recurse -File | ForEach-Object {
        # Ignorer le manifeste lui-même
        if ($_.FullName -ne $manifestPath) {
            $relativePath = $_.FullName.Substring($BackupPath.Length + 1)
            $hash = Get-FileHash256 -FilePath $_.FullName
            
            if ($null -ne $hash) {
                $manifest[$relativePath] = @{
                    "Hash" = $hash
                    "Size" = $_.Length
                    "LastWriteTime" = $_.LastWriteTime.ToString("o")
                }
            }
            
            $processedFiles++
            
            # Afficher la progression tous les 100 fichiers
            if ($processedFiles % 100 -eq 0 -or $processedFiles -eq $totalFiles) {
                $percentComplete = [math]::Round(($processedFiles / $totalFiles) * 100, 1)
                Write-Log "Calcul d'intégrité: $processedFiles/$totalFiles fichiers ($percentComplete%)" -Type "INFO" -NoConsole
            }
        }
    }
    
    $manifestObj = @{
        "CreationDate" = (Get-Date).ToString("o")
        "BackupPath" = $BackupPath
        "BackupMode" = $BackupMode
        "Files" = $manifest
    }
    
    $manifestObj | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Force
    Write-Log "Manifeste d'intégrité créé avec succès: $manifestPath ($totalFiles fichiers)" -Type "SUCCESS"
}

# =============================
# VÉRIFIER L'INTÉGRITÉ D'UNE SAUVEGARDE
# =============================
Function Test-BackupIntegrity {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )
    
    if (!$EnableIntegrityCheck) {
        return $true
    }
    
    Write-Log "Vérification de l'intégrité de la sauvegarde: $BackupPath" -Type "INFO"
    
    $manifestPath = Join-Path -Path $BackupPath -ChildPath "integrity_manifest.json"
    
    if (!(Test-Path $manifestPath)) {
        Write-Log "Manifeste d'intégrité non trouvé: $manifestPath" -Type "ERROR"
        return $false
    }
    
    try {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
        $files = $manifest.Files.PSObject.Properties
        $totalFiles = $files.Count
        $processedFiles = 0
        $failedFiles = 0
        
        foreach ($file in $files) {
            $relativePath = $file.Name
            $expectedHash = $file.Value.Hash
            $fullPath = Join-Path -Path $BackupPath -ChildPath $relativePath
            
            if (Test-Path $fullPath) {
                $currentHash = Get-FileHash256 -FilePath $fullPath
                
                if ($currentHash -ne $expectedHash) {
                    Write-Log "Échec de vérification d'intégrité: $relativePath" -Type "ERROR" -NoConsole
                    $failedFiles++
                }
            } else {
                Write-Log "Fichier manquant: $relativePath" -Type "ERROR" -NoConsole
                $failedFiles++
            }
            
            $processedFiles++
            
            # Afficher la progression tous les 100 fichiers
            if ($processedFiles % 100 -eq 0 -or $processedFiles -eq $totalFiles) {
                $percentComplete = [math]::Round(($processedFiles / $totalFiles) * 100, 1)
                Write-Log "Vérification d'intégrité: $processedFiles/$totalFiles fichiers ($percentComplete%)" -Type "INFO" -NoConsole
            }
        }
        
        if ($failedFiles -gt 0) {
            Write-Log "Échec de la vérification d'intégrité: $failedFiles/$totalFiles fichiers corrompus ou manquants" -Type "ERROR"
            return $false
        } else {
            Write-Log "Vérification d'intégrité réussie: $totalFiles fichiers vérifiés" -Type "SUCCESS"
            return $true
        }
    } catch {
        Write-Log "Erreur lors de la vérification d'intégrité: $_" -Type "ERROR"
        return $false
    }
}

# =============================
# RÉCUPÉRATION DE L'HISTORIQUE DES SAUVEGARDES
# =============================
Function Get-BackupHistory {
    if (Test-Path $BackupHistoryFile) {
        try {
            $history = Get-Content -Path $BackupHistoryFile -Raw | ConvertFrom-Json
            return $history
        } catch {
            Write-Log "Erreur lors de la lecture de l'historique des sauvegardes: $_" -Type "WARNING"
            return @{
                "LastFullBackup" = $null
                "LastIncrementalBackup" = $null
                "BackupSets" = @()
            }
        }
    } else {
        return @{
            "LastFullBackup" = $null
            "LastIncrementalBackup" = $null
            "BackupSets" = @()
        }
    }
}

# =============================
# MISE À JOUR DE L'HISTORIQUE DES SAUVEGARDES
# =============================
Function Update-BackupHistory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Complete", "Differential", "Incremental")]
        [string]$BackupType,
        
        [Parameter(Mandatory=$false)]
        [datetime]$BackupDate = (Get-Date)
    )
    
    try {
        $history = Get-BackupHistory
        
        # Créer un nouvel enregistrement pour cette sauvegarde
        $newBackup = @{
            "Path" = $BackupPath
            "Type" = $BackupType
            "Date" = $BackupDate.ToString("o")
            "SourcePaths" = $SourcePaths
        }
        
        # Mettre à jour le dernier type de sauvegarde
        if ($BackupType -eq "Complete") {
            $history.LastFullBackup = $newBackup
        } elseif ($BackupType -eq "Incremental") {
            $history.LastIncrementalBackup = $newBackup
        }
        
        # Ajouter à l'historique des sauvegardes
        if ($null -eq $history.BackupSets) {
            $history.BackupSets = @()
        }
        
        $history.BackupSets += $newBackup
        
        # Écrire l'historique mis à jour
        $history | ConvertTo-Json -Depth 10 | Set-Content -Path $BackupHistoryFile -Force
        Write-Log "Historique des sauvegardes mis à jour" -Type "INFO" -NoConsole
    } catch {
        Write-Log "Erreur lors de la mise à jour de l'historique des sauvegardes: $_" -Type "ERROR"
    }
}

# =============================
# DÉTERMINE SI UN FICHIER DOIT ÊTRE SAUVEGARDÉ SELON LE MODE DE SAUVEGARDE
# =============================
Function Test-BackupFile {
    param(
        [Parameter(Mandatory=$true)]
        [System.IO.FileInfo]$File,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Complete", "Differential", "Incremental")]
        [string]$Mode,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ReferenceData
    )
    
    # En mode complet, on sauvegarde toujours
    if ($Mode -eq "Complete") {
        return $true
    }
    
    # Si pas de référence, on sauvegarde par précaution
    if ($null -eq $ReferenceData) {
        return $true
    }
    
    # En mode différentiel ou incrémentiel, on vérifie par rapport à la dernière sauvegarde complète
    if ($Mode -eq "Differential") {
        $lastFullBackup = $ReferenceData.LastFullBackupDate
        if ($null -eq $lastFullBackup) {
            return $true  # Si pas de sauvegarde complète, on sauvegarde
        }
        
        return $File.LastWriteTime -gt $lastFullBackup
    }
    
    # En mode incrémentiel, on vérifie par rapport à la dernière sauvegarde (complète ou incrémentielle)
    if ($Mode -eq "Incremental") {
        $lastBackupDate = $ReferenceData.LastBackupDate
        if ($null -eq $lastBackupDate) {
            return $true  # Si pas de sauvegarde antérieure, on sauvegarde
        }
        
        return $File.LastWriteTime -gt $lastBackupDate
    }
    
    # Par défaut, on sauvegarde
    return $true
}

# =============================
# PRÉPARE LES DONNÉES DE RÉFÉRENCE POUR LES SAUVEGARDES DIFF/INCR
# =============================
Function Get-ReferenceData {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Complete", "Differential", "Incremental")]
        [string]$BackupMode
    )
    
    if ($BackupMode -eq "Complete") {
        return $null
    }
    
    $history = Get-BackupHistory
    $referenceData = @{}
    
    if ($BackupMode -eq "Differential") {
        if ($null -ne $history.LastFullBackup) {
            $referenceData.LastFullBackupDate = [datetime]::Parse($history.LastFullBackup.Date)
            $referenceData.LastFullBackupPath = $history.LastFullBackup.Path
            Write-Log "Mode différentiel: référence à la sauvegarde complète du $($referenceData.LastFullBackupDate)" -Type "INFO"
        } else {
            Write-Log "Aucune sauvegarde complète trouvée. Une sauvegarde complète sera effectuée." -Type "WARNING"
            return $null
        }
    } elseif ($BackupMode -eq "Incremental") {
        if ($null -ne $history.LastIncrementalBackup) {
            $referenceData.LastBackupDate = [datetime]::Parse($history.LastIncrementalBackup.Date)
            $referenceData.LastBackupPath = $history.LastIncrementalBackup.Path
            Write-Log "Mode incrémentiel: référence à la sauvegarde du $($referenceData.LastBackupDate)" -Type "INFO"
        } elseif ($null -ne $history.LastFullBackup) {
            $referenceData.LastBackupDate = [datetime]::Parse($history.LastFullBackup.Date)
            $referenceData.LastBackupPath = $history.LastFullBackup.Path
            Write-Log "Mode incrémentiel: première sauvegarde incrémentielle après la sauvegarde complète du $($referenceData.LastBackupDate)" -Type "INFO"
        } else {
            Write-Log "Aucune sauvegarde antérieure trouvée. Une sauvegarde complète sera effectuée." -Type "WARNING"
            return $null
        }
    }
    
    return $referenceData
}

# =============================
# ROTATION DES SAUVEGARDES
# =============================
Function Remove-OldBackups {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupDir,
        
        [Parameter(Mandatory=$true)]
        [int]$RetentionDays
    )
    
    Write-Log "Recherche des sauvegardes obsolètes (plus de $RetentionDays jours)..." -Type "INFO"
    
    try {
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $oldBackups = Get-ChildItem -Path $BackupDir -Directory | 
            Where-Object { $_.LastWriteTime -lt $cutoffDate }
        
        if ($oldBackups.Count -eq 0) {
            Write-Log "Aucune sauvegarde obsolète à supprimer" -Type "INFO"
            return
        }
        
        Write-Log "Suppression de $($oldBackups.Count) sauvegarde(s) obsolète(s)" -Type "INFO"
        
        foreach ($item in $oldBackups) {
            try {
                Remove-Item -Path $item.FullName -Recurse -Force
                Write-Log "Ancienne sauvegarde supprimée : $($item.FullName)" -Type "SUCCESS"
            } catch {
                Write-Log "Erreur lors de la suppression de $($item.FullName) : $_" -Type "ERROR"
            }
        }
    } catch {
        Write-Log "Erreur lors de la rotation des sauvegardes : $_" -Type "ERROR"
    }
}

# =============================
# COMPRESSION DES DOSSIERS
# =============================
Function Compress-Backup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Source,
        
        [Parameter(Mandatory=$true)]
        [string]$Destination
    )
    
    if (!$EnableCompression) {
        return
    }
    
    $zipPath = "$Destination.zip"
    Write-Log "Compression de $Source vers $zipPath..." -Type "INFO"
    
    try {
        $startCompress = Get-Date
        
        # Récupération de la taille avant compression
        $originalSize = (Get-ChildItem -Path $Source -Recurse | Measure-Object -Property Length -Sum).Sum
        
        # Compression
        Compress-Archive -Path "$Source\*" -DestinationPath $zipPath -Force
        
        # Vérification du fichier ZIP
        if (Test-Path $zipPath) {
            $compressedSize = (Get-Item $zipPath).Length
            $compressionRatio = if ($originalSize -gt 0) { 
                [math]::Round(100 - (($compressedSize / $originalSize) * 100), 2) 
            } else { 
                0 
            }
            
            $durationSec = (Get-Date).Subtract($startCompress).TotalSeconds
            
            Write-Log "Fichier compressé : $zipPath ($compressionRatio% d'économie d'espace)" -Type "SUCCESS"
            Write-Log "Taille originale: $([math]::Round($originalSize / 1MB, 2)) MB, Taille compressée: $([math]::Round($compressedSize / 1MB, 2)) MB" -Type "INFO" -NoConsole
            
            # Suppression de la source après compression réussie
            Remove-Item -Path $Source -Recurse -Force
            Write-Log "Dossier source supprimé après compression : $Source" -Type "INFO" -NoConsole
            
            # Ajout des métriques de compression
            if ($CollectMetrics) {
                $script:MetricsData += [PSCustomObject]@{
                    DateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Operation = "Compression"
                    Source = $Source
                    Destination = $zipPath
                    OriginalSizeMB = [math]::Round($originalSize / 1MB, 2)
                    CompressedSizeMB = [math]::Round($compressedSize / 1MB, 2)
                    CompressionRatio = $compressionRatio
                    DurationSeconds = [math]::Round($durationSec, 2)
                }
            }
            
            return $true
        } else {
            Write-Log "Échec de compression : le fichier ZIP n'existe pas" -Type "ERROR"
            return $false
        }
    } catch {
        Write-Log "Erreur lors de la compression de $Source : $_" -Type "ERROR"
        return $false
    }
}

# =============================
# NOTIFICATION EMAIL
# =============================
Function Send-Notification {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        
        [Parameter(Mandatory=$true)]
        [string]$Body,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential = $null,
        
        [Parameter(Mandatory=$false)]
        [switch]$IsHTML = $false
    )
    
    if (!$EnableMail) {
        return
    }
    
    try {
        $params = @{
            From = $MailFrom
            To = $MailTo
            Subject = $Subject
            Body = $Body
            SmtpServer = $SmtpServer
        }
        
        # Ajout des paramètres conditionnels
        if ($IsHTML) {
            $params.Add("BodyAsHtml", $true)
        }
        
        # Utilisation des credentials sécurisés si activé
        if ($UseSecureCredentials) {
            # Récupération des credentials depuis le gestionnaire Windows
            if ($null -eq $Credential) {
                Write-Log "Aucun credential fourni pour l'envoi de mail" -Type "WARNING"
                return
            }
            
            if ($null -ne $Credential) {
                $params.Add("Credential", $Credential)
            } else {
                Write-Log "Aucun credential trouvé pour l'envoi de mail" -Type "WARNING"
            }
        }
        
        Send-MailMessage @params
        Write-Log "Notification envoyée à $MailTo : $Subject" -Type "SUCCESS"
        return $true
    } catch {
        Write-Log "Erreur lors de l'envoi de la notification : $_" -Type "ERROR"
        return $false
    }
}

# =============================
# RÉCUPÉRATION DES CREDENTIALS SÉCURISÉS
# =============================
Function Get-StoredCredential {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        # Utilisation du module CredentialManager s'il est disponible
        if (Get-Module -ListAvailable -Name "CredentialManager") {
            Import-Module CredentialManager
            return Get-StoredCredential -Target $CredentialName
        } else {
            # Utilisation de l'API Windows directement
            $credential = cmdkey /list:$CredentialName
            if ($credential -like "*Target:*$CredentialName*") {
                $username = ($credential | Select-String "User:").Line.Split(":")[1].Trim()
                $securePassword = Read-Host "Entrez le mot de passe pour $username" -AsSecureString
                return New-Object System.Management.Automation.PSCredential($username, $securePassword)
            } else {
                Write-Log "Credential '$CredentialName' non trouvé dans le gestionnaire d'identifiants Windows" -Type "WARNING"
                return $null
            }
        }
    } catch {
        Write-Log "Erreur lors de la récupération des credentials : $_" -Type "ERROR"
        return $null
    }
}

# =============================
# COLLECTE DES MÉTRIQUES DE PERFORMANCE
# =============================
Function Add-PerformanceMetric {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Operation,
        
        [Parameter(Mandatory=$true)]
        [string]$Source,
        
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        
        [Parameter(Mandatory=$true)]
        [long]$SizeCopiedBytes,
        
        [Parameter(Mandatory=$true)]
        [int]$FilesCopied,
        
        [Parameter(Mandatory=$true)]
        [double]$DurationSeconds
    )
    
    if (!$CollectMetrics) {
        return
    }
    
    $transferSpeedMBps = if ($DurationSeconds -gt 0) { 
        [math]::Round(($SizeCopiedBytes / 1MB) / $DurationSeconds, 2) 
    } else { 
        0 
    }
    
    $script:MetricsData += [PSCustomObject]@{
        DateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Operation = $Operation
        Source = $Source
        Destination = $Destination
        SizeMB = [math]::Round($SizeCopiedBytes / 1MB, 2)
        FileCount = $FilesCopied
        DurationSeconds = [math]::Round($DurationSeconds, 2)
        SpeedMBps = $transferSpeedMBps
        BackupMode = $BackupMode
    }
}

# =============================
# EXPORT DES MÉTRIQUES DE PERFORMANCE
# =============================
Function Export-Metrics {
    if (!$CollectMetrics -or $script:MetricsData.Count -eq 0) {
        return
    }
    
    try {
        # Création du dossier parent si nécessaire
        $metricsDir = Split-Path -Path $MetricsOutputPath -Parent
        if (!(Test-Path $metricsDir)) {
            New-Item -Path $metricsDir -ItemType Directory -Force | Out-Null
        }
        
        # Si le fichier existe déjà, on ajoute les nouvelles données
        if (Test-Path $MetricsOutputPath) {
            $existingMetrics = Import-Csv -Path $MetricsOutputPath
            $allMetrics = $existingMetrics + $script:MetricsData
            $allMetrics | Export-Csv -Path $MetricsOutputPath -NoTypeInformation -Force
        } else {
            $script:MetricsData | Export-Csv -Path $MetricsOutputPath -NoTypeInformation -Force
        }
        
        Write-Log "Métriques de performance exportées vers $MetricsOutputPath" -Type "SUCCESS"
    } catch {
        Write-Log "Erreur lors de l'export des métriques : $_" -Type "ERROR"
    }
}

# =============================
# FORMATAGE DU RAPPORT DE SAUVEGARDE
# =============================
Function Format-BackupReport {
    param(
        [Parameter(Mandatory=$true)]
        [DateTime]$StartTime,
        
        [Parameter(Mandatory=$true)]
        [DateTime]$EndTime,
        
        [Parameter(Mandatory=$true)]
        [string]$BackupMode,
        
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory=$true)]
        [int]$FilesCopied,
        
        [Parameter(Mandatory=$true)]
        [long]$SizeCopiedBytes,
        
        [Parameter(Mandatory=$true)]
        [bool]$Success,
        
        [Parameter(Mandatory=$false)]
        [int]$ErrorCount = 0
    )
    
    $duration = $EndTime - $StartTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration
    $sizeMB = [math]::Round($SizeCopiedBytes / 1MB, 2)
    $speedMBps = if ($duration.TotalSeconds -gt 0) { 
        [math]::Round($sizeMB / $duration.TotalSeconds, 2) 
    } else { 
        0 
    }
    
    # Préparation du corps HTML pour l'email
    $htmlBody = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .header { background-color: #4472C4; color: white; padding: 10px; }
        .success { background-color: #C6E0B4; }
        .error { background-color: #F8CBAD; }
        .summary { background-color: #E2EFD9; padding: 10px; margin-top: 10px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Rapport de Sauvegarde</h2>
    </div>
    <div class="summary $(if($Success){'success'}else{'error'})">
        <h3>État: $(if($Success){'Réussite'}else{'Échec'})</h3>
        <p>Mode de sauvegarde: $BackupMode</p>
        <p>Démarré le: $($StartTime.ToString("yyyy-MM-dd HH:mm:ss"))</p>
        <p>Terminé le: $($EndTime.ToString("yyyy-MM-dd HH:mm:ss"))</p>
        <p>Durée: $durationFormatted</p>
    </div>
    <table>
        <tr><th>Métrique</th><th>Valeur</th></tr>
        <tr><td>Fichiers sauvegardés</td><td>$FilesCopied</td></tr>
        <tr><td>Taille totale</td><td>$sizeMB MB</td></tr>
        <tr><td>Vitesse moyenne</td><td>$speedMBps MB/s</td></tr>
        <tr><td>Dossier de sauvegarde</td><td>$BackupPath</td></tr>
        <tr><td>Erreurs rencontrées</td><td>$ErrorCount</td></tr>
    </table>
</body>
</html>
"@
    
    # Préparation du corps texte pour l'email ou l'affichage console
    $textBody = @"
=== Rapport de Sauvegarde ===
État: $(if($Success){'Réussite'}else{'Échec'})
Mode: $BackupMode
Démarré le: $($StartTime.ToString("yyyy-MM-dd HH:mm:ss"))
Terminé le: $($EndTime.ToString("yyyy-MM-dd HH:mm:ss"))
Durée: $durationFormatted
Fichiers sauvegardés: $FilesCopied
Taille totale: $sizeMB MB
Vitesse moyenne: $speedMBps MB/s
Dossier de sauvegarde: $BackupPath
Erreurs rencontrées: $ErrorCount
"@
    
    return @{
        HTML = $htmlBody
        Text = $textBody
    }
}

# =============================
# SAUVEGARDE D'UN DOSSIER AVEC GESTION DES ERREURS ET TENTATIVES
# =============================
Function Backup-FolderWithRetry {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Source,
        
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ReferenceData = $null,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = $RetryCount,
        
        [Parameter(Mandatory=$false)]
        [int]$RetryDelaySeconds = $RetryDelay
    )
    
    $folderName = Split-Path -Path $Source -Leaf
    $backupPath = Join-Path -Path $Destination -ChildPath "$folderName-$Date"
    
    Write-Log "Préparation à la sauvegarde de '$Source' vers '$backupPath' (Mode: $BackupMode)" -Type "INFO"
    
    if ($EnableDryRun) {
        Write-Log "[Dry-Run] Simulation : '$Source' -> '$backupPath'" -Type "INFO"
        return @{
            Success = $true
            FilesCopied = 0
            SizeCopied = 0
            BackupPath = $backupPath
        }
    }
    
    # Création du dossier de destination s'il n'existe pas
    if (!(Test-Path $backupPath)) {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
    }
    
    $filesCopied = 0
    $sizeCopied = 0
    $retry = 0
    $success = $false
    $errorFiles = @()
    
    do {
        try {
            if ($retry -gt 0) {
                Write-Log "Tentative $retry/$MaxRetries pour '$Source'..." -Type "WARNING"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
            
            # Préparation d'un journal des fichiers pour ce dossier
            $fileLog = @()
        } catch {
            Write-Log "Erreur lors de la tentative de sauvegarde : $_" -Type "ERROR"
        } finally {
            Write-Log "Bloc Finally exécuté après la tentative de sauvegarde." -Type "INFO"
        }
    } while ($retry -le $MaxRetries -and !$success) # Closing the do-while block

    # Obtention des fichiers sources (récursivement)
    $sourceFiles = Get-ChildItem -Path $Source -Recurse -File
    $totalFiles = $sourceFiles.Count
    $currentFile = 0

    do {
        # Add your logic here for what should happen during each retry
        Write-Log "Tentative $retry/$MaxRetries pour '$Source'..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    } # Closing brace for the do block
    while ($retry -le $MaxRetries)

    Write-Log "Analyse de $totalFiles fichiers dans '$Source'..." -Type "INFO"
            
            foreach ($file in $sourceFiles) {
                $currentFile++
                
                # Déterminer si ce fichier doit être sauvegardé selon le mode
                $shouldBackup = Test-BackupFile -File $file -Mode $BackupMode -ReferenceData $ReferenceData
                
                # Si ce n'est pas necessaire de sauvegarder ce fichier, on passe au suivant
                if (!$shouldBackup) {
                    continue
                }
                
                # Calculer le chemin relatif et le chemin de destination
                $relativePath = $file.FullName.Substring($Source.Length + 1)
                $destFilePath = Join-Path -Path $backupPath -ChildPath $relativePath
                $destDir = Split-Path -Path $destFilePath -Parent
                
                # Créer le dossier de destination s'il n'existe pas
                if (!(Test-Path $destDir)) {
                    New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                }
                
                # Copier le fichier
                Copy-Item -Path $file.FullName -Destination $destFilePath -Force
                
                # Vérifier si la copie a réussi
                if (Test-Path $destFilePath) {
                    $filesCopied++
                    $sizeCopied += $file.Length
                } else {
                    $errorFiles += $file.FullName
                }
                
                # Afficher la progression tous les 100 fichiers ou à la fin
                if ($currentFile % 100 -eq 0 -or $currentFile -eq $totalFiles) {
                    $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100, 1)
                    Write-Log "Progression: $currentFile/$totalFiles fichiers ($percentComplete%)" -Type "INFO" -NoConsole
                }
            }
            
            # Si pas d'erreurs, marquer comme succès
            if ($errorFiles.Count -eq 0) {
                $success = $true
            } else {
                Write-Log "$($errorFiles.Count) fichiers n'ont pas pu être copiés" -Type "ERROR"
            }
        } catch {
            Write-Log "Erreur lors de la sauvegarde de '$Source' : $_" -Type "ERROR"
        }
        
        $retry++
    {
        Write-Log "Tentative $retry/$MaxRetries pour '$Source'..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    {
        # Add your logic here for what should happen during each retry
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    {
        # Add your logic here for what should happen during each retry
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    {
        # Add your logic here for what should happen during each retry
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    } # Closing the do block
    while ($retry -le $MaxRetries -and !$success) {
        Write-Log "Tentative $retry/$MaxRetries pour '$Source'..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    }
        # Placeholder for loop body
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
    }
        # Placeholder for loop body
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
    }
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
    }
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
    }
        # Add your logic here for what should happen during each retry
        Write-Log "Tentative $retry/$MaxRetries pour '$Source'..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    # Collecte des métriques
    Add-PerformanceMetric -Operation "Backup-$BackupMode" -Source $Source -Destination $backupPath `
        -SizeCopiedBytes $sizeCopied -FilesCopied $filesCopied -DurationSeconds $duration.TotalSeconds
    
    # Log de synthèse
    if ($success) {
        Write-Log "Sauvegarde réussie de '$Source' vers '$backupPath' ($filesCopied fichiers, $([math]::Round($sizeCopied / 1MB, 2)) MB)" -Type "SUCCESS"
    } else {
        Write-Log "Échec de la sauvegarde complète de '$Source' après $MaxRetries tentatives" -Type "ERROR"
    }
    
    return @{
        Success = $success
        FilesCopied = $filesCopied
        SizeCopied = $sizeCopied
        BackupPath = $backupPath
        Errors = $errorFiles.Count
    }


# =============================
# SAUVEGARDE D'UN DOSSIER
# =============================
Function Backup-Folder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Source,
        
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ReferenceData = $null
    )
    
    try {
        # Vérification de l'existence du dossier source
        if (!(Test-Path $Source)) {
            Write-Log "Le dossier source '$Source' n'existe pas." -Type "ERROR"
            return $false
        }
        
        # Effectuer la sauvegarde avec gestion des erreurs et tentatives
        $result = Backup-FolderWithRetry -Source $Source -Destination $Destination -ReferenceData $ReferenceData
        
        # Si la sauvegarde a réussi et que la compression est activée
        if ($result.Success -and $EnableCompression) {
            Compress-Backup -Source $result.BackupPath -Destination $result.BackupPath
        }
        
        # Vérification d'intégrité si activée et si la sauvegarde a réussi
        if ($result.Success -and $EnableIntegrityCheck) {
            $targetPath = if ($EnableCompression) { "$($result.BackupPath).zip" } else { $result.BackupPath }
            
            if (Test-Path $targetPath) {
                if (-not $EnableCompression) {
                    New-IntegrityManifest -BackupPath $targetPath
                    $integrityCheck = Verify-BackupIntegrity -BackupPath $targetPath
                    
                    if (-not $integrityCheck) {
                        Write-Log "La vérification d'intégrité a échoué pour '$targetPath'" -Type "ERROR"
                        $result.Success = $false
                    }
                }
            } else {
                Write-Log "Le chemin cible n'existe pas pour la vérification d'intégrité: '$targetPath'" -Type "ERROR"
                $result.Success = $false
            }
        }
        
        # Mise à jour des compteurs globaux
        $script:TotalFilesCopied += $result.FilesCopied
        $script:TotalFilesSize += $result.SizeCopied
        
        return $result.Success
    } catch {
        Write-Log "Erreur catastrophique lors de la sauvegarde de '$Source' : $_" -Type "ERROR"
        return $false
    }
}

# =============================
# TRAITEMENT PARALLÈLE DE SAUVEGARDES
# =============================
Function Backup-FoldersInParallel {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$SourcePaths,
        
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ReferenceData = $null
    )
    
    # Si le traitement parallèle n'est pas activé ou s'il n'y a qu'un seul dossier, utiliser l'approche séquentielle
    if (!$ParallelProcessing -or $SourcePaths.Count -le 1) {
        $results = @{}
        foreach ($src in $SourcePaths) {
            $results[$src] = Backup-Folder -Source $src -Destination $Destination -ReferenceData $ReferenceData
        }
        return $results
    }
    
    # Préparation du traitement parallèle
    Write-Log "Démarrage des sauvegardes en parallèle (max $MaxParallelJobs jobs)" -Type "INFO"
    
    # Limitation du nombre de jobs en parallèle
    $maxConcurrentJobs = [Math]::Min($MaxParallelJobs, $SourcePaths.Count)
    $throttleLimit = $maxConcurrentJobs
    
    # Stockage des résultats
    $results = @{}
    $jobs = @()
    
    try {
        # Création d'un script block réutilisable pour les jobs
        $scriptBlock = {
            param($Source, $Destination, $ConfigPath, $BackupMode, $EnableCompression, $EnableIntegrityCheck)
            
            # Charger la configuration pour ce job
            . $ConfigPath
            
            # Simuler les fonctions nécessaires pour le job
            function Backup-FolderInJob {
                param($Src, $Dest, $BkpMode)
                
                # Cette fonction est une version simplifiée pour le job
                $folderName = Split-Path -Path $Src -Leaf
                $backupPath = Join-Path -Path $Dest -ChildPath "$folderName-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
                
                # Création du dossier de destination
                if (!(Test-Path $backupPath)) {
                    New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
                }
                
                # Copie des fichiers
                $sourceFiles = Get-ChildItem -Path $Src -Recurse -File
                $filesCopied = 0
                $sizeCopied = 0
                
                foreach ($file in $sourceFiles) {
                    $relativePath = $file.FullName.Substring($Src.Length + 1)
                    $destFilePath = Join-Path -Path $backupPath -ChildPath $relativePath
                    $destDir = Split-Path -Path $destFilePath -Parent
                    
                    if (!(Test-Path $destDir)) {
                        New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                    }
                    
                    Copy-Item -Path $file.FullName -Destination $destFilePath -Force
                    
                    if (Test-Path $destFilePath) {
                        $filesCopied++
                        $sizeCopied += $file.Length
                    }
                }
                
                # Compression si nécessaire
                if ($EnableCompression) {
                    $zipPath = "$backupPath.zip"
                    Compress-Archive -Path "$backupPath\*" -DestinationPath $zipPath -Force
                    if (Test-Path $zipPath) {
                        Remove-Item -Path $backupPath -Recurse -Force
                    }
                }
                
                return @{
                    Source = $Src
                    Success = $true
                    FilesCopied = $filesCopied
                    SizeCopied = $sizeCopied
                    BackupPath = $backupPath
                }
            }
            
            # Exécution de la sauvegarde
            return Backup-FolderInJob -Src $Source -Dest $Destination -BkpMode $BackupMode
        }
        
        # Démarrage des jobs
        foreach ($src in $SourcePaths) {
            $jobParams = @{
                ScriptBlock = $scriptBlock
                ArgumentList = $src, $Destination, $configPath, $BackupMode, $EnableCompression, $EnableIntegrityCheck
            }
            
            $job = Start-Job @jobParams
            $jobs += $job
            
            Write-Log "Job démarré pour la sauvegarde de '$src'" -Type "INFO"
            
            # Limitation du nombre de jobs
            if ($jobs.Count -ge $throttleLimit) {
                $completedJob = $jobs | Wait-Job -Any
                $jobResult = Receive-Job -Job $completedJob
                $results[$jobResult.Source] = $jobResult.Success
                
                Write-Log "Sauvegarde parallèle terminée pour '$($jobResult.Source)' ($($jobResult.FilesCopied) fichiers)" -Type "SUCCESS"
                
                $script:TotalFilesCopied += $jobResult.FilesCopied
                $script:TotalFilesSize += $jobResult.SizeCopied
                
                Remove-Job -Job $completedJob
                $jobs = $jobs | Where-Object { $_ -ne $completedJob }
            }
        }
        
        # Attendre les jobs restants
        while ($jobs.Count -gt 0) {
            $completedJob = $jobs | Wait-Job -Any
            $jobResult = Receive-Job -Job $completedJob
            $results[$jobResult.Source] = $jobResult.Success
            
            Write-Log "Sauvegarde parallèle terminée pour '$($jobResult.Source)' ($($jobResult.FilesCopied) fichiers)" -Type "SUCCESS"
            
            $script:TotalFilesCopied += $jobResult.FilesCopied
            $script:TotalFilesSize += $jobResult.SizeCopied
            
            Remove-Job -Job $completedJob
            $jobs = $jobs | Where-Object { $_ -ne $completedJob }
        }
        
        Write-Log "Toutes les sauvegardes parallèles sont terminées" -Type "SUCCESS"
        return $results
    } catch {
        Write-Log "Erreur lors du traitement parallèle : $_" -Type "ERROR"
        
        # Nettoyage des jobs en cas d'erreur
        foreach ($job in $jobs) {
            if ($job.State -ne "Completed") {
                Stop-Job -Job $job
            }
            Remove-Job -Job $job -Force
        }
        
        return @{}
    }
}

# =============================
# EXÉCUTION PRINCIPALE
# =============================
Function Start-Backup {
    # Initialisation
    $script:StartTime = Get-Date
    $script:TotalFilesCopied = 0
    $script:TotalFilesSize = 0
    $script:BackupSuccess = $true
    $script:ErrorCount = 0
    
    try {
        # Entête du log
        Write-Log "=======================================================" -Type "INFO"
        Write-Log "=== Début du script de sauvegarde (Mode: $BackupMode) ===" -Type "INFO"
        Write-Log "=======================================================" -Type "INFO"
        Write-Log "Date et heure : $($script:StartTime.ToString("yyyy-MM-dd HH:mm:ss"))" -Type "INFO"
        Write-Log "Version du script : 2.0" -Type "INFO"
        
        # Vérification préalable de l'espace disque
        $driveLetter = ($BackupDestination -split ':')[0]
        $diskSpaceOk = Test-FreeSpace -DriveLetter $driveLetter -MinFreeGB $MinFreeGB
        
        if (!$diskSpaceOk) {
            throw "Espace disque insuffisant sur le disque de destination"
        }
        
        # Création du dossier de destination s'il n'existe pas
        if (!(Test-Path $BackupDestination)) {
            Write-Log "Création du dossier de destination : $BackupDestination" -Type "INFO"
            New-Item -Path $BackupDestination -ItemType Directory -Force | Out-Null
        }
        
        # Préparation des données de référence pour sauvegardes diff/incr
        $referenceData = Get-ReferenceData -BackupMode $BackupMode
        
        # Si en mode différentiel ou incrémentiel mais sans référence, basculer en mode complet
        if (($BackupMode -eq "Differential" -or $BackupMode -eq "Incremental") -and $null -eq $referenceData) {
            Write-Log "Pas de sauvegarde de référence trouvée pour le mode $BackupMode, basculement en mode Complete" -Type "WARNING"
            $BackupMode = "Complete"
        }
        
        # Sauvegarde des dossiers sources (en parallèle si activé)
        if ($ParallelProcessing -and $SourcePaths.Count -gt 1) {
            $results = Backup-FoldersInParallel -SourcePaths $SourcePaths -Destination $BackupDestination -ReferenceData $referenceData
        } else {
            $results = @{}
            foreach ($src in $SourcePaths) {
                $results[$src] = Backup-Folder -Source $src -Destination $BackupDestination -ReferenceData $referenceData
            }
        }
        
        # Vérification des résultats
        foreach ($key in $results.Keys) {
            if (!$results[$key]) {
                $script:BackupSuccess = $false
                Write-Log "La sauvegarde de '$key' a échoué" -Type "ERROR"
            }
        }
        
        # Mise à jour de l'historique des sauvegardes
        Update-BackupHistory -BackupPath $BackupDestination -BackupType $BackupMode
        
        # Rotation des anciennes sauvegardes
        Remove-OldBackups -BackupDir $BackupDestination -RetentionDays $RetentionDays
    } catch {
        $script:BackupSuccess = $false
        Write-Log "Erreur critique dans le processus de sauvegarde : $_" -Type "ERROR"
    } finally {
        # Finalisation
        $endTime = Get-Date
        $duration = $endTime - $script:StartTime
        
        Write-Log "=======================================================" -Type "INFO"
        Write-Log "=== Fin du script de sauvegarde ===" -Type "INFO"
        Write-Log "=======================================================" -Type "INFO"
        Write-Log "Durée totale : $($duration.ToString("hh\:mm\:ss"))" -Type "INFO"
        Write-Log "Fichiers sauvegardés : $script:TotalFilesCopied" -Type "INFO"
        Write-Log "Taille totale : $([math]::Round($script:TotalFilesSize / 1MB, 2)) MB" -Type "INFO"
        Write-Log "Statut : $(if($script:BackupSuccess){"Réussite"}else{"Échec"})" -Type $(if($script:BackupSuccess){"SUCCESS"}else{"ERROR"})
        Write-Log "Erreurs rencontrées : $script:ErrorCount" -Type "INFO"
        
        # Préparation et envoi du rapport
        $report = Format-BackupReport -StartTime $script:StartTime -EndTime $endTime `
            -BackupMode $BackupMode -BackupPath $BackupDestination `
            -FilesCopied $script:TotalFilesCopied -SizeCopiedBytes $script:TotalFilesSize `
            -Success $script:BackupSuccess -ErrorCount $script:ErrorCount
        
        # Affichage du résumé dans la console
        Write-Host "`n$($report.Text)" -ForegroundColor $(if($script:BackupSuccess){"Green"}else{"Red"})
        
        # Envoi de la notification
        $subject = "Sauvegarde $(if($script:BackupSuccess){"Réussie"}else{"Échouée"}) - $([datetime]::Now.ToString("yyyy-MM-dd HH:mm"))"
        Send-Notification -Subject $subject -Body $report.HTML -IsHTML
        
        # Export des métriques de performance
        Export-Metrics
    }
}

# =============================
# LANCEMENT DU SCRIPT
# =============================
# Vérification que le script n'est pas importé mais exécuté directement
if ($MyInvocation.InvocationName -ne ".") {
    Start-Backup
}
