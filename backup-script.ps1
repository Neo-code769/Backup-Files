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
# Vérification et définition de $PSScriptRoot si nécessaire
# =============================
if (-not $PSScriptRoot) {
    $ScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
} # Closing brace added here
# =============================
# IMPORT DU FICHIER DE CONFIGURATION EXTERNE
# =============================
try {
    $configPath = "$ScriptRoot\config.ps1"
    if (Test-Path $configPath) {
        . $configPath
        Write-Output "Configuration chargée depuis $configPath"
    } else {
        throw "Fichier de configuration non trouvé : $configPath"
    } # Closing brace for the previous block
} catch {
    Write-Error "Erreur lors du chargement de la configuration : $_"
    Exit 1
} # Closing brace added here

# =============================
# CONFIGURATION PAR DÉFAUT SI NON DÉFINIE DANS CONFIG.PS1
# =============================
if (-not $SourcePaths) {
    $SourcePaths = @("C:\Windows\Temp")
} # Closing brace added here
if (-not $BackupDestination) {
    $BackupDestination = "C:\Backup"
} 
if (-not $LogFile) {
    $LogFile = "$ScriptRoot\backup.log"
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
if (-not $RetryDelaySeconds) { $RetryDelaySeconds = $RetryDelay }  # Utiliser $RetryDelay comme valeur par défaut
if ($null -eq $CollectMetrics) { $CollectMetrics = $true }
if (-not $MetricsOutputPath) { $MetricsOutputPath = "$ScriptRoot\metrics.csv" }
$UseSecureCredentials = if ($null -eq $UseSecureCredentials) { $false } else { $UseSecureCredentials }
if (-not $CredentialName) { $CredentialName = "BackupSMTP" }
if (-not $BackupHistoryFile) {
    $BackupHistoryFile = "$ScriptRoot\backup_history.json"
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
    
    # Ajout d'une vérification pour s'assurer que $RetryDelaySeconds a une valeur par défaut
    if (-not $RetryDelaySeconds) {
        $RetryDelaySeconds = 30  # Valeur par défaut en secondes
    }

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
        # Logique de la tentative
        Write-Log "Retrying backup operation ($retry/$MaxRetries)..." -Type "WARNING"
        Start-Sleep -Seconds $RetryDelaySeconds
        $retry++
    } while ($retry -le $MaxRetries -and !$success)

    # Obtention des fichiers sources (récursivement)
    $sourceFiles = Get-ChildItem -Path $Source -Recurse -File
    $totalFiles = $sourceFiles.Count
    $currentFile = 0

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
}
