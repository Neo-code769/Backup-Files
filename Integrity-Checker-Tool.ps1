# ============================================
# Script PowerShell de vérification d'intégrité des sauvegardes
# Auteur : [TRUBLEREAU PIERRE]
# Date de création initiale : [22/04/2025]
# Date de dernière mise à jour : [22/04/2025]
# Version : 1.0
# Description : Script de vérification d'intégrité des sauvegardes créées par le script de sauvegarde avancée.
# Vérifie l'intégrité des manifestes, décompresse les archives si nécessaire, et valide les checksums.
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
    }
} catch {
    Write-Error "Erreur lors du chargement de la configuration : $_"
    Exit 1
}

# =============================
# CONFIGURATION PAR DÉFAUT SI NON DÉFINIE DANS CONFIG.PS1
# =============================
$BackupDestination = $BackupDestination ?? "D:\Sauvegardes"
$LogFile = $LogFile ?? "$PSScriptRoot\integrity_check.log"
$MaxParallelJobs = $MaxParallelJobs ?? 4
$EnableParallelProcessing = $EnableParallelProcessing ?? $true
$TempExtractionFolder = $TempExtractionFolder ?? "$env:TEMP\backup_integrity_check"
$ErrorThreshold = $ErrorThreshold ?? 5  # Nombre d'erreurs maximum avant arrêt de la vérification
$EnableNotification = $EnableNotification ?? $true
$MailFrom = $MailFrom ?? "backup@domain.com"
$MailTo = $MailTo ?? "admin@domain.com"
$SmtpServer = $SmtpServer ?? "smtp.domain.com"
$BackupHistoryFile = $BackupHistoryFile ?? "$PSScriptRoot\backup_history.json"
$ScanDepth = $ScanDepth ?? 30  # Nombre de jours en arrière pour rechercher des sauvegardes
$EmailErrorsOnly = $EmailErrorsOnly ?? $false  # Envoyer un email seulement en cas d'erreur

# =============================
# VARIABLES GLOBALES
# =============================
$script:StartTime = Get-Date
$script:TotalBackupsChecked = 0
$script:TotalBackupsValid = 0
$script:TotalBackupsInvalid = 0
$script:TotalFilesChecked = 0
$script:TotalFilesValid = 0
$script:TotalFilesInvalid = 0
$script:ErrorCount = 0
$script:CheckResults = @()
$script:TemporaryFiles = @()

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
        
        # Vérification du seuil d'erreurs
        if ($script:ErrorCount -ge $ErrorThreshold) {
            Write-Host "Seuil d'erreurs atteint ($ErrorThreshold). Arrêt de la vérification." -ForegroundColor Red
            return $false
        }
    }
    
    return $true
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
# CALCUL HASH (CHECKSUM)
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
# RÉCUPÉRATION DES SAUVEGARDES RÉCENTES
# =============================
Function Get-RecentBackups {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupRoot,
        
        [Parameter(Mandatory=$false)]
        [int]$DaysToScan = $ScanDepth
    )
    
    try {
        Write-Log "Recherche des sauvegardes dans $BackupRoot (sur les derniers $DaysToScan jours)..." -Type "INFO"
        
        $cutoffDate = (Get-Date).AddDays(-$DaysToScan)
        
        # Recherche des dossiers de sauvegarde
        $backupFolders = Get-ChildItem -Path $BackupRoot -Directory | 
            Where-Object { $_.LastWriteTime -ge $cutoffDate }
        
        $backupCount = ($backupFolders | Measure-Object).Count
        
        if ($backupCount -eq 0) {
            Write-Log "Aucune sauvegarde récente trouvée dans $BackupRoot" -Type "WARNING"
            return @()
        }
        
        Write-Log "$backupCount sauvegarde(s) trouvée(s) dans $BackupRoot" -Type "INFO"
        
        # Recherche des fichiers ZIP (sauvegardes compressées)
        $backupZips = Get-ChildItem -Path $BackupRoot -Filter "*.zip" | 
            Where-Object { $_.LastWriteTime -ge $cutoffDate }
        
        $zipCount = ($backupZips | Measure-Object).Count
        
        if ($zipCount -gt 0) {
            Write-Log "$zipCount sauvegarde(s) compressée(s) trouvée(s) dans $BackupRoot" -Type "INFO"
        }
        
        # Combiner les résultats
        $allBackups = @()
        $allBackups += $backupFolders | ForEach-Object { 
            [PSCustomObject]@{
                Path = $_.FullName
                LastWriteTime = $_.LastWriteTime
                IsCompressed = $false
                Name = $_.Name
            }
        }
        
        $allBackups += $backupZips | ForEach-Object {
            [PSCustomObject]@{
                Path = $_.FullName
                LastWriteTime = $_.LastWriteTime
                IsCompressed = $true
                Name = $_.Name
            }
        }
        
        # Trier par date (plus récent d'abord)
        return $allBackups | Sort-Object -Property LastWriteTime -Descending
    } catch {
        Write-Log "Erreur lors de la recherche des sauvegardes : $_" -Type "ERROR"
        return @()
    }
}

# =============================
# DÉCOMPRESSION D'UNE SAUVEGARDE
# =============================
Function Expand-Backup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ZipPath
    )
    
    try {
        # Créer un dossier temporaire pour l'extraction
        $extractPath = Join-Path -Path $TempExtractionFolder -ChildPath (Split-Path -Leaf $ZipPath).Replace(".zip", "")
        
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force
        }
        
        New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
        
        Write-Log "Décompression de $ZipPath vers $extractPath..." -Type "INFO"
        
        # Décompresser l'archive
        Expand-Archive -Path $ZipPath -DestinationPath $extractPath -Force
        
        # Enregistrer pour nettoyage ultérieur
        $script:TemporaryFiles += $extractPath
        
        Write-Log "Décompression terminée" -Type "SUCCESS" -NoConsole
        
        return $extractPath
    } catch {
        Write-Log "Erreur lors de la décompression de $ZipPath : $_" -Type "ERROR"
        return $null
    }
}

# =============================
# VÉRIFICATION D'UN MANIFESTE D'INTÉGRITÉ
# =============================
Function Verify-IntegrityManifest {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$IsExtracted
    )
    
    try {
        $manifestPath = Join-Path -Path $BackupPath -ChildPath "integrity_manifest.json"
        
        if (!(Test-Path $manifestPath)) {
            Write-Log "Manifeste d'intégrité non trouvé dans $BackupPath" -Type "ERROR"
            return @{
                Success = $false
                FilesChecked = 0
                FilesValid = 0
                FilesInvalid = 0
                MissingFiles = 0
                Details = "Manifeste d'intégrité manquant"
            }
        }
        
        Write-Log "Analyse du manifeste d'intégrité : $manifestPath" -Type "INFO"
        
        # Lecture du manifeste
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
        $files = $manifest.Files.PSObject.Properties
        $totalFiles = $files.Count
        
        Write-Log "Manifeste trouvé avec $totalFiles fichiers à vérifier" -Type "INFO"
        
        $processedFiles = 0
        $validFiles = 0
        $invalidFiles = 0
        $missingFiles = 0
        $details = [System.Collections.ArrayList]::new()
        
        # Préparation de la barre de progression
        $progressParams = @{
            Activity = "Vérification d'intégrité"
            Status = "Validation des checksums"
            PercentComplete = 0
        }
        
        foreach ($file in $files) {
            $relativePath = $file.Name
            $expectedHash = $file.Value.Hash
            $fullPath = Join-Path -Path $BackupPath -ChildPath $relativePath
            
            # Mise à jour de la progression
            $processedFiles++
            $progressParams.PercentComplete = [math]::Min(100, [math]::Round(($processedFiles / $totalFiles) * 100))
            $progressParams.Status = "Fichier $processedFiles/$totalFiles : $relativePath"
            Write-Progress @progressParams
            
            if (Test-Path $fullPath) {
                $currentHash = Get-FileHash256 -FilePath $fullPath
                
                if ($null -eq $currentHash) {
                    $invalidFiles++
                    [void]$details.Add("ERREUR: Impossible de calculer le hash pour '$relativePath'")
                    Write-Log "Impossible de calculer le hash pour '$relativePath'" -Type "ERROR" -NoConsole
                } elseif ($currentHash -ne $expectedHash) {
                    $invalidFiles++
                    [void]$details.Add("ERREUR: Hash invalide pour '$relativePath' (Attendu: $expectedHash, Obtenu: $currentHash)")
                    Write-Log "Hash invalide pour '$relativePath'" -Type "ERROR" -NoConsole
                } else {
                    $validFiles++
                    # On ne log pas les fichiers valides pour éviter de surcharger le journal
                }
            } else {
                $missingFiles++
                [void]$details.Add("ERREUR: Fichier manquant '$relativePath'")
                Write-Log "Fichier manquant: '$relativePath'" -Type "ERROR" -NoConsole
            }
            
            # Tous les 100 fichiers ou à la fin, on affiche un résumé
            if ($processedFiles % 100 -eq 0 -or $processedFiles -eq $totalFiles) {
                $percentComplete = [math]::Round(($processedFiles / $totalFiles) * 100, 1)
                Write-Log "Progression: $processedFiles/$totalFiles fichiers vérifiés ($percentComplete%)" -Type "INFO" -NoConsole
            }
        }
        
        # Fin de la barre de progression
        Write-Progress -Activity "Vérification d'intégrité" -Completed
        
        # Résultat global
        $success = ($invalidFiles -eq 0) -and ($missingFiles -eq 0)
        $statusType = if ($success) { "SUCCESS" } else { "ERROR" }
        $statusMessage = if ($success) {
            "Vérification réussie: $totalFiles fichiers vérifiés, tous valides"
        } else {
            "Échec de la vérification: $validFiles/$totalFiles valides, $invalidFiles invalides, $missingFiles manquants"
        }
        
        Write-Log $statusMessage -Type $statusType
        
        return @{
            Success = $success
            FilesChecked = $totalFiles
            FilesValid = $validFiles
            FilesInvalid = $invalidFiles
            MissingFiles = $missingFiles
            Details = $details -join "`n"
        }
    } catch {
        Write-Log "Erreur lors de la vérification du manifeste d'intégrité : $_" -Type "ERROR"
        return @{
            Success = $false
            FilesChecked = 0
            FilesValid = 0
            FilesInvalid = 0
            MissingFiles = 0
            Details = "Exception: $_"
        }
    }
}

# =============================
# VÉRIFICATION D'UN JOURNAL DE FICHIERS
# =============================
Function Check-FileLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )
    
    $fileLogPath = Join-Path -Path $BackupPath -ChildPath "_file_log.txt"
    
    if (!(Test-Path $fileLogPath)) {
        Write-Log "Journal de fichiers non trouvé: $fileLogPath" -Type "WARNING"
        return @{
            Found = $false
            ErrorEntries = 0
        }
    }
    
    try {
        $logContent = Get-Content -Path $fileLogPath
        $errorEntries = $logContent | Where-Object { $_ -like "*ÉCHEC*" }
        $errorCount = ($errorEntries | Measure-Object).Count
        
        if ($errorCount -gt 0) {
            Write-Log "Journal de fichiers contient $errorCount erreurs" -Type "WARNING"
            return @{
                Found = $true
                ErrorEntries = $errorCount
                ErrorDetails = $errorEntries -join "`n"
            }
        } else {
            Write-Log "Journal de fichiers ne contient pas d'erreurs" -Type "INFO" -NoConsole
            return @{
                Found = $true
                ErrorEntries = 0
            }
        }
    } catch {
        Write-Log "Erreur lors de l'analyse du journal de fichiers: $_" -Type "ERROR"
        return @{
            Found = $true
            ErrorEntries = -1
            ErrorDetails = "Exception lors de l'analyse: $_"
        }
    }
}

# =============================
# VÉRIFICATION COMPLÈTE D'UNE SAUVEGARDE
# =============================
Function Check-Backup {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Backup
    )
    
    try {
        $backupPath = $Backup.Path
        $backupName = $Backup.Name
        $isCompressed = $Backup.IsCompressed
        
        Write-Log "Vérification de la sauvegarde: $backupName ($(if($isCompressed){"Compressée"}else{"Non compressée"}))" -Type "INFO"
        
        $pathToCheck = $backupPath
        $isExtracted = $false
        
        # Si c'est une sauvegarde compressée, on la décompresse d'abord
        if ($isCompressed) {
            $pathToCheck = Expand-Backup -ZipPath $backupPath
            
            if ($null -eq $pathToCheck) {
                return @{
                    BackupName = $backupName
                    BackupPath = $backupPath
                    Success = $false
                    FilesChecked = 0
                    FilesValid = 0
                    FilesInvalid = 0
                    MissingFiles = 0
                    ErrorEntries = 0
                    Details = "Échec de la décompression"
                }
            }
            
            $isExtracted = $true
        }
        
        # Vérification du manifeste d'intégrité
        $manifestResult = Verify-IntegrityManifest -BackupPath $pathToCheck -IsExtracted:$isExtracted
        
        # Vérification du journal de fichiers
        $fileLogResult = Check-FileLog -BackupPath $pathToCheck
        
        # Construction du résultat
        $result = @{
            BackupName = $backupName
            BackupPath = $backupPath
            IsCompressed = $isCompressed
            Success = $manifestResult.Success -and ($fileLogResult.ErrorEntries -eq 0)
            FilesChecked = $manifestResult.FilesChecked
            FilesValid = $manifestResult.FilesValid
            FilesInvalid = $manifestResult.FilesInvalid
            MissingFiles = $manifestResult.MissingFiles
            FileLogFound = $fileLogResult.Found
            FileLogErrors = $fileLogResult.ErrorEntries
            Details = if ($manifestResult.Details -or $fileLogResult.ErrorDetails) {
                @(
                    "=== Détails du manifeste ===",
                    $manifestResult.Details,
                    if ($fileLogResult.ErrorEntries -gt 0) {
                        @(
                            "",
                            "=== Erreurs du journal de fichiers ===",
                            $fileLogResult.ErrorDetails
                        )
                    }
                ) -join "`n"
            } else {
                "Aucun problème détecté"
            }
        }
        
        # Mise à jour des compteurs globaux
        $script:TotalBackupsChecked++
        if ($result.Success) {
            $script:TotalBackupsValid++
        } else {
            $script:TotalBackupsInvalid++
        }
        
        $script:TotalFilesChecked += $result.FilesChecked
        $script:TotalFilesValid += $result.FilesValid
        $script:TotalFilesInvalid += $result.FilesInvalid + $result.MissingFiles
        
        # Log du résultat
        $status = if ($result.Success) { "SUCCESS" } else { "ERROR" }
        Write-Log "Résultat: $(if($result.Success){"VALIDE"}else{"INVALIDE"}) - $($result.FilesValid)/$($result.FilesChecked) fichiers valides" -Type $status
        
        return $result
    } catch {
        Write-Log "Erreur lors de la vérification de $backupName : $_" -Type "ERROR"
        return @{
            BackupName = $backupName
            BackupPath = $backupPath
            Success = $false
            FilesChecked = 0
            FilesValid = 0
            FilesInvalid = 0
            MissingFiles = 0
            Details = "Exception: $_"
        }
    }
}

# =============================
# TRAITEMENT PARALLÈLE
# =============================
Function Check-BackupsInParallel {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject[]]$Backups,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxJobs = $MaxParallelJobs
    )
    
    if (!$EnableParallelProcessing -or $Backups.Count -le 1) {
        $results = @()
        foreach ($backup in $Backups) {
            $results += Check-Backup -Backup $backup
        }
        return $results
    }
    
    try {
        Write-Log "Démarrage des vérifications en parallèle (max $MaxJobs jobs)..." -Type "INFO"
        
        # Limitation du nombre de jobs en parallèle
        $maxConcurrentJobs = [Math]::Min($MaxJobs, $Backups.Count)
        $throttleLimit = $maxConcurrentJobs
        
        # Stockage des résultats
        $results = @()
        $jobs = @()
        
        # Script block pour les jobs
        $scriptBlock = {
            param($BackupPath, $BackupName, $IsCompressed, $TempFolder)
            
            # Définition des fonctions nécessaires
            function Get-FileHash256 {
                param([string]$FilePath)
                try {
                    $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
                    return $hash.Hash
                } catch {
                    return $null
                }
            }
            
            function Expand-BackupInJob {
                param([string]$ZipPath)
                try {
                    $extractPath = Join-Path -Path $TempFolder -ChildPath (Split-Path -Leaf $ZipPath).Replace(".zip", "") + "_" + [Guid]::NewGuid().ToString().Substring(0, 8)
                    if (Test-Path $extractPath) { Remove-Item -Path $extractPath -Recurse -Force }
                    New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                    Expand-Archive -Path $ZipPath -DestinationPath $extractPath -Force
                    return $extractPath
                } catch {
                    return $null
                }
            }
            
            function Verify-ManifestInJob {
                param([string]$BackupPath)
                try {
                    $manifestPath = Join-Path -Path $BackupPath -ChildPath "integrity_manifest.json"
                    if (!(Test-Path $manifestPath)) { 
                        return @{
                            Success = $false
                            FilesChecked = 0
                            FilesValid = 0
                            FilesInvalid = 0
                            MissingFiles = 0
                            Details = "Manifeste d'intégrité manquant"
                        }
                    }
                    
                    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                    $files = $manifest.Files.PSObject.Properties
                    $totalFiles = $files.Count
                    
                    $validFiles = 0
                    $invalidFiles = 0
                    $missingFiles = 0
                    $details = @()
                    
                    foreach ($file in $files) {
                        $relativePath = $file.Name
                        $expectedHash = $file.Value.Hash
                        $fullPath = Join-Path -Path $BackupPath -ChildPath $relativePath
                        
                        if (Test-Path $fullPath) {
                            $currentHash = Get-FileHash256 -FilePath $fullPath
                            
                            if ($null -eq $currentHash) {
                                $invalidFiles++
                                $details += "Impossible de calculer le hash pour '$relativePath'"
                            } elseif ($currentHash -ne $expectedHash) {
                                $invalidFiles++
                                $details += "Hash invalide pour '$relativePath'"
                            } else {
                                $validFiles++
                            }
                        } else {
                            $missingFiles++
                            $details += "Fichier manquant '$relativePath'"
                        }
                    }
                    
                    $success = ($invalidFiles -eq 0) -and ($missingFiles -eq 0)
                    
                    return @{
                        Success = $success
                        FilesChecked = $totalFiles
                        FilesValid = $validFiles
                        FilesInvalid = $invalidFiles
                        MissingFiles = $missingFiles
                        Details = $details -join "`n"
                    }
                } catch {
                    return @{
                        Success = $false
                        FilesChecked = 0
                        FilesValid = 0
                        FilesInvalid = 0
                        MissingFiles = 0
                        Details = "Exception: $_"
                    }
                }
            }
            
            function Check-FileLogInJob {
                param([string]$BackupPath)
                
                $fileLogPath = Join-Path -Path $BackupPath -ChildPath "_file_log.txt"
                
                if (!(Test-Path $fileLogPath)) {
                    return @{
                        Found = $false
                        ErrorEntries = 0
                    }
                }
                
                try {
                    $logContent = Get-Content -Path $fileLogPath
                    $errorEntries = $logContent | Where-Object { $_ -like "*ÉCHEC*" }
                    $errorCount = ($errorEntries | Measure-Object).Count
                    
                    return @{
                        Found = $true
                        ErrorEntries = $errorCount
                        ErrorDetails = if ($errorCount -gt 0) { $errorEntries -join "`n" } else { "" }
                    }
                } catch {
                    return @{
                        Found = $true
                        ErrorEntries = -1
                        ErrorDetails = "Exception lors de l'analyse: $_"
                    }
                }
            }
            
            # Processus principal du job
            try {
                $pathToCheck = $BackupPath
                $extractedPath = $null
                
                # Si c'est une sauvegarde compressée, on la décompresse
                if ($IsCompressed) {
                    $pathToCheck = Expand-BackupInJob -ZipPath $BackupPath
                    $extractedPath = $pathToCheck
                    
                    if ($null -eq $pathToCheck) {
                        return @{
                            BackupName = $BackupName
                            BackupPath = $BackupPath
                            Success = $false
                            FilesChecked = 0
                            FilesValid = 0
                            FilesInvalid = 0
                            MissingFiles = 0
                            Details = "Échec de la décompression"
                        }
                    }
                }
                
                # Vérification du manifeste
                $manifestResult = Verify-ManifestInJob -BackupPath $pathToCheck
                
                # Vérification du journal de fichiers
                $fileLogResult = Check-FileLogInJob -BackupPath $pathToCheck
                
                # Nettoyage du dossier temporaire si nécessaire
                if ($null -ne $extractedPath -and (Test-Path $extractedPath)) {
                    Remove-Item -Path $extractedPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                
                # Résultat
                return @{
                    BackupName = $BackupName
                    BackupPath = $BackupPath
                    IsCompressed = $IsCompressed
                    Success = $manifestResult.Success -and ($fileLogResult.ErrorEntries -eq 0)
                    FilesChecked = $manifestResult.FilesChecked
                    FilesValid = $manifestResult.FilesValid
                    FilesInvalid = $manifestResult.FilesInvalid
                    MissingFiles = $manifestResult.MissingFiles
                    FileLogFound = $fileLogResult.Found
                    FileLogErrors = $fileLogResult.ErrorEntries
                    Details = if ($manifestResult.Details -or $fileLogResult.ErrorDetails) {
                        @(
                            "=== Détails du manifeste ===",
                            $manifestResult.Details,
                            if ($fileLogResult.ErrorEntries -gt 0) {
                                @(
                                    "",
                                    "=== Erreurs du journal de fichiers ===",
                                    $fileLogResult.ErrorDetails
                                )
                            }
                        ) -join "`n"
                    } else {
                        "Aucun problème détecté"
                    }
                }
            } catch {
                return @{
                    BackupName = $BackupName
                    BackupPath = $BackupPath
                    Success = $false
                    FilesChecked = 0
                    FilesValid = 0
                    FilesInvalid = 0
                    MissingFiles = 0
                    Details = "Exception critique: $_"
                }
            }
        }
        
        # Création du dossier temporaire
        if (!(Test-Path $TempExtractionFolder)) {
            New-Item -Path $TempExtractionFolder -ItemType Directory -Force | Out-Null
        }
        
# Complétion de Check-BackupsInParallel
        foreach ($backup in $Backups) {
            $jobParams = @{
                ScriptBlock = $scriptBlock
                ArgumentList = @($backup.Path, $backup.Name, $backup.IsCompressed, $TempExtractionFolder)
            }
            
            # Attendre si on a atteint le nombre max de jobs concurrents
            while ((Get-Job -State Running).Count -ge $throttleLimit) {
                Start-Sleep -Seconds 1
                
                # Vérifier les jobs terminés
                $completedJobs = Get-Job -State Completed
                foreach ($job in $completedJobs) {
                    $jobResult = Receive-Job -Job $job
                    $results += $jobResult
                    
                    # Mise à jour des compteurs globaux
                    $script:TotalBackupsChecked++
                    if ($jobResult.Success) {
                        $script:TotalBackupsValid++
                    } else {
                        $script:TotalBackupsInvalid++
                    }
                    
                    $script:TotalFilesChecked += $jobResult.FilesChecked
                    $script:TotalFilesValid += $jobResult.FilesValid
                    $script:TotalFilesInvalid += $jobResult.FilesInvalid + $jobResult.MissingFiles
                    
                    # Log du résultat
                    $status = if ($jobResult.Success) { "SUCCESS" } else { "ERROR" }
                    Write-Log "Résultat [JOB]: $(if($jobResult.Success){"VALIDE"}else{"INVALIDE"}) - $($jobResult.BackupName) - $($jobResult.FilesValid)/$($jobResult.FilesChecked) fichiers valides" -Type $status
                    
                    Remove-Job -Job $job
                }
            }
            
            # Démarrer le job
            $jobs += Start-Job @jobParams
            Write-Log "Job démarré pour $($backup.Name)" -Type "INFO" -NoConsole
        }
        
        # Attendre que tous les jobs se terminent
        Write-Log "Attente de la fin des jobs..." -Type "INFO"
        
        while (Get-Job) {
            $completedJobs = Get-Job -State Completed
            foreach ($job in $completedJobs) {
                $jobResult = Receive-Job -Job $job
                $results += $jobResult
                
                # Mise à jour des compteurs globaux
                $script:TotalBackupsChecked++
                if ($jobResult.Success) {
                    $script:TotalBackupsValid++
                } else {
                    $script:TotalBackupsInvalid++
                }
                
                $script:TotalFilesChecked += $jobResult.FilesChecked
                $script:TotalFilesValid += $jobResult.FilesValid
                $script:TotalFilesInvalid += $jobResult.FilesInvalid + $jobResult.MissingFiles
                
                # Log du résultat
                $status = if ($jobResult.Success) { "SUCCESS" } else { "ERROR" }
                Write-Log "Résultat [JOB]: $(if($jobResult.Success){"VALIDE"}else{"INVALIDE"}) - $($jobResult.BackupName) - $($jobResult.FilesValid)/$($jobResult.FilesChecked) fichiers valides" -Type $status
                
                Remove-Job -Job $job
            }
            
            # S'il reste des jobs en cours, attendre un peu
            if (Get-Job) {
                Start-Sleep -Seconds 2
            }
        }
        
        Write-Log "Tous les jobs terminés" -Type "INFO"
        return $results
    } catch {
        Write-Log "Erreur lors du traitement parallèle : $_" -Type "ERROR"
        
        # Nettoyer les jobs restants
        Get-Job | Remove-Job -Force
        
        return @()
    }
}

# =============================
# FONCTIONS DE NOTIFICATION PAR EMAIL
# =============================
Function Send-NotificationEmail {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Results,
        
        [Parameter(Mandatory=$false)]
        [switch]$ErrorsOnly = $EmailErrorsOnly
    )
    
    try {
        # Vérifier si on doit envoyer un email
        if (!$EnableNotification) {
            Write-Log "Notifications par email désactivées" -Type "INFO"
            return
        }
        
        $invalidBackups = $Results | Where-Object { !$_.Success }
        $invalidCount = ($invalidBackups | Measure-Object).Count
        
        # Si on veut uniquement les erreurs et qu'il n'y en a pas, on n'envoie pas de mail
        if ($ErrorsOnly -and $invalidCount -eq 0) {
            Write-Log "Aucune erreur à signaler par email" -Type "INFO"
            return
        }
        
        # Création du contenu de l'email
        $subject = "Rapport de vérification d'intégrité des sauvegardes"
        if ($invalidCount -gt 0) {
            $subject += " - $invalidCount problème(s) détecté(s)"
        } else {
            $subject += " - Tout est OK"
        }
        
        $htmlBody = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; text-align: left; }
        .success { background-color: #dff0d8; }
        .error { background-color: #f2dede; }
        .summary { font-weight: bold; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h2>Rapport de vérification d'intégrité des sauvegardes</h2>
    
    <div class="summary">
        <p>Date de vérification: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Sauvegardes vérifiées: $script:TotalBackupsChecked</p>
        <p>Sauvegardes valides: $script:TotalBackupsValid</p>
        <p>Sauvegardes invalides: $script:TotalBackupsInvalid</p>
        <p>Fichiers vérifiés: $script:TotalFilesChecked</p>
        <p>Fichiers valides: $script:TotalFilesValid</p>
        <p>Fichiers invalides: $script:TotalFilesInvalid</p>
    </div>
    
    <h3>Détails des sauvegardes</h3>
    <table>
        <tr>
            <th>Nom</th>
            <th>État</th>
            <th>Fichiers valides</th>
            <th>Fichiers invalides</th>
            <th>Fichiers manquants</th>
        </tr>
"@
        
        foreach ($result in $Results) {
            $rowClass = if ($result.Success) { "success" } else { "error" }
            $status = if ($result.Success) { "VALIDE" } else { "INVALIDE" }
            
            $htmlBody += @"
        <tr class="$rowClass">
            <td>$($result.BackupName)</td>
            <td>$status</td>
            <td>$($result.FilesValid)</td>
            <td>$($result.FilesInvalid)</td>
            <td>$($result.MissingFiles)</td>
        </tr>
"@
        }
        
        $htmlBody += @"
    </table>
    
    <h3>Détails des erreurs</h3>
"@
        
        if ($invalidCount -gt 0) {
            foreach ($invalid in $invalidBackups) {
                $htmlBody += @"
    <h4>$($invalid.BackupName)</h4>
    <pre>$($invalid.Details)</pre>
    <hr>
"@
            }
        } else {
            $htmlBody += "<p>Aucune erreur détectée.</p>"
        }
        
        $htmlBody += @"
</body>
</html>
"@
        
        # Paramètres de l'email
        $mailParams = @{
            From = $MailFrom
            To = $MailTo
            Subject = $subject
            Body = $htmlBody
            BodyAsHtml = $true
            SmtpServer = $SmtpServer
        }
        
        # Envoi de l'email
        Send-MailMessage @mailParams
        Write-Log "Email de notification envoyé à $MailTo" -Type "SUCCESS"
    } catch {
        Write-Log "Erreur lors de l'envoi de l'email de notification : $_" -Type "ERROR"
    }
}

# =============================
# NETTOYAGE DES FICHIERS TEMPORAIRES
# =============================
Function Remove-TemporaryFiles {
    try {
        if (Test-Path $TempExtractionFolder) {
            Write-Log "Nettoyage des fichiers temporaires..." -Type "INFO"
            
            # Supprimer tous les fichiers temporaires
            foreach ($tempFile in $script:TemporaryFiles) {
                if (Test-Path $tempFile) {
                    Remove-Item -Path $tempFile -Recurse -Force
                }
            }
            
            # Essayer de supprimer le dossier temporaire
            if ((Get-ChildItem -Path $TempExtractionFolder -Recurse | Measure-Object).Count -eq 0) {
                Remove-Item -Path $TempExtractionFolder -Force
                Write-Log "Dossier temporaire supprimé" -Type "INFO" -NoConsole
            } else {
                Write-Log "Impossible de supprimer complètement le dossier temporaire, certains fichiers sont peut-être encore en cours d'utilisation" -Type "WARNING" -NoConsole
            }
        }
    } catch {
        Write-Log "Erreur lors du nettoyage des fichiers temporaires : $_" -Type "ERROR"
    }
}

# =============================
# EXPORT DES RÉSULTATS
# =============================
Function Export-CheckResults {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Results
    )
    
    try {
        # Créer un objet de rapport
        $report = [PSCustomObject]@{
            Date = Get-Date
            BackupsChecked = $script:TotalBackupsChecked
            BackupsValid = $script:TotalBackupsValid
            BackupsInvalid = $script:TotalBackupsInvalid
            FilesChecked = $script:TotalFilesChecked
            FilesValid = $script:TotalFilesValid
            FilesInvalid = $script:TotalFilesInvalid
            Details = $Results
        }
        
        # Exporter en JSON
        $reportPath = "$PSScriptRoot\integrity_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Log "Rapport exporté vers $reportPath" -Type "SUCCESS"
        
        # Exporter en CSV
        $csvPath = "$PSScriptRoot\integrity_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $Results | Select-Object BackupName, Success, FilesChecked, FilesValid, FilesInvalid, MissingFiles, FileLogErrors | 
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Rapport CSV exporté vers $csvPath" -Type "SUCCESS"
        
        # Mise à jour du fichier d'historique
        Update-BackupHistory -Results $Results
        
        return $reportPath
    } catch {
        Write-Log "Erreur lors de l'export des résultats : $_" -Type "ERROR"
        return $null
    }
}

# =============================
# MISE À JOUR DE L'HISTORIQUE
# =============================
Function Update-BackupHistory {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Results
    )
    
    try {
        # Charger l'historique existant ou créer un nouveau
        $history = @()
        if (Test-Path $BackupHistoryFile) {
            $history = Get-Content -Path $BackupHistoryFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($null -eq $history) { $history = @() }
        }
        
        # Date actuelle
        $checkDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Ajouter les nouveaux résultats
        foreach ($result in $Results) {
            $historyItem = [PSCustomObject]@{
                Date = $checkDate
                BackupName = $result.BackupName
                BackupPath = $result.BackupPath
                Success = $result.Success
                FilesChecked = $result.FilesChecked
                FilesValid = $result.FilesValid
                FilesInvalid = $result.FilesInvalid
                MissingFiles = $result.MissingFiles
            }
            
            $history += $historyItem
        }
        
        # Limiter l'historique aux 1000 dernières vérifications
        if ($history.Count -gt 1000) {
            $history = $history | Select-Object -Last 1000
        }
        
        # Sauvegarder l'historique
        $history | ConvertTo-Json | Out-File -FilePath $BackupHistoryFile -Encoding UTF8
        Write-Log "Historique des vérifications mis à jour" -Type "INFO" -NoConsole
    } catch {
        Write-Log "Erreur lors de la mise à jour de l'historique : $_" -Type "ERROR"
    }
}

# =============================
# FONCTION PRINCIPALE
# =============================
Function Start-IntegrityCheck {
    param(
        [Parameter(Mandatory=$false)]
        [string]$BackupFolder = $BackupDestination,
        
        [Parameter(Mandatory=$false)]
        [int]$DaysToScan = $ScanDepth
    )
    
    try {
        Write-Log "Début de la vérification d'intégrité des sauvegardes" -Type "INFO"
        Write-Log "Dossier de sauvegardes : $BackupFolder" -Type "INFO"
        Write-Log "Profondeur de scan : $DaysToScan jours" -Type "INFO"
        
        # Création du dossier temporaire
        if (!(Test-Path $TempExtractionFolder)) {
            New-Item -Path $TempExtractionFolder -ItemType Directory -Force | Out-Null
        }
        
        # Récupération des sauvegardes récentes
        $backups = Get-RecentBackups -BackupRoot $BackupFolder -DaysToScan $DaysToScan
        
        if ($backups.Count -eq 0) {
            Write-Log "Aucune sauvegarde trouvée à vérifier" -Type "WARNING"
            return $null
        }
        
        Write-Log "Nombre de sauvegardes à vérifier : $($backups.Count)" -Type "INFO"
        
        # Vérification des sauvegardes
        if ($EnableParallelProcessing -and $backups.Count -gt 1) {
            Write-Log "Utilisation du traitement parallèle" -Type "INFO"
            $results = Check-BackupsInParallel -Backups $backups -MaxJobs $MaxParallelJobs
        } else {
            Write-Log "Utilisation du traitement séquentiel" -Type "INFO"
            $results = @()
            foreach ($backup in $backups) {
                $results += Check-Backup -Backup $backup
            }
        }
        
        # Export des résultats
        $reportPath = Export-CheckResults -Results $results
        
        # Envoi de notification par email
        Send-NotificationEmail -Results $results
        
        return $results
    } catch {
        Write-Log "Erreur critique lors de la vérification d'intégrité : $_" -Type "ERROR"
        return $null
    } finally {
        # Nettoyage final
        Remove-TemporaryFiles
    }
}

# =============================
# EXÉCUTION PRINCIPALE
# =============================
try {
    Write-Log "============================================" -Type "INFO"
    Write-Log "Démarrage du script de vérification d'intégrité" -Type "INFO"
    Write-Log "Version : 1.0" -Type "INFO"
    Write-Log "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Type "INFO"
    Write-Log "============================================" -Type "INFO"
    
    # Vérification des droits administrateur
    if (-not (Test-IsAdmin)) {
        Write-Log "Ce script doit être exécuté en tant qu'administrateur." -Type "ERROR"
        Exit 1
    }
    
    # Exécution de la vérification d'intégrité
    $results = Start-IntegrityCheck
    
    # Affichage des statistiques globales
    if ($null -ne $results) {
        $totalDuration = (Get-Date) - $script:StartTime
        $durationFormatted = "{0:D2}h:{1:D2}m:{2:D2}s" -f $totalDuration.Hours, $totalDuration.Minutes, $totalDuration.Seconds
        
        Write-Log "============================================" -Type "INFO"
        Write-Log "RÉSULTATS GLOBAUX DE LA VÉRIFICATION" -Type "INFO"
        Write-Log "============================================" -Type "INFO"
        Write-Log "Durée totale: $durationFormatted" -Type "INFO"
        Write-Log "Sauvegardes vérifiées: $script:TotalBackupsChecked" -Type "INFO"
        Write-Log "Sauvegardes valides: $script:TotalBackupsValid" -Type "INFO"
        Write-Log "Sauvegardes invalides: $script:TotalBackupsInvalid" -Type "INFO"
        Write-Log "Fichiers vérifiés: $script:TotalFilesChecked" -Type "INFO"
        Write-Log "Fichiers valides: $script:TotalFilesValid" -Type "INFO"
        Write-Log "Fichiers invalides: $script:TotalFilesInvalid" -Type "INFO"
        
        # Code de sortie selon le résultat
        if ($script:TotalBackupsInvalid -eq 0) {
            Write-Log "Vérification terminée avec succès" -Type "SUCCESS"
            Exit 0
        } else {
            Write-Log "Vérification terminée avec $script:TotalBackupsInvalid erreur(s)" -Type "ERROR"
            Exit 2
        }
    } else {
        Write-Log "Vérification terminée sans résultats" -Type "WARNING"
        Exit 1
    }
} catch {
    Write-Log "Erreur fatale dans le script principal : $_" -Type "ERROR"
    Exit 99
} finally {
    Write-Log "Fin du script de vérification d'intégrité" -Type "INFO"
    Write-Log "============================================" -Type "INFO"
}
