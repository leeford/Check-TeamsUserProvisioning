<# 
.SYNOPSIS
 
    Check-TeamsUserProvisioning.ps1 - Check Provisioning Status of Teams Users
 
.DESCRIPTION

    Author: Lee Ford

    This tool allows you to check the assignment and provisioning status of a single user or batch of users from a CSV file.

    It will first check the user(s) Azure AD assignment for Teams licenses - this ensures the assigned license in Azure AD has been provisioned (actioned) correctly. Next, it will check the assignment and provisioning of the _actual_ service(s) in Teams - this is where the delay is normally found.

    Once all users have been checked a summary of potential licensing issues is provided.

.LINK

    Blog: https://www.lee-ford.co.uk
    Twitter: http://www.twitter.com/lee_ford
    LinkedIn: https://www.linkedin.com/in/lee-ford/
 
.EXAMPLE 
    
    The script can be ran to check a single user by running:

    .\Check-TeamsUserProvisioning.ps1 -UPN user@domain.com

    To check for a batch of users you can feed in a CSV (the CSV needs the header 'UPN' with user's UPN listed underneath):

    .\Check-TeamsUserProvisioning.ps1 -ImportUserCSV .\Users.csv

    To include deleted (unassigned) plans:

    .\Check-TeamsUserProvisioning.ps1 -UPN user@domain.com -IncludeDeleted

    To exports errors to a path:
    .\Check-TeamsUserProvisioning.ps1 -ImportUserCSV .\Users.csv -ExportErrorPath c:\temp\errors
        
#>

Param (

    [Parameter(mandatory = $false)][String]$UPN,
    [Parameter(mandatory = $false)][String]$ImportUserCSV,
    [Parameter(mandatory = $false)][Switch]$IncludeDeleted,
    [Parameter(mandatory = $false)][string]$OverrideAdminDomain,
    [Parameter(mandatory = $false)][String]$ExportErrorPath

)

$script:AzureADLicenseIssues = @()
$script:TeamsLicenseIssues = @()

function Check-UserLicense {

    param (
        
        [Parameter (mandatory = $true)][String]$UPN

    )

    # Azure AD
    try {

        Write-Host "`n----------------------------------------------------------------------------------------------
        `n $UPN
        `n----------------------------------------------------------------------------------------------" -ForegroundColor Yellow
        
        $AADLicenses = (Get-AzureADUser -ObjectId $UPN | Get-AzureADUserLicenseDetail).ServicePlans | Where-Object { $_.ServicePlanName -like "MCO*" -or $_.ServicePlanName -like "Teams*" } | Sort-Object -Property ServicePlanName -ErrorAction Stop

        Write-Host "`n`rAzure AD Provisioning Status for $UPN..." -ForegroundColor Blue -BackgroundColor Black
        $AADLicenses | Format-Table

        $AADLicenses | ForEach-Object {

            if ([string]$_.ProvisioningStatus -ne "Success" -and [string]$_.ProvisioningStatus -ne "Deleted") {
            
                # Potential Licensing Issue
                $AzureADLicenseIssue = @{ }
                $AzureADLicenseIssue.UPN = $UPN
                $AzureADLicenseIssue.ProvisioningStatus = $_.ProvisioningStatus
                $AzureADLicenseIssue.ServicePlanId = $_.ServicePlanId
                $AzureADLicenseIssue.ServicePlanName = $_.ServicePlanName

                $script:AzureADLicenseIssues += New-Object PSObject -Property $AzureADLicenseIssue

            }

        }

        # Teams
        $user = Get-CSOnlineUser -Identity $UPN | Select-Object AssignedPlan, ProvisionedPlan

        $assingedPlans = @()
        $user.assignedPlan | ForEach-Object {

            $assignedPlan = $_ | Select-String -Pattern 'Plan=(")(.*?)\1'
            $assignedPlan = $assignedPlan.Matches.Groups[2]

            $assignedPlanId = $_ | Select-String -Pattern 'SubscribedPlanId=(")(.*?)\1'
            $assignedPlanId = $assignedPlanId.Matches.Groups[2]

            $assignedPlanCapabilityStatus = $_ | Select-String -Pattern 'CapabilityStatus=(")(.*?)\1'
            $assignedPlanCapabilityStatus = $assignedPlanCapabilityStatus.Matches.Groups[2]

            $assignedPlanAssignedTimestamp = $_ | Select-String -Pattern 'AssignedTimestamp=(")(.*?)\1'
            $assignedPlanAssignedTimestamp = $assignedPlanAssignedTimestamp.Matches.Groups[2]
        
            # Check if deleted
            if ([string]$assignedPlanCapabilityStatus -ne "Deleted" -or $IncludeDeleted) {

                $assingedPlan = @{ }
                $assingedPlan.AssignedTimestamp = $assignedPlanAssignedTimestamp
                $assingedPlan.AssignedStatus = $assignedPlanCapabilityStatus
                $assingedPlan.LicensePlan = $assignedPlan
                $assingedPlan.SubscribedPlanId = $assignedPlanId
    
                $user.provisionedPlan | ForEach-Object {
    
                    $provisionedPlanId = $_ | Select-String -Pattern 'SubscribedPlanId=(")(.*?)\1'
                    $provisionedPlanId = $provisionedPlanId.Matches.Groups[2]
    
                    if ($provisionedPlanId -like "*$assignedPlanId*") {
    
                        $provisionedPlanCapabilityStatus = $_ | Select-String -Pattern 'CapabilityStatus=(")(.*?)\1'
                        $provisionedPlanCapabilityStatus = $provisionedPlanCapabilityStatus.Matches.Groups[2]
    
                        $assingedPlan.ProvisioningStatus = $provisionedPlanCapabilityStatus
    
                    }
    
                }
    
                $assingedPlans += New-Object PSObject -Property $assingedPlan

                if ([string]$assingedPlan.AssignedStatus -ne "Enabled" -and [string]$assingedPlan.AssignedStatus -ne "Deleted" -and [string]$assingedPlan.ProvisioningStatus -ne "Enabled" -and [string]$assingedPlan.ProvisioningStatus -ne "Deleted") {
            
                    # Potential Licensing Issue
                    $TeamsLicenseIssue = @{ }
                    $TeamsLicenseIssue.UPN = $UPN
                    $TeamsLicenseIssue.ProvisioningStatus = $assingedPlan.ProvisioningStatus
                    $TeamsLicenseIssue.AssignedStatus = $assingedPlan.AssignedStatus
                    $TeamsLicenseIssue.SubscribedPlanId = $assignedPlanId
                    $TeamsLicenseIssue.LicensePlan = $assignedPlan
    
                    $script:TeamsLicenseIssues += New-Object PSObject -Property $TeamsLicenseIssue
    
                }

            }

        }

        Write-Host "`n`rTeams Assignment and Provisioning Status for $UPN..." -ForegroundColor DarkMagenta -BackgroundColor Black

        $assingedPlans | Sort-Object -Property LicensePlan | Format-Table

        if ($user.MCOValidationError) {

            Write-Host "`r`nValidate Error Found: `r`n$($user.MCOValidationError)" -ForegroundColor Red -BackgroundColor Black

        }

    }
    catch {

        Write-Warning "UPN not found in Azure AD!"

    }
    
}

function Check-ModuleInstalled {
    param (

        [Parameter (mandatory = $true)][String]$module,
        [Parameter (mandatory = $true)][String]$moduleName
        
    )

    # Do you have module installed?
    Write-Host "`nChecking $moduleName installed..."

    if (Get-Module -ListAvailable -Name $module) {
    
        Write-Host "$moduleName installed." -ForegroundColor Green

    }
    else {

        Write-Error -Message "$moduleName not installed, please install and try again."
        
        break

    }
    
}

function Check-ExistingPSSession {
    param (
        [Parameter (mandatory = $true)][string]$ComputerName
    )
    
    $OpenSessions = Get-PSSession | Where-Object { $_.ComputerName -like $ComputerName -and $_.State -eq "Opened" }

    return $OpenSessions

}

# Start
Write-Host "`n----------------------------------------------------------------------------------------------
            `n Check-TeamsUserProvisioning.ps1 - Lee Ford - https://www.lee-ford.co.uk
            `n----------------------------------------------------------------------------------------------" -ForegroundColor Yellow


# Check Azure AD and Teams modules installed
Check-ModuleInstalled -module MicrosoftTeams -moduleName "Microsoft Teams module"
Check-ModuleInstalled -module AzureAD -moduleName "AzureAD v2 module"

$Connected = Check-ExistingPSSession -ComputerName "api.interfaces.records.teams.microsoft.com"

if (!$Connected) {

    Write-Host "No existing PowerShell Sessions..."
    Write-Host "`r`nSign in to Teams using prompt (this may appear behind this terminal)..."

    Connect-MicrosoftTeams

    # Connect to Azure AD
    Write-Host "`r`nSign in to AzureAD using prompt (this may appear behind this terminal)..."
    Connect-AzureAD

}
else {

    Write-Host "Using existing PowerShell Sessions..."

}

if ($ImportUserCSV) {

    # Import CSV
    $CSV = Import-CSV $ImportUserCSV

    $userCount = $CSV.Count

    $CSV | ForEach-Object {

        # Progress counter
        $counter++

        # Progress
        Write-Progress -Activity "Checking Users" -Status "Checking User $counter of $userCount" -CurrentOperation $_.UPN -PercentComplete (($counter / $userCount) * 100)

        Check-UserLicense -UPN $_.UPN
    
    }

}
elseif ($UPN) {

    Check-UserLicense -UPN $UPN

}
else {
    
    Write-Warning "No valid parameters specified!"

}

Write-Host "`n----------------------------------------------------------------------------------------------
            `n Licensing Summary
            `n----------------------------------------------------------------------------------------------" -ForegroundColor Yellow

if ($script:AzureADLicenseIssues) {

    Write-Host "`r`nThe following potential Azure AD licensing issues were found:" -ForegroundColor Red
    $script:AzureADLicenseIssues | Format-Table

    if ($ExportErrorPath) {

        Write-Host "Exporting Azure AD License Errors to $ExportErrorPath/AzureADLicenseErrors.csv"
        $script:AzureADLicenseIssues | Export-Csv -Path "$ExportErrorPath/AzureADLicenseErrors.csv" -NoTypeInformation

    }

}
else {

    Write-Host "`r`nNo Azure AD licensing issues were found." -ForegroundColor Green

}

if ($script:TeamsLicenseIssues) {

    Write-Host "`r`nThe following potential Teams licensing issues were found:" -ForegroundColor Red
    $script:TeamsLicenseIssues | Format-Table

    if ($ExportErrorPath) {

        Write-Host "Exporting Teams Licenses Errors to $ExportErrorPath/TeamsLicenseErrors.csv"
        $script:TeamsLicenseIssues | Export-Csv -Path "$ExportErrorPath/TeamsLicenseErrors.csv" -NoTypeInformation

    }

}
else {

    Write-Host "`r`nNo Teams licensing issues were found." -ForegroundColor Green

}