<# 
.SYNOPSIS
 
    Check-TeamsUserProvisioning.ps1 - Check Provisioning Status of SfB and Teams Users
 
.DESCRIPTION

    Author: Lee Ford

    This tool allows you to check the assignment and provisioning status of a single user or batch of users from a CSV file.

    It will first check the user(s) Azure AD assignment for Teams/SfB licenses - this ensures the assigned license in Azure AD has been provisioned (actioned) correctly. Next, it will check the assignment and provisioning of the _actual_ service(s) in Teams/SfB - this is where the delay is normally found.

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

    To include deleted (unassigned) plans add to command:

    .\Check-TeamsUserProvisioning.ps1 -UPN user@domain.com -IncludeDeleted
        
#>

Param (

    [Parameter(mandatory = $false)][String]$UPN,
    [Parameter(mandatory = $false)][String]$ImportUserCSV,
    [Parameter(mandatory = $false)][Switch]$IncludeDeleted,
    [Parameter(mandatory = $false)][string]$OverrideAdminDomain,
    [Parameter(mandatory= $false)][switch]$DoNotCreateSessions

)

$script:AzureADLicenseIssues = @()
$script:SfBLicenseIssues = @()

function CheckUserLicense {

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

        # SfB/Teams
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
                    $SfBLicenseIssue = @{ }
                    $SfBLicenseIssue.UPN = $UPN
                    $SfBLicenseIssue.ProvisioningStatus = $assingedPlan.ProvisioningStatus
                    $SfBLicenseIssue.AssignedStatus = $assingedPlan.AssignedStatus
                    $SfBLicenseIssue.SubscribedPlanId = $assignedPlanId
                    $SfBLicenseIssue.LicensePlan = $assignedPlan
    
                    $script:SfBLicenseIssues += New-Object PSObject -Property $SfBLicenseIssue
    
                }

            }

        }

        Write-Host "`n`rSfB/Teams Assignment and Provisioning Status for $UPN..." -ForegroundColor DarkMagenta -BackgroundColor Black

        $assingedPlans | Sort-Object -Property LicensePlan | Format-Table

        if ($user.MCOValidationError) {

            Write-Host "`r`nValidate Error Found: `r`n$($user.MCOValidationError)" -ForegroundColor Red -BackgroundColor Black

        }

    }
    catch {

        Write-Warning "UPN not found in Azure AD!"

    }
    
}

function CheckModuleInstalled {
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

# Start
Write-Host "`n----------------------------------------------------------------------------------------------
            `n Check-TeamsUserProvisioning.ps1 - Lee Ford - https://www.lee-ford.co.uk
            `n----------------------------------------------------------------------------------------------" -ForegroundColor Yellow


# Check Azure AD and SfB modules installed
CheckModuleInstalled -module SkypeOnlineConnector -moduleName "Skype for Business Online module"
CheckModuleInstalled -module AzureAD -moduleName "Azure AD v2 module"

# Do not try to create sessions to SfB and Azure AD
if (!$DoNotCreateSessions) {

Write-Host "Using existing PowerShell sessions (outside of script)..."

# Is a SfB session already in place and is it "Opened"?
if (!$global:SfBPSSession -or $global:SfBPSSession.State -ne "Opened") {

    $username = Read-Host -Prompt "`r`nPlease enter your user principal name (ex. User@Domain.Com) to sign in to SfB and Azure AD PowerShell"

    Write-Host "`r`nSign in to SfB using prompt..."

    if ($OverrideAdminDomain) {

        $global:SfBPSSession = New-CsOnlineSession -OverrideAdminDomain $OverrideAdminDomain -UserName $username

    }
    else {

        $global:SfBPSSession = New-CsOnlineSession -UserName $username

    }
    
    # Import Session
    Import-PSSession $global:SfBPSSession -AllowClobber | Out-Null

    # Connect to Azure AD
    Write-Host "`r`nSign in to Azure AD using prompt (if required)..."
    Connect-AzureAD -AccountId $username | Out-Null

}
else {

    Write-Host "`r`nAlready connected to SfB and Azure AD..."

}

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

        CheckUserLicense -UPN $_.UPN
    
    }

}
elseif ($UPN) {

    CheckUserLicense -UPN $UPN

}
else {
    
    Write-Warning "No valid parameters specified!"

}

Write-Host "`n----------------------------------------------------------------------------------------------
            `n Licensing Summary
            `n----------------------------------------------------------------------------------------------" -ForegroundColor Yellow

if ($script:AzureADLicenseIssues) {

    Write-Host "`r`nThe following potential Azure AD licensing issues were found:" -ForegroundColor Red -BackgroundColor Black
    $script:AzureADLicenseIssues | Format-Table

}
else {

    Write-Host "`r`nNo Azure AD licensing issues were found." -ForegroundColor Green -BackgroundColor Black

}

if ($script:SfBLicenseIssues) {

    Write-Host "`r`nThe following potential Teams/SfB licensing issues were found:" -ForegroundColor Red -BackgroundColor Black
    $script:SfBLicenseIssues | Format-Table

}
else {

    Write-Host "`r`nNo Teams/SfB licensing issues were found." -ForegroundColor Green -BackgroundColor Black

}