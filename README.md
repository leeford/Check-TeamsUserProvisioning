# Check-TeamsUserProvisioning
Check Provisioning Status of SfB and Teams Users

## Introduction

You may from time to time have run in to an issue where an Teams/SfB user has not been provisioned correctly. The most common scenario for this is a delay in Office 365 provisioning the user - you have assigned the required SfB/Teams licenses and it has yet to become available to the end user (it is not uncommon for licenses to take over 24 hours to be provisioned).

Another scenario is where the provisioning has become 'stuck' due to an error but this is not apparent from the Office 365 Portal or Teams Admin Centre.

## What does this tool do?

This tool allows you to check the assignment and provisioning status of a single user or batch of users from a CSV file.

It will first check the user(s) Azure AD assignment for Teams/SfB licenses - this ensures the assigned license in Azure AD has been provisioned (actioned) correctly. Next, it will check the assignment and provisioning of the _actual_ service(s) in Teams/SfB - this is where the delay is normally found.

Once all users have been checked a summary of potential licensing issues is provided.

## What this tool does not do

This tool will not fix any provisioning or assignment issues for you. It is here to highlight any potential issues you may not be aware of or to check if provisioning is complete.

## Usage

> Before you can use this tool you need to ensure you have the Skype Online and Azure AD (v2) PowerShell modules installed.

The script can be ran to check a single user by running:

```.\Check-TeamsUserProvisioning.ps1 -UPN user@domain.com```

To check for a batch of users you can feed in a CSV (the CSV needs the header 'UPN' with user's UPN listed underneath):

```.\Check-TeamsUserProvisioning.ps1 -ImportUserCSV .\Users.csv```

To include deleted (unassigned) plans add to command:

```.\Check-TeamsUserProvisioning.ps1 -UPN user@domain.com -IncludeDeleted```

Upon running the tool, for each user their Azure AD and Teams/SfB status will be outputted to the console. At the end of the script any issues will be provided.

![](https://www.lee-ford.co.uk/images/provisioning-check/PendingAzure.png)