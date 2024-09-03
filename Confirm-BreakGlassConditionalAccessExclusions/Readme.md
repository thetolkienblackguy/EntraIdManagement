# Confirm-BreakGlassConditionalAccessExclusions

## Overview

This PowerShell script is designed to monitor and verify the exclusion of break glass (BG) accounts from Conditional Access Policies (CAPs) in Microsoft Entra ID (formerly Azure AD). It addresses situations where BG accounts might inadvertently be included in restrictive policies, potentially blocking emergency access when it's most needed.

Microsoft's guidance on break glasss (emergency access accounts) is available at [Security emergency access accounts in Azure AD](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access).


## Features

- Checks if specified break glass accounts are excluded from all Conditional Access Policies by checking if the account is excluded individually, as part of a group, or as part of a nested group
- Generates a report of policies where BG accounts are not excluded
- Optionally sends an email report with findings
- Supports multiple authentication methods:
  - Managed Identity (for use in Azure Automation)
  - App Registration with Client Secret
  - App Registration with Certificate
  - Delegated authentication

## Prerequisites

- PowerShell 5.1 or later
- Microsoft Graph PowerShell SDK
- [Microsoft.Graph.Extensions](https://github.com/thetolkienblackguy/Microsoft.Graph.Extensions/tree/main) module (for email functionality)

## Setup

### App Registration Setup (Client Secret Method)

1. Navigate to the Azure Portal and go to "App registrations".
2. Click "New registration".
3. Name your application (e.g., "Confirm-BreakGlassConditionalAccessExclusions").
4. Select "Accounts in this organizational directory only" for Supported account types.
5. Click "Register".

![App Registration](https://private-user-images.githubusercontent.com/28851692/363809916-a62ea3d7-a696-4c8a-960c-48ae78ec1248.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjUzMjU1MDIsIm5iZiI6MTcyNTMyNTIwMiwicGF0aCI6Ii8yODg1MTY5Mi8zNjM4MDk5MTYtYTYyZWEzZDctYTY5Ni00YzhhLTk2MGMtNDhhZTc4ZWMxMjQ4LnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA5MDMlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwOTAzVDAxMDAwMlomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTg2ZTgwYTE5ZGQxYzlhZDEzYTQwMTkwOGJkZDRiYTI2MzZiMjI0MGUxMzc1ODc0ZmExOTM2YTFiZTg5NjFlMmMmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.yZD5x9-PDVSUSjvCy4udeSnUSZyujB1P2BVKRUZh70c)

6. Once registered, go to "API permissions" and add the following permissions:
   - Microsoft Graph > Application > Mail.Send
   - Microsoft Graph > Application > Policy.Read.All
   - Microsoft Graph > Application > User.Read.All

   **Important** It is recommended to limit the scope of the Mail.Send permission to only the mailbox that will be used to send the email alerts.
   Reference: [Application Access Policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access)

7. Click "Grant admin consent" for your organization.

![API Permissions](https://private-user-images.githubusercontent.com/28851692/363809914-51f1ae6d-80ef-4721-bc5f-5fedbff95232.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjUzMjU1MDIsIm5iZiI6MTcyNTMyNTIwMiwicGF0aCI6Ii8yODg1MTY5Mi8zNjM4MDk5MTQtNTFmMWFlNmQtODBlZi00NzIxLWJjNWYtNWZlZGJmZjk1MjMyLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA5MDMlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwOTAzVDAxMDAwMlomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPTJiYjliYjQ1ZTZkMzYwMDE0ODczODVmZTliYWNkYzhjOGIxZjNmNGY0MDBkYjg0MDI1MWJiOGE5ODY2NWY2OTQmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.JgRzt4WpI6fxILH2QaHTGhvkUj3F-oKWsQw4KmGrlDM)

8. Go to "Certificates & secrets", click "New client secret", and create a secret.
9. Copy the secret value immediately (you won't be able to see it again).

![Client Secret](https://private-user-images.githubusercontent.com/28851692/363809910-75f4e13b-5316-4dd0-839e-59790ee0be91.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3MjUzMjU1MDIsIm5iZiI6MTcyNTMyNTIwMiwicGF0aCI6Ii8yODg1MTY5Mi8zNjM4MDk5MTAtNzVmNGUxM2ItNTMxNi00ZGQwLTgzOWUtNTk3OTBlZTBiZTkxLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNDA5MDMlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjQwOTAzVDAxMDAwMlomWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWRhZmNkYmZkOTk4ZjkyNjdkNjU5YWM2NThmMzhkN2JiNTFiNzQxMTg0YjNmMDFmZDllNWEyOGI1YzQyYTgyMWEmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0JmFjdG9yX2lkPTAma2V5X2lkPTAmcmVwb19pZD0wIn0.pcFmSbs6IRediIexW0rzEo9hX4LrezQMf-hEMCTG0F8)

## Running the Script

### Preparing your Environment

1. Ensure you have the latest version of PowerShell installed.
2. Install the Microsoft Graph PowerShell SDK by running:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

3. Install the Microsoft.Graph.Extensions module:

```powershell
# Download the module
Invoke-WebRequest -Uri "https://github.com/thetolkienblackguy/Microsoft.Graph.Extensions/archive/main.zip" -OutFile "Microsoft.Graph.Extensions.zip"

# Extract the module
Expand-Archive -Path "Microsoft.Graph.Extensions.zip" -DestinationPath "C:\Temp"

# Move the module to the PowerShell modules folder
Move-Item -Path "C:\Temp\Microsoft.Graph.Extensions-main" -Destination "$($env:PSModulePath.Split(';')[0])\Microsoft.Graph.Extensions"

# Import the module
Import-Module Microsoft.Graph.Extensions

```

### Script Parameters

- `Break_Glass_Account`: An array of UPNs for your break glass accounts
- `To`: Email address(es) to send the report to
- `From`: Email address to send the report from
- `Client_Id`: Your app registration's client ID
- `Tenant_Id`: Your Entra ID tenant ID
- `Client_Secret`: Your app registration's client secret

### Running with Client Secret Authentication

```powershell
.\Confirm-BreakGlassConditionalAccessExclusions.ps1 `
    -Break_Glass_Account @("bg1@contoso.com","bg2@contoso.com") `
    -To "admin@contoso.com" `
    -From "noreply@contoso.com" `
    -Client_Id "your-client-id" `
    -Tenant_Id "your-tenant-id" `
    -Client_Secret "your-client-secret"
```

### Running with Certificate Authentication

For certificate-based authentication, you'll need to upload a certificate to your app registration and use its thumbprint:

```powershell
.\Confirm-BreakGlassConditionalAccessExclusions.ps1 `
    -Break_Glass_Account @("bg1@contoso.com","bg2@contoso.com") `
    -To "admin@contoso.com" `
    -From "noreply@contoso.com" `
    -Client_Id "your-client-id" `
    -Tenant_Id "your-tenant-id" `
    -Certificate_Thumbprint "your-certificate-thumbprint"
```

### Running with Delegated Permissions

For delegated permissions, you'll need to authenticate interactively:

```powershell
.\Confirm-BreakGlassConditionalAccessExclusions.ps1 `
    -Break_Glass_Account @("bg1@contoso.com","bg2@contoso.com") `
    -To "admin@contoso.com" `
    -From "noreply@contoso.com"
```

## Output and Reporting

The script generates a CSV report listing any Conditional Access Policies that do not exclude the specified break glass accounts. This report includes:

- Policy ID
- Policy Name
- Description
- State (Enabled/Disabled)
- Break Glass Account affected
- Whether it's excluded from the policy

If email parameters are provided, this report is sent via email using the `Send-GraphMailMessage` function from the Microsoft.Graph.Extensions module.

## Notes

- The script uses the Microsoft Graph SDK for most operations.
- Email functionality relies on the `Send-GraphMailMessage` function from [Microsoft.Graph.Extensions](https://github.com/thetolkienblackguy/Microsoft.Graph.Extensions/tree/main).
- While this README focuses on the client secret authentication method, the script also supports managed identity, certificate-based authentication, and delegated authentication.

## Contributing

Contributions to improve the script are welcome. Please submit pull requests or open issues on the GitHub repository.

## License

[MIT](https://github.com/thetolkienblackguy/EntraIdManagement/blob/main/LICENSE)