# Confirm-BreakGlassConditionalAccessExclusions

## Overview

Roughly two years ago, one of my clients encountered a critical situation where a Conditional Access Policy (CAP) was created that blocked every user from accessing Entra ID, with the exception of some printer mailboxes. They called me on a Saturday, and thankfully, I had an app registration that I could use to add an admin to the CAP's exclusion group.

Ever since that incident, I've been adamant about working with my clients to create break glass (BG) accounts, following Microsoft's best practices as closely as possible: [Security emergency access accounts in Azure AD](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access).

One crucial aspect of BG accounts is that they should be excluded from CAPs wherever possible. While this may seem straightforward, in environments with multiple administrators, I often see CAPs being created without excluding the BG accounts. To address this, I've developed a simple solution: this PowerShell script.

## Features

- Checks if specified break glass accounts are excluded from all Conditional Access Policies
- Generates a report of policies where BG accounts are not excluded
- Optionally sends an email report with findings
- Supports multiple authentication methods:
  - Managed Identity (for use in Azure Automation)
  - App Registration with Client Secret
  - App Registration with Certificate
  - Delegated permissions

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

![App Registration](path_to_image3.png)

6. Once registered, go to "API permissions" and add the following permissions:
   - Microsoft Graph > Application > Mail.Send
   - Microsoft Graph > Application > Policy.Read.All
   - Microsoft Graph > Application > User.Read.All

7. Click "Grant admin consent" for your organization.

![API Permissions](path_to_image2.png)

8. Go to "Certificates & secrets", click "New client secret", and create a secret.
9. Copy the secret value immediately (you won't be able to see it again).

![Client Secret](path_to_image1.png)

## Usage

### Client Secret Authentication

```powershell
.\Confirm-BreakGlassConditionalAccessExclusions.ps1 `
    -Break_Glass_Account "bg1@contoso.com","bg2@contoso.com" `
    -To "admin@contoso.com" `
    -From "noreply@contoso.com" `
    -Client_Id "your-client-id" `
    -Tenant_Id "your-tenant-id" `
    -Client_Secret "your-client-secret"
```

### Certificate Authentication

```powershell
.\Confirm-BreakGlassConditionalAccessExclusions.ps1 `
    -Break_Glass_Account "bg1@contoso.com","bg2@contoso.com" `
    -To "admin@contoso.com" `
    -From "noreply@contoso.com" `
    -Client_Id "your-client-id" `
    -Tenant_Id "your-tenant-id" `
    -Certificate_Thumbprint "your-certificate-thumbprint"
```

### Delegated Authentication

```powershell
.\Confirm-BreakGlassConditionalAccessExclusions.ps1 `
    -Break_Glass_Account "bg1@contoso.com","bg2@contoso.com" `
    -To "admin@contoso.com" `
    -From "noreply@contoso.com"
```

## Output

The script generates a CSV report listing any Conditional Access Policies that do not exclude the specified break glass accounts. If email parameters are provided, this report is sent via email using the `Send-GraphMailMessage` function from the [Microsoft.Graph.Extensions](https://github.com/thetolkienblackguy/Microsoft.Graph.Extensions/tree/main) module.

## Notes

- The script uses the Microsoft Graph SDK for most operations.
- Email functionality relies on the `Send-GraphMailMessage` function from [Microsoft.Graph.Extensions](https://github.com/thetolkienblackguy/Microsoft.Graph.Extensions/tree/main).
- While this README focuses on the client secret authentication method, the script also supports managed identity, certificate-based authentication, and delegated permissions.

## Contributing

Contributions to improve the script are welcome. Please submit pull requests or open issues on the GitHub repository.

## License

[MIT](https://github.com/thetolkienblackguy/EntraIdManagement/blob/main/LICENSE)