<##########################################################################################################################
    .DESCRIPTION
    This script is used to create a version history of conditional access policies in your tenant.

    .PARAMETER To
    The email address(es) to send the report to.

    .PARAMETER From
    The email address to send the report from.

    .PARAMETER Cc
    The email address(es) to Cc.

    .PARAMETER Subject
    The subject of the email.

    .PARAMETER Scope
    Micorosoft Graph scopes to use for the script.

    .PARAMETER ManagedIdentity
    Switch to use managed identity to connect to Microsoft Graph.

    .PARAMETER Client_Id
    The client id of the app registration.

    .PARAMETER Tenant_Id
    The tenant id of the app registration.

    .PARAMETER Certificate_Thumbpint
    The certificate thumbpint of the app registration.

    .PARAMETER Client_Secret
    The client secret of the app registration.

    .NOTES
    Author: Gabriel Delaney
    Date: 09/28/2024
    Version: 1.0
    Name: Invoke-ConditionalAccessPolicyVersionControl
    
    Version History:
    1.0 - Initial release - Gabriel Delaney - 09/01/2024

    .LINK
    https://github.com/thetolkienblackguy/EntraIdManagement/Readme.md
##########################################################################################################################>
[CmdletBinding(DefaultParameterSetName="Delegated")]
param (
    [Parameter(Mandatory=$false)]
    [string[]]$To,
    [Parameter(Mandatory=$false)]
    [string]$From,
    [Parameter(Mandatory=$false)]
    [string[]]$Cc,
    [Parameter(Mandatory=$false)]
    [string]$Subject = "Conditional Access Policy Comparison Report",
    [Parameter(DontShow=$true)]
    [string[]]$Scope = @(
        "Policy.Read.All","AuditLog.Read.All","Mail.Send"

    ),
    [Parameter(Mandatory=$false)]
    [string]$Output_Path = ".\",
    [Parameter(Mandatory=$true, ParameterSetName="ManagedIdentity")]
    [switch]$ManagedIdentity,
    [Parameter(Mandatory=$true, ParameterSetName="ClientSecret")]
    [Parameter(Mandatory=$true, ParameterSetName="Certificate")]
    [string]$Client_Id,
    [Parameter(Mandatory=$true, ParameterSetName="ClientSecret")]
    [Parameter(Mandatory=$true, ParameterSetName="Certificate")]
    [string]$Tenant_Id,
    [Parameter(Mandatory=$true, ParameterSetName="Certificate")]
    [string]$Certificate_Thumbpint,
    [Parameter(Mandatory=$true, ParameterSetName="ClientSecret")]
    [string]$Client_Secret

)
#region Prep

# Setting error handling to stop on error
$ErrorActionPreference = "Stop"

# Setting default parameter values
$PSDefaultParameterValues = @{}
$PSDefaultParameterValues["Write-Host:BackgroundColor"] = "Black"
$PSDefaultParameterValues["Write-Host:ForegroundColor"] = "Yellow"
$PSDefaultParameterValues["ConvertTo-SecureString:AsPlainText"] = $true
$PSDefaultParameterValues["ConvertTo-SecureString:Force"] = $true
$PSDefaultParameterValues["Sort-Object:Descending"] = $true
$PSDefaultParameterValues["ConvertFrom-Json:Depth"] = 4
$PSDefaultParameterValues["ConvertTo-Json:Depth"] = 4
$PSDefaultParameterValues["Get-MgAuditDirectoryAudit:Top"] = 1

#endregion

#region splatting
# Send-GraphMailMessage parameters
$send_mail_params = @{}
$send_mail_params["To"] = $to
$send_mail_params["From"] = $from
$send_mail_params["Subject"] = $subject
If ($cc) {
    $send_mail_params["Cc"] = $Cc

}

# Connect-MgGraph parameters
$connect_mg_params = @{}
$connect_mg_params["NoWelcome"] = $true

# If the parameter set is not managed identity, then we need to set the tenant id
If ($PSCmdlet.ParameterSetName -notin ("ManagedIdentity","Delegated")) {
    $connect_mg_params["TenantId"] = $tenant_id
    
    # If the parameter set is client secret, then we need to create a client secret credential object
    If ($PSCmdlet.ParameterSetName -eq "ClientSecret") {
        $connect_mg_params["ClientSecretCredential"] = New-Object System.Management.Automation.PSCredential($client_id, $($client_secret | ConvertTo-SecureString))

    # If the parameter set is certificate, then we need to set the certificate thumbprint
    } ElseIf ($PSCmdlet.ParameterSetName -eq "Certificate") {
        $connect_mg_params["ClientId"] = $client_id
        $connect_mg_params["CertificateThumbprint"] = $certificate_thumbpint

    }
# If the parameter set is delegated, then we need to set the scope
} ElseIf ($PSCmdlet.ParameterSetName -eq "Delegated") {
    $connect_mg_params["Scope"] = $scope

}
#endregion

#region Function definitions

# Function to flatten objects that have nested objects, hashtables, etc.
Function ConvertTo-FlatObject {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$InputObject,
        [Parameter(Mandatory=$false)]
        [string]$Prefix
    )
    Begin {
        # Initialize the flat object
        $flat_object = New-Object PSObject
    
    } Process {
        # Iterate through each property of the input object
        foreach ($property in $InputObject.PSObject.Properties) {
            # Create the key for the property
            $key = if ($Prefix) { "$Prefix.$($property.Name)" } else { $property.Name }
        
            # If the property value is a dictionary or a PSObject, recursively flatten it
            if ($property.Value -is [System.Collections.IDictionary] -or $property.Value -is [PSObject]) {
                $nested_object = ConvertTo-FlatObject -InputObject $property.Value -Prefix $key

                # Add each nested property to the flat object
                foreach ($nested_property in $nested_object.PSObject.Properties) {
                    $flat_object | Add-Member -NotePropertyName $nested_property.Name -NotePropertyValue $nested_property.Value
                
                }
            } else {
                # Add the property to the flat object
                $flat_object | Add-Member -NotePropertyName $key -NotePropertyValue $property.Value
            }
        }
    } End {
        # Return the flat object
        $flat_object
    
    }
}

# Function to compare the policies recursively
Function Compare-CAPObjectRecursively {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param (
        [Parameter(Mandatory=$true)]
        [object]$ReferenceObject,
        [Parameter(Mandatory=$true)]
        [object]$DifferenceObject
    )
    Begin {
        $differences = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    } Process {
        $flattened_reference = ConvertTo-FlatObject -InputObject $ReferenceObject
        $flattened_difference = ConvertTo-FlatObject -InputObject $DifferenceObject

        $all_properties = $flattened_reference.PSObject.Properties.Name + $flattened_difference.PSObject.Properties.Name | Select-Object -Unique

        foreach ($property_name in $all_properties) {
            # Initialize the is_different variable
            $is_different = $false

            # Skip the ModifiedDateTime property
            if ($property_name -like "*ModifiedDateTime*" -or $property_name -like "*CreatedDateTime*") { 
                continue 
            
            }

            # Get the property values from both objects
            $reference_value = $flattened_reference.$property_name
            $difference_value = $flattened_difference.$property_name

            # If the reference value is null and the difference value is not null, then the policy has been modified
            if ($null -eq $reference_value -and $null -ne $difference_value) {
                $is_different = $true
            
            # If the reference value is not null and the difference value is null, then the policy has been modified
            } Elseif ($null -ne $reference_value -and $null -eq $difference_value) {
                $is_different = $true
            
            # If the reference value and the difference value are not null, then compare the values
            } ElseIf ($null -ne $reference_value -and $null -ne $difference_value) {
                # If the reference value and the difference value are arrays, then compare the arrays
                if ($reference_value -is [array] -and $difference_value -is [array]) {
                    # If the arrays are different, then the policy has been modified
                    if (Compare-Object $reference_value $difference_value) {
                        $is_different = $true
                    }
                # If the reference value and the difference value are not arrays, then compare the values
                } Elseif ($reference_value -ne $difference_value) {
                    $is_different = $true
                
                }
            }
            # If the policy has been modified, then add the difference to the list
            if ($is_different) {
                $short_name = $property_name -split '\.' | Select-Object -Last 1
                $obj = [ordered]@{}
                $obj['FullPath'] = $property_name
                $obj['PropertyName'] = $short_name
                $obj['OldValue'] = $reference_value
                $obj['NewValue'] = $difference_value
                $differences.Add([PSCustomObject]$obj)

            }
        }
    } End {
        # Return the differences
        $differences
    
    }
}

# Helper function to format comparison values
Function Format-Value($Value) {
    # Format the value
    If ($null -eq $value) {
        "<em>null</em>"
    
    # If the value is an array and not a string, join the elements with commas
    } ElseIf ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
        ($value | ForEach-Object {$_ }) -join ", "
    
    # If the value is a string, return it as is
    } Else {
        $value
    
    }
}

# Function to create the HTML comparison
Function New-CAPHTMLComparison {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [Object]$PolicyInfo,
        [Parameter(Mandatory=$true)]
        [Object]$Differences,
        [Parameter(Mandatory=$true)]
        [string]$ModifiedBy,
        [Parameter(Mandatory=$false)]
        [string]$Version = "1"
    
    )
    Begin {
        # Get the total number of changes
        $total_changes = $differences.Count

        # Format the changes
        $changes_rows = $differences | ForEach-Object {
            $old_value_formatted = Format-Value $_.OldValue
            $new_value_formatted = Format-Value $_.NewValue
            "<tr><td>$($_.FullPath)</td><td>$($_.PropertyName)</td><td>$old_value_formatted</td><td>$new_value_formatted</td></tr>"
        
        }

        # Create the changes table
        $changes_table = "
        <h3>Changes ($total_changes)</h3>
        <table>
            <tr><th>Full Path</th><th>Property Name</th><th>Old Value</th><th>New Value</th></tr>
            $($changes_rows -join "`n")
        </table>"
    } Process {
        # Create the HTML content
        $html_content = "
        <!DOCTYPE html>
        <html lang=`"en`">
        <head>
            <meta charset=`"UTF-8`">
            <meta name=`"viewport`" content=`"width=device-width, initial-scale=1.0`">
            <title>$($policyInfo.DisplayName)</title>
            <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { width: 95%; margin: 0 auto; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .summary { font-weight: bold; margin-bottom: 10px; }
            </style>
        </head>
        <body>
            <div class=`"container`">
                <h1>$($policyInfo.DisplayName)</h1>
                <h2>Policy Information</h2>
                <table>
                    <tr><th>Display Name</th><td>$($policyInfo.DisplayName)</td></tr>
                    <tr><th>Policy ID</th><td>$($policyInfo.Id)</td></tr>
                    <tr><th>Policy Version</th><td>$version</td></tr>
                    <tr><th>Modified Date</th><td>$($policyInfo.ModifiedDateTime)</td></tr>
                    <tr><th>Modified By</th><td>$($modifiedBy)</td></tr>
                </table>
                <h2>Summary of Changes</h2>
                <p class=`"summary`">Total changes: $total_changes</p>
                <h2>Detailed Changes</h2>
                $changes_table
            </div>
        </body>
        </html>"
    
    } End {
        # Return the HTML content
        $html_content
    
    }
}

# Function to compare the policies recursively
Function Compare-ConditionalAccessPolicy {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [object]$ReferencePolicy,
        [Parameter(Mandatory=$true)]
        [object]$DifferencePolicy,
        [Parameter(Mandatory=$false)]
        [string]$Path = ".\",
        [Parameter(Mandatory=$false)]
        [string]$Version = "1",
        [Parameter(Mandatory=$false)]
        [string]$ModifiedBy,
        [Parameter(Mandatory=$false)]
        [switch]$Export
    
    )
    Begin {
        # Set the default parameter values for the functions
        $PSDefaultParameterValues = @{}
        $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

        $output_obj = [ordered]@{}

        # Create a hashtable to store the policy info
        $policy_info = [ordered]@{}
        $policy_info['DisplayName'] = $policy.DisplayName
        $policy_info['Id'] = $policy.Id
        $policy_info['ModifiedDateTime'] = $policy.ModifiedDateTime

    } Process {
        # Compare the policies recursively
        $differences = Compare-CAPObjectRecursively -ReferenceObject $referencePolicy -DifferenceObject $differencePolicy

        # New-CAPHTMLComparison parameters
        $new_html_report = @{}
        $new_html_report['PolicyInfo'] = $differencePolicy
        $new_html_report['Differences'] = $differences
        $new_html_report['ModifiedBy'] = $modifiedBy
        $new_html_report['Version'] = $version

        # Create the HTML report
        $html_report = New-CAPHTMLComparison @new_html_report

        # Create the full path
        $file_name = "$($differencePolicy.Id)_Version_$($version).html"
        $full_path = Join-Path -Path $path -ChildPath $file_name

        # Write the HTML report to the file
        $html_report | Out-File -FilePath $full_path

        $output_obj["Policy"] = $differencePolicy.DisplayName
        $output_obj["Html"] = $html_report
        $output_obj["Path"] = $full_path
        
    } End {
        # Return the HTML report path
        [PSCustomObject]$output_obj
    
    }
}

# Helper function to get the modified by for the policy
Function Get-CAPModifiedBy($PolicyId) {
    # Get-MgAuditLogDirectoryAudit parameters
    $get_audit_params = @{}
    $get_audit_params['Filter'] = "ActivityDisplayName eq 'Update conditional access policy' and targetResources/any(t:t/id eq '$PolicyId')"
    $get_audit_params['Top'] = 1

    # Get the audit log for the policy
    $initiated_by = (Get-MgAuditLogDirectoryAudit @get_audit_params).InitiatedBy

    # If the policy was modified by an app, then set the modified by to the app service principal name
    if ($initiated_by.App.ServicePrincipalName) {
        return $initiated_by.App.ServicePrincipalName
        
    # If the policy was modified by a user, then set the modified by to the user principal name
    } ElseIf ($initiated_by.User.UserPrincipalName) {
        return $initiated_by.User.UserPrincipalName
    
    } Else {
        "Unknown"
    
    }
}

# Helper function to export the policy to a json file
Function Export-CAPJson {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [object]$Policy,
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [string]$Version = "1",
        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )
    
    Begin {
        # Ensure the directory exists
        if (!(Test-Path -Path $path)) {
            New-Item -Path $path -ItemType Directory | Out-Null
        
        }
        
        # Create the full path for the file
        $file_name = "$($Policy.Id)_Version_$Version.json"
        $full_path = Join-Path -Path $Path -ChildPath $file_name
    
    } Process {
        Try {
            # Convert the policy to JSON and save it
            $policy | ConvertTo-Json -Depth 10 | Out-File -FilePath $full_path -Force
            Write-Verbose "Policy exported to: $full_path"
        
        } Catch {
            Write-Error "Failed to export policy to $full_path. Error: $_"
        
        }
    
    } End {
        If ($passThru) {
            $full_path
        
        }
    }
}

# Function to create the index.html file that contains the summary of all conditional access policy changes
Function New-CAPIndexHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[PSCustomObject]]$PolicyReports,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [Parameter(Mandatory=$false)]
        [string]$Title = "Conditional Access Policy Changes",
        [Parameter(Mandatory=$false)]
        [string]$Name = "index.html"
    
    )    
    Begin {
        # Create the output object
        $output_obj = [ordered]@{}
        # Create the index.html file
        $index_html = "<!DOCTYPE html>
        <html lang=`"en`">
        <head>
            <meta charset=`"UTF-8`">
            <meta name=`"viewport`" content=`"width=device-width, initial-scale=1.0`">
            <title>$Title</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; }
                h1, h2 { color: #0066cc; }
                ul { list-style-type: none; padding: 0; }
                li { margin-bottom: 10px; }
                a { text-decoration: none; color: #0066cc; }
                a:hover { text-decoration: underline; }
                .policy-report { margin-top: 40px; border-top: 1px solid #ccc; padding-top: 20px; }
                .download-btn { background-color: #4CAF50; border: none; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; }
                .footer { margin-top: 40px; border-top: 1px solid #ccc; padding-top: 20px; font-style: italic; }
            </style>
        </head>
        <body>
            <h1>$Title</h1>
            <p>To restore a Conditional Access Policy using the downloaded JSON, please refer to this article: <a href=`"https://techcommunity.microsoft.com/t5/microsoft-entra/conditional-access-upload-policy-file-preview/m-p/3835296`" target=`"_blank`">Conditional Access: Upload Policy File (Preview)</a></p>
            <h2>Policies with Changes:</h2>
            <ul>"
    
    } Process {
        # Add the policies to the index.html file
        foreach ($report in $policyReports) {
            $index_html += "
            <li><a href=`"#$($report.Policy)`">$($report.Policy)</a></li>"
        }
        
        # Add the detailed policy reports to the index.html file
        $index_html += "
        </ul>
        <h2>Detailed Policy Reports:</h2>"
        
        # Add the detailed policy reports to the index.html file
        foreach ($report in $policyReports) {
            # Get the JSON file path
            $json_path = $report.Path -replace '\.html$', '.json'

            # Get the JSON content
            $json_content = Get-Content -Path $json_path -Raw
            
            # Get the JSON bytes
            $json_bytes = [System.Text.Encoding]::UTF8.GetBytes($json_content)

            # Get the JSON base64
            $json_base64 = [Convert]::ToBase64String($json_bytes)
            
            # Add the detailed policy report to the index.html file
            $index_html += "
            <div id=`"$($report.Policy)`" class=`"policy-report`">
                <h3>$($report.Policy)</h3>
                <a href=`"data:application/json;base64,$json_base64`" download=`"$($report.Policy).json`" class=`"download-btn`">Download JSON</a>
                $($report.Html)
            </div>"
        }
        
        # Add the footer to the index.html file
        $index_html += "
        <div class=`"footer`">
            <p>Author: Gabriel Delaney</p>
            <p>GitHub: <a href=`"https://github.com/thetolkienblackguy/EntraIdManagement`" target=`"_blank`">https://github.com/thetolkienblackguy/EntraIdManagement</a></p>
        </div>
        </body>
        </html>"
        
        # Create the full path for the index.html file
        $index_path = Join-Path -Path $OutputPath -ChildPath $Name

        # Write the index.html file
        $index_html | Out-File -FilePath $index_path -Encoding utf8

        # Add the index.html file path to the output object
        $output_obj["Path"] = $index_path
        $output_obj["Html"] = $index_html
    } End {
        # Return the output object
        [PSCustomObject]$output_obj
    
    }
}

# Function to get the conditional access policies from Microsoft Graph. 
# I decided to use my own function because when exporting the policy to JSON, the policy
# it seemed to have elements that prevented it from being restored in the Entra Id portal.
Function Get-GraphConditionalAccessPolicy {
    <#
        .DESCRIPTION
        Gets a Conditional Access Policy from Microsoft Graph

        .SYNOPSIS
        Gets a Conditional Access Policy from Microsoft Graph


        .EXAMPLE
        Get-GraphConditionalAccessPolicy -ConditionalAccessPolicyId "00000000-0000-0000-0000-000000000000" 

        .EXAMPLE
        Get-MgIdentityConditionalAccessPolicy | Get-GraphConditionalAccessPolicy 
        
        
        .EXAMPLE
        Get-GraphConditionalAccessPolicy -Filter "displayName eq 'Test Policy'"

        .EXAMPLE
        Get-GraphConditionalAccessPolicy -All -FlattenOutput
        
        .INPUTS
        System.String
        System.IO.FileInfo

        .OUTPUTS
        System.Management.Automation.PSObject

        .LINK
        https://docs.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-1.0
        
        .NOTES
        Author: Gabriel Delaney | gdelaney@phzconsulting.com
        Date: 11/11/2023
        Version: 0.0.1
        Name: Get-GraphConditionalAccessPolicy

        Version History:
        0.0.1 - Alpha Release - 11/11/2023 - Gabe Delaney

    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    [OutputType([System.Management.Automation.PSObject])]
    Param (
        [Parameter(
            Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConditionalAccessPolicyId"
        )]
        [Alias("Id","PolicyId")]
        [string[]]$ConditionalAccessPolicyId,
        [Parameter(Mandatory=$false,ParameterSetName="Filter")]
        [string]$Filter,
        [Parameter(Mandatory=$false,ParameterSetName="All")]
        [switch]$All,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Beta","v1.0")]
        [string]$ApiVersion = "v1.0",
        [Parameter(Mandatory=$false,ParameterSetName="Filter")]
        [Parameter(Mandatory=$false,ParameterSetName="All")]
        [ValidateRange(1,999)]
        [int]$Top,
        [Parameter(Mandatory=$false)]
        [switch]$FlattenOutput
    
    )
    Begin {
        # Set the default parameter values
        $PSDefaultParameterValues = @{}
        $PSDefaultParameterValues["ConvertTo-Json:Depth"] = 10
        $PSDefaultParameterValues["Invoke-MgGraphRequest:Method"] = "GET"
        $PSDefaultParameterValues["Invoke-MgGraphRequest:OutputType"] = "PSObject"

    } Process {
        # Setting the filter based on the parameter set
        If ($PSCmdlet.ParameterSetName -eq "ConditionalAccessPolicyId") {
            $filter = "id eq '$conditionalAccessPolicyId'"
        
        } ElseIf ($PSCmdlet.ParameterSetName -eq "All") {
            $filter = $null

        }
        If ($top) {
            $top_str = "&`$top=$top"

        }
        Try {
            Do {
                # Get all the policies
                $r = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/$apiVersion/identity/conditionalAccess/policies?`$filter=$filter$($top_str)"
                
                # Output the policies
                If ($flattenOutput) {
                    # Flatten the output
                    Write-Warning "Object flattening is experimental and may not work as expected in all scenarios."
                    Foreach ($policy in $r.Value) {
                        $policy | ConvertTo-FlatObject
                
                    }
                } Else {
                    # Return the raw object
                    $r.Value
                
                }
            } Until (!$r."@odata.nextLink")
        } Catch {
            # Write the error
            Write-Error -Message $_
        
        } 
    } End {

    }
}

# Helper Function to create an attachment array for the Send-GraphMailMessage function
Function Set-GraphAttachmentArray {
    <#
        .DESCRIPTION
        This is a helper function to create an attachment array for the Send-GraphMailMessage function.

        .LINK
        https://docs.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0&tabs=http

        .INPUTS
        System.Array

        .OUTPUTS
        System.Col

        .NOTES
        Author: Gabe Delaney | gdelaney@phzconsulting.com
        Version: 0.0.1
        Date: 11/09/2023
        Name: Set-GraphAttachmentArray

        Version History:
        0.0.1 - Alpha Release - 11/09/2023 - Gabe Delaney

    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSObject]])]
    param (   
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [array]$Attachments

    )
    Begin {
        class MimeMapping {
            # Created this class to map file extensions to MIME types as System.Web.MimeMapping does not work in PowerShell 7.x
            static [string] GetMimeType([string]$path) {
                $extension = [System.IO.Path]::GetExtension($path).ToLower()
                if ([string]::IsNullOrEmpty($extension)) {
                    return "application/octet-stream"
                
                }
        
                try {
                    $reg_key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($extension)
                    if ($reg_key -and $reg_key.GetValue("Content Type")) {
                        return $reg_key.GetValue("Content Type").ToString()
                    }
                }
                catch {
                    Write-Verbose "Error getting MIME type for $($extension): $_"
                }
        
                return "application/octet-stream"
            }
        }
        # Create the attachment array
        $attachment_array = [system.collections.generic.list[psobject]]::new()

    } Process {
        # Loop through each attachment and add it to the attachment array
        Foreach ($attachment in $attachments) {
            # Get the file info
            $attachment_file_info = Get-Item $attachment
            
            # Create the attachment table
            $attachment_table = @{}
            $attachment_table["@odata.type"] = "#microsoft.graph.fileAttachment"
            $attachment_table["name"] = $attachment | Split-Path -Leaf
            $attachment_table["contentType"] = [MimeMapping]::GetMimeType($attachment_file_info.FullName)
            $attachment_table["contentBytes"] = [Convert]::ToBase64String([IO.File]::ReadAllBytes(($attachment_file_info).FullName))
            
            # Add the attachment table to the attachment array
            $attachment_array.Add($attachment_table)

        }
    } End {
        $attachment_array

    }  
}

# Helper Function to create a recipient array for the Send-GraphMailMessage function

Function Set-GraphRecipientArray {
    <#
        .DESCRIPTION
        This is a helper function that sets the recipient array for the Send-GraphMailMessage function.

        .INPUTS
        System.Array

        .OUTPUTS
        System.Collections.Generic.List[PSObject]

        .LINK
        https://docs.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0&tabs=http

        .NOTES
        Author: Gabe Delaney | gdelaney@phzconsulting.com
        Version: 0.0.1
        Date: 11/09/2023
        Name: Set-GraphRecipirentArray

        Version History:
        0.0.1 - Alpha Release - 11/09/2023 - Gabe Delaney

    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[PSObject]])]
    param (   
        [Parameter(Mandatory=$true)]
        [string[]]$Recipients

    )
    Begin {
        # Create the recipient array
        $recipient_array = [system.collections.generic.list[psobject]]::new()
        
    } Process {
        # Loop through each recipient and add it to the recipient array
        Foreach ($recipient in $recipients) {
            # Create the address table          
            $address = @{}
            $address["address"] = $recipient

            # Create the recipient table
            $recipient_table = @{}
            $recipient_table["emailAddress"] = $address

            # Add the recipient table to the recipient array
            $recipient_array.Add($recipient_table)

        }
    } End {
        # Return the recipient array
        $recipient_array

    }  
}

# Function to send a mail message using the Microsoft Graph API
Function Send-GraphMailMessage {
    <#
        .DESCRIPTION
        This function sends an email message using the Microsoft Graph API.

        .SYNOPSIS
        This function sends an email message using the Microsoft Graph API.

        .PARAMETER To
        Specifies the recipient(s) of the email message.

        .PARAMETER Subject
        Specifies the subject of the email message.

        .PARAMETER Body
        Specifies the body of the email message.

        .PARAMETER From
        Specifies the sender of the email message.

        .PARAMETER Cc
        Specifies the carbon copy recipient(s) of the email message.

        .PARAMETER Bcc
        Specifies the blind carbon copy recipient(s) of the email message.

        .PARAMETER Attachments
        Specifies the attachment(s) of the email message.

        .PARAMETER Importance
        Specifies the importance of the email message.

        .PARAMETER SaveToSentItems
        Specifies whether to save the email message to the sent items folder.

        .EXAMPLE
        Send-GraphMailMessage -To "john.doe@contoso.com" -From "jane.doe@contoso.com" -Subject "Test" -Body "This is a test"

        .EXAMPLE
        Send-GraphMailMessage -To "john.doe@contoso.com" -From "jane.doe@contoso.com" -Subject "Test" -Body "This is a test" -Attachments "C:\Temp\test.txt"

        .LINK
        https://docs.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0&tabs=http
        
        .INPUTS
        System.String
        System.IO.FileInfo
        System.Boolean

        .OUTPUTS

        .NOTES
        Author: Gabe Delaney | gdelaney@phzconsulting.com
        Version: 0.0.1
        Date: 11/09/2023
        Name: Send-GraphMailMessage

        Version History:
        0.0.1 - Alpha Release - 11/09/2023 - Gabe Delaney
    
    #>
    [CmdletBinding()]
    [OutputType()]
    param (      
        [Parameter(Mandatory=$true)]
        [Alias("Recipient")]
        [string[]]$To,
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        [Parameter(Mandatory=$true)]
        [Alias("EmailBody")]
        [string]$Body,
        [Parameter(Mandatory=$true)]
        [Alias("Sender")]
        [string]$From,
        [Parameter(Mandatory=$false)]
        [string[]]$Cc,
        [Parameter(Mandatory=$false)]
        [string[]]$Bcc,
        [Parameter(Mandatory=$false)]
        [system.io.fileinfo[]]$Attachments,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Low", "Normal", "High")]
        [string]$Importance = "Normal",
        [Parameter(Mandatory=$false)]
        [bool]$SaveToSentItems = $true

    )
    Begin {
        # Creating parent message hash table
        $mail_message = @{}
        $mail_message["message"] = ""
        $mail_message["saveToSentItems"] = $saveToSentItems
           
        # Creating message hash table
        $message = @{}
        $message["subject"] =  $subject
        $message["body"] = @{}
        $message["body"]["contentType"] = "HTML"
        $message["body"]["content"] = $body
        $message["importance"] = $importance
        Try {
            # Setting recipients
            $message["toRecipients"] = @(Set-GraphRecipientArray -Recipients $to)
            
            # Setting cc recipients
            If ($PSBoundParameters.ContainsKey("Cc")) {
                $message["ccRecipients"] = @(Set-GraphRecipientArray -Recipients $cc)

            }

            # Setting Bcc recipients
            If ($PSBoundParameters.ContainsKey("Bcc")) {
                $message["bccRecipients"] = @(Set-GraphRecipientArray -Recipients $bcc)

            }

            # Setting attachments
            If ($PSBoundParameters.ContainsKey("Attachments")) {
                $message["attachments"] = @(Set-GraphAttachmentArray -Attachments $attachments)

            }
        } Catch {
            Write-Error $_ -ErrorAction Stop
        
        }

        # Setting the message key
        $mail_message["message"] = $message

        # Setting the Invoke-MgGraphRequest parameters
        $invoke_graph_params = @{}
        $invoke_graph_params["Uri"] = "https://graph.microsoft.com/v1.0/users/$from/sendMail"
        $invoke_graph_params["Method"] = "Post"
        $invoke_graph_params["Body"] = $mail_message | ConvertTo-Json -Depth 4
        $invoke_graph_params["ContentType"] = "application/json"
        $invoke_graph_params["OutputType"] = "PSObject"

    } Process {
        Try {
            # Sending the message
            Invoke-MgGraphRequest @invoke_graph_params
        } Catch {
            Write-Error $_
        
        }
    } End {

    }
} 

#endregion

#region Graph Call
Try {
    Write-Output "Connecting to Graph"
    # Connecting to Microsoft Graph
    Connect-MgGraph @connect_mg_params
    Write-Output "Connected to Graph successfully"

} Catch {
    Write-Error "Failed to connect to Graph: $_"
    Exit 1

}
#endregion

#region Main
$policy_reports = [System.Collections.Generic.List[PSCustomObject]]::new()
$policies = Get-GraphConditionalAccessPolicy -All
Foreach ($policy in $policies) {
    $policy_id = $policy.id
    $policy_path = Join-Path -Path $output_path -ChildPath "Policies\$policy_id"
    
    # Export-CAPJson parameters
    $export_cap_params = @{}
    $export_cap_params['Policy'] = $policy
    $export_cap_params['Path'] = $policy_path

    Try {
        If (!(Test-Path -Path $policy_path)) {

            # Save the policy to the full path
            Export-CAPJson @export_cap_params -Version 1

            # Write the policy to the console
            Write-Output "Policy $($policy_id) has been saved to $($policy_path)"
            Write-Output "This is the initial version of the policy so no comparison is needed"
            Continue
            
        } Else {
            # Get the last modified policy
            $last_modified_policy = Get-ChildItem -Path $policy_path -Filter "*.json"| Sort-Object -Property LastWriteTime | Select-Object -First 1
            
            # Get the reference policy which is the last modified policy
            $reference_policy = Get-Content -Path $last_modified_policy.FullName | ConvertFrom-Json

            # Get the difference policy which is the current policy
            $difference_policy = $policy 

            # Compare the policies recursively
            $differences = Compare-CAPObjectRecursively -ReferenceObject $reference_policy -DifferenceObject $difference_policy

            # If there are no differences, then the policy has not been modified since the last version
            If (@($differences).Count -eq 0) {
                Write-Output "The policy $($policy_id) has not been modified since the last version"
                Continue
            
            # If there are differences, then the policy has been modified since the last version
            } Else {
                Write-Output "The policy $($policy_id) has been modified since the last version"
                # Increment the version number
                [int]$ver = ($last_modified_policy.Name -split '_' | Select-Object -Last 1).TrimEnd(".json")
                $ver++

                # Save the current policy to the full path
                Write-Output "Saving the current version of the policy $($policy_id) to the full path"
                Export-CAPJson @export_cap_params -Version $ver 
            
                # Get the modified by
                Write-Output "Getting the modified by for the policy $($policy_id)"
                $modified_by = Get-CAPModifiedBy -PolicyId $policy_id

                # Compare-ConditionalAccessPolicy parameters
                $compare_cap_params = @{}
                $compare_cap_params['ReferencePolicy'] = $reference_policy
                $compare_cap_params['DifferencePolicy'] = $difference_policy
                $compare_cap_params['Path'] = $policy_path
                $compare_cap_params['Version'] = $ver
                $compare_cap_params['ModifiedBy'] = $modified_by
                $compare_cap_params['Export'] = $true

                # Compare the policies recursively
                $html_report_obj = Compare-ConditionalAccessPolicy @compare_cap_params
                $policy_reports.Add($html_report_obj)

                Write-Output "The policy $($policy_id) has been modified since the last version"
                Write-Output "The report has been saved to $($html_report_obj.Path)"
            
            }   
        }
    } Catch {
        Write-Error "Could not compare policy $($policy_id): $_" -ErrorAction Continue
    
    }
}

#endregion

#region Post Processing

# Create the index.html file
If ($policy_reports.Count -gt 0) {
    $index_html_obj = New-CAPIndexHtml -PolicyReports $policy_reports -OutputPath $output_path
    Write-Output "Index HTML created at: $($index_html_obj.Path)"

    # Send an email with the index HTML
    Send-GraphMailMessage @send_mail_params -Body $index_html_obj.Html

} Else {
    Write-Output "No policy changes detected. No index HTML created."

}

#endregion