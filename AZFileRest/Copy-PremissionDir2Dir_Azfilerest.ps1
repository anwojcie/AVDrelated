
function Get-AzAccessToken_forStorage {
    <#
    .SYNOPSIS
    Gets an access token to access Az Storage FileRest API
    .DESCRIPTION
    Gets an access token to access Az Storage FileRest API
    .INPUTS
    None. You cannot pipe objects 
    .OUTPUTS
    System.String: Access Token
    .EXAMPLE
    PS> Get-AzAccessToken_forStorage -AzPwshSession
    eyJhbGciOiJSUzI1NiIsIng1dCI6Imd4OHRHeX....
    .EXAMPLE
    PS> Get-AzAccessToken_forStorage -TenantID "fbc16a22-454e-440c-a4d0-48c39aebb389" -client_id "7a9edb5c-7423-44c7-99b1-c0ebac0bbe2a" -client_secret $env:SPNSecret  
    eyJhbGciOiJSUzI1NiIsIng1dCI6Imd4OHRHeX...
    .EXAMPLE
    PS> Get-AzAccessToken_forStorage -TenantID "fbc16a22-454e-440c-a4d0-48c39aebb389" -client_id "7a9edb5c-7423-44c7-99b1-c0ebac0bbe2a" -Federated_Token $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN  
    eyJhbGciOiJSUzI1NiIsIng1dCI6Imd4OHRHeX...
    .LINK
    https://learn.microsoft.com/en-us/rest/api/storageservices/file-service-rest-api
    #>
    [CmdletBinding(DefaultParameterSetName = 'AzPwshSession')]
    param (
        # If Az Pwsh is installed and this session is logged in you can use
        [Parameter(Mandatory, ParameterSetName = 'AzPwshSession')]
        [switch]$AzPwshSession,
        # If Az Cli is installed and this session is logged in you can use
        [Parameter(Mandatory, ParameterSetName = 'AzCli')]
        [switch]$AzCli,
        # Tenant ID of the SPN or Managed Identity to get an access token for
        [Parameter(Mandatory, ParameterSetName = 'AzSPNSecret')]
        [Parameter(Mandatory, ParameterSetName = 'AzSPNFereation')]
        [string]$TenantID,
        # client / app id of the SPN
        [Parameter(Mandatory, ParameterSetName = 'AzSPNSecret')]
        [Parameter(Mandatory, ParameterSetName = 'AzSPNFereation')]
        [string]$client_id,
        # client secret for the SPN
        [Parameter(Mandatory, ParameterSetName = 'AzSPNSecret')]        
        [string]$client_secret,
        # federated token from the source auth provider configured for the SPN
        [Parameter(Mandatory, ParameterSetName = 'AzSPNFereation')]
        [string]$Federated_Token
    )
    
    switch ($PSCmdlet.ParameterSetName) {
        'AzSPNSecret' { 
            $Auth_uri = "https://login.microsoft.com/" + $TenantID + "/oauth2/v2.0/token"
            $Auth_body = @{
                grant_type    = "client_credentials"
                client_id     = $client_id
                client_secret = $client_secret
                scope         = "https://storage.azure.com//.default openid profile offline_access"
            }
            $resp = Invoke-RestMethod -Method Post -Uri $Auth_uri -Body $Auth_body -ContentType "application/x-www-form-urlencoded"
            $result = $resp.access_token
        }
        'AzCli' {
            $result = az account get-access-token --resource="https://storage.azure.com/" | ConvertFrom-Json | Select-Object -ExpandProperty accessToken
        }
        'AzPwshSession' {
            $result = Get-AzAccessToken -ResourceUrl "https://storage.azure.com/" | Select-Object -ExpandProperty Token
        }
        'AzSPNFereation' {
            $Auth_uri = "https://login.microsoft.com/" + $TenantID + "/oauth2/v2.0/token"
            $Auth_body = @{
                grant_type            = "client_credentials"
                client_id             = $client_id
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion      = $Federated_Token
                scope                 = "https://storage.azure.com//.default openid profile offline_access"
            }
            $resp = Invoke-RestMethod -Method Post -Uri $Auth_uri -Body $Auth_body -ContentType "application/x-www-form-urlencoded"
            $result = $resp.access_token
        }
        Default {
            Write-Error "this I do not know..."
        }
        

    }

    return $(ConvertTo-SecureString $result -asplaintext -force)
}


function New-AzFilePermissionKey {
    <#
    .SYNOPSIS
    Creates a new permissionkey on the share level based on a SDDL String
    .DESCRIPTION
    creates a permission (a security descriptor) at the share level. You can use the created security descriptor for the files and directories in the share.
    .INPUTS
    None. You cannot pipe objects 
    .OUTPUTS
    System.String: x-ms-file-permission-key
    .EXAMPLE
    PS> New-AzFilePermissionKey -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -SDDL $Source_SDDL 
    9483042146253521759*10680507000892221844
    .LINK
    https://learn.microsoft.com/en-us/rest/api/storageservices/create-permission
    #>
    [CmdletBinding()]
    param (
        # access token for https://storage.azure.com/
        [Parameter(Mandatory)]
        [securestring]$access_token,
        # Target Storage Account name
        [Parameter(Mandatory)]
        [string]$StorageAccountName,
        # Share within the target Storage Account
        [Parameter(Mandatory)]
        [string]$ShareName,
        #SDDL String 
        [Parameter(Mandatory)]
        [string]$SDDL
    )
    
    $Uri = "https://" + $StorageAccountName + ".file.core.windows.net/" + $ShareName + "?restype=share&comp=filepermission"

    $header = @{
        "x-ms-command-name"        = "StorageClient.ListDirectoriesAndFiles222"
        "x-ms-file-request-intent" = "backup"
        "x-ms-version"             = "2022-11-02" 
    }
    
    $body = @{
        # Permission = "ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)"
        permission = $SDDL
    } | ConvertTo-Json
    
    $webresult = Invoke-RestMethod -Authentication Bearer -Token $access_token -ResponseHeadersVariable ResponseHeadersVariable -Method PUT -Body $body -Headers $header -Uri $Uri

    if ($ResponseHeadersVariable."x-ms-file-permission-key") {
        return $ResponseHeadersVariable."x-ms-file-permission-key"
    }
    else {
        $result = @{
            response = $webresult
            header   = $ResponseHeadersVariable
        }
        return $result
    }
}

function Get-AzFilePermissionKey {
    <#
    .SYNOPSIS
    Gets the SDDL String for a permission key on the share level
    .DESCRIPTION
    Gets the SDDL String for a permission key on the share level
    .INPUTS
    None. You cannot pipe objects 
    .OUTPUTS
    System.String: SDDL
    .EXAMPLE
    PS> Get-AzFilePermissionKey -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -permissionkey "9483042146253521759*10680507000892221844"
    O:S-1-5-21-2127521184-16.....
    .LINK
    https://learn.microsoft.com/en-us/rest/api/storageservices/get-permission
    #>
    [CmdletBinding()]
    param (
        # access token for https://storage.azure.com/
        [Parameter(Mandatory)]
        [securestring]$access_token,
        # Target Storage Account name
        [Parameter(Mandatory)]
        [string]$StorageAccountName,
        # Share within the target Storage Account
        [Parameter(Mandatory)]
        [string]$ShareName,
        # x-ms-file-permission-key / security descriptor
        [Parameter(Mandatory)]
        [string]$permissionkey
    )
    
    $Uri = "https://" + $StorageAccountName + ".file.core.windows.net/" + $ShareName + "?restype=share&comp=filepermission"

    $header = @{
        "x-ms-command-name"        = "StorageClient.ListDirectoriesAndFiles222"
        "x-ms-file-request-intent" = "backup"
        "x-ms-version"             = "2022-11-02" 
        "x-ms-file-permission-key" = $permissionkey
    }
    
    
    $webresult = Invoke-RestMethod -Authentication Bearer -Token $access_token -ResponseHeadersVariable ResponseHeadersVariable -Method Get -Body $body -Headers $header -Uri $Uri

    return $webresult.permission
}

function Get-AzFileDirectoryProperties {
    <#
    .SYNOPSIS
    returns all system properties for the specified directory
    .DESCRIPTION
    returns all system properties for the specified directory, and it can also be used to check the existence of a directory. The returned data doesn't include the files in the directory or any subdirectories.
    .INPUTS
    None. You cannot pipe objects 
    .OUTPUTS
    Dictonary: AzFileDirectoryProperties
    .EXAMPLE
    PS> Get-AzFileDirectoryProperties -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -Path ""
    Key                       Value
    ---                       -----
    ETag                      {"0x8DBF18ECB45E332"}
    Server                    {Windows-Azure-File/1.0, Microsoft-HTTPAPI/2.0}
    x-ms-request-id           {083b7de5-101a-008e-0678-234b80000000}
    x-ms-version              {2022-11-02}
    x-ms-server-encrypted     {true}
    x-ms-file-change-time     {2023-11-30T10:26:20.1062194Z}
    x-ms-file-last-write-time {2023-11-30T07:35:11.2122070Z}
    x-ms-file-creation-time   {2023-11-30T07:35:11.2122070Z}
    x-ms-file-permission-key  {13590250280325294639*10620508000892221444}
    x-ms-file-attributes      {Directory}
    x-ms-file-id              {9223407221226864640}
    x-ms-file-parent-id       {0}
    Date                      {Thu, 30 Nov 2023 10:32:29 GMT}
    Content-Length            {0}
    Last-Modified             {Thu, 30 Nov 2023 10:26:20 GMT}
    .LINK
    https://learn.microsoft.com/en-us/rest/api/storageservices/get-directory-properties
    #>
    [CmdletBinding()]
    param (
        # access token for https://storage.azure.com/
        [Parameter(Mandatory)]
        [securestring]$access_token,
        # Target Storage Account name
        [Parameter(Mandatory)]
        [string]$StorageAccountName,
        # Share within the target Storage Account
        [Parameter(Mandatory)]
        [string]$ShareName,
        # Full Path of the directory without trailing "/" e.g. "parentdir/subdir/something" 
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    $Uri = "https://" + $StorageAccountName + ".file.core.windows.net/" + $ShareName + "/" + $Path + "?restype=directory"

    $header = @{
        "x-ms-file-request-intent" = "backup"
        "x-ms-version"             = "2022-11-02" 
    }
    
    
    $null = Invoke-RestMethod -Authentication Bearer -Token $access_token -ResponseHeadersVariable ResponseHeadersVariable -Method Head -Body $body -Headers $header -Uri $Uri
    return $ResponseHeadersVariable
}

function Set-AzFileDirectoryProperties {
    <#
    .SYNOPSIS
    sets system properties for the specified directory
    .DESCRIPTION
    sets system properties for the specified directory
    .INPUTS
    None. You cannot pipe objects 
    .OUTPUTS
    Dictonary: AzFileDirectoryProperties
    .EXAMPLE
    PS> Set-AzFileDirectoryProperties -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -Path "" -x_ms_file_permission_key "13590250280325294639*10620508000892221444"
    Key                       Value
    ---                       -----
    ETag                      {"0x8DBF18ECB45E332"}
    Server                    {Windows-Azure-File/1.0, Microsoft-HTTPAPI/2.0}
    x-ms-request-id           {083b7de5-101a-008e-0678-234b80000000}
    x-ms-version              {2022-11-02}
    x-ms-server-encrypted     {true}
    x-ms-file-change-time     {2023-11-30T10:26:20.1062194Z}
    x-ms-file-last-write-time {2023-11-30T07:35:11.2122070Z}
    x-ms-file-creation-time   {2023-11-30T07:35:11.2122070Z}
    x-ms-file-permission-key  {13590250280325294639*10620508000892221444}
    x-ms-file-attributes      {Directory}
    x-ms-file-id              {9223407221226864640}
    x-ms-file-parent-id       {0}
    Date                      {Thu, 30 Nov 2023 10:32:29 GMT}
    Content-Length            {0}
    Last-Modified             {Thu, 30 Nov 2023 10:26:20 GMT}
    .LINK
    https://learn.microsoft.com/en-us/rest/api/storageservices/set-directory-properties
    #>
    [CmdletBinding()]
    param (
        # access token for https://storage.azure.com/
        [Parameter(Mandatory)]
        [securestring]$access_token,
        # Target Storage Account name
        [Parameter(Mandatory)]
        [string]$StorageAccountName,
        # Share within the target Storage Account
        [Parameter(Mandatory)]
        [string]$ShareName,
        # Full Path of the directory without trailing "/" e.g. "parentdir/subdir/something" 
        [Parameter(Mandatory)]
        [string]$Path,
        # Permissionkey gathered from Get/New-AzFilePermissionKey
        [Parameter(Mandatory)]
        [string]$x_ms_file_permission_key
    )
    
    $Uri = "https://" + $StorageAccountName + ".file.core.windows.net/" + $ShareName + "/" + $Path + "?restype=directory&comp=properties"

    $header = @{
        "x-ms-file-request-intent" = "backup"
        "x-ms-version"             = "2022-11-02" 
        "x-ms-file-permission-key" = $x_ms_file_permission_key
    }
    
    $null = Invoke-RestMethod -Authentication Bearer -Token $access_token -ResponseHeadersVariable ResponseHeadersVariable -Method Put -Body $body -Headers $header -Uri $Uri
    return $ResponseHeadersVariable
}

$StorageAccount_Name = "somestorageaccount"
$ShareName = "profiles"
$SourceDir = "permissionsource"
$TargetDir = "permissiontarget"

$access_token = $Source_AzFileDirectoryProperties = $Source_SDDL = $Target_Permissionkey = $target_AzFileDirectoryProperties = $Target_SDDL = $null

$access_token = Get-AzAccessToken_forStorage -AzPwshSession

$Source_AzFileDirectoryProperties = Get-AzFileDirectoryProperties -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -Path $SourceDir
$Source_SDDL = Get-AzFilePermissionKey -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -permissionkey $($Source_AzFileDirectoryProperties["x-ms-file-permission-key"])

$Target_Permissionkey = New-AzFilePermissionKey -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -SDDL $Source_SDDL 
$target_AzFileDirectoryProperties = Set-AzFileDirectoryProperties -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -Path $TargetDir -x_ms_file_permission_key $Target_Permissionkey

$Target_SDDL = Get-AzFilePermissionKey -StorageAccountName $StorageAccount_Name -ShareName $ShareName -access_token $access_token -permissionkey $($target_AzFileDirectoryProperties["x-ms-file-permission-key"])

$Source_SDDL
$Target_SDDL