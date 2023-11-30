# Az FileRest

[Azure Files REST API](https://learn.microsoft.com/en-us/rest/api/storageservices/file-service-rest-api) 

Consider:
- Data plane operations require different roles and permissions 
    -[Storage File Data SMB Share Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage-file-data-smb-share-contributor) to enable mounting the share
    -[Storage File Data SMB Share Elevated Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage-file-data-smb-share-contributor) to mount with modify permissions permissions
    -[Storage File Data Privileged Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage-file-data-privileged-contributor) to enable priviliged operations through the Rest API, this is NOT SMB


## Copy-PremissionDir2Dir_Azfilerest.ps1
Example Script to showcase how to utilize [Azure Files REST API](https://learn.microsoft.com/en-us/rest/api/storageservices/file-service-rest-api) to copy permissions from one directory to another.\
Intention is to enable automation scenarios to NOT need to mount an Az Files SMB Store to set permissions, e.g. provisioning FSLogix shares with ADDS Auth for AVD.

Requirements
- network line of sight to the storage account, also in private endpoint scenarios
- network requirements met for AAD Auth
- The SPN / User executing the script needs [Storage File Data Privileged Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage-file-data-privileged-contributor) role assigned