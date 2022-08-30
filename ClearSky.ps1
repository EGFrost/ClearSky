# https://docs.microsoft.com/de-de/azure/active-directory/fundamentals/users-default-permissions <- def. Perm.

function Get-AzureGraphToken
{
    $APSUser = Get-AzContext *>&1 
    $resource = "https://graph.microsoft.com"
    $Token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
    $Headers = @{}
    $Headers.Add("Authorization","Bearer"+ " " + "$($token)")
    $Headers
}

function Get-TenantID {
    Write-Host "Getting small overview over Tenant" -ForegroundColor black -BackgroundColor White 
    $TenantObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/organization'
    $Tenant = $TenantObj.value
    $global:TenantId = $Tenant.id

    try{
    $HeadersWithConsistencyLevel = $Headers
    $HeadersWithConsistencyLevel.Add('ConsistencyLevel','eventual')
    }catch{

    }
    #Get UserCount:
    $UserCount =  Invoke-RestMethod -Headers $HeadersWithConsistencyLevel -Uri "https://graph.microsoft.com/v1.0/users/`$count"
    #Get GroupCount:
    $GroupCount =  Invoke-RestMethod -Headers $HeadersWithConsistencyLevel -Uri "https://graph.microsoft.com/v1.0/groups/`$count"
    #Get SyncStatus:
   
    $SyncState =  Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/organization"
    
   <# if("" -eq $SyncState.value.onPremisesSyncEnabled){
        Write-Host "FALSE"
    }#>


    Write-Host "Tenant-ID is: ${TenantId}"  -ForegroundColor Green 
    Write-Host "Tenant Name is :" $SyncState.value.displayName -ForegroundColor Green
    Write-Host "Usercount: " $UserCount     -ForegroundColor Green 
    Write-Host "Groups: " $GroupCount       -ForegroundColor Green 


    Write-Host "Number of Assigned Roles: " $global:RoleCount "(Only available in non-transitive mode)"    -ForegroundColor Green 
    $SyncEnabled
    if($SyncState.value.onPremisesSyncEnabled){
        $SyncEnabled = "True"
    }else{
         $SyncEnabled = "False"
    }
    Write-Host "AD-Sync enabled :" $SyncEnabled `n -ForegroundColor Green
}




function Get-UserList($transitive){  #standard are the first 100, but this gets all users.

    $UserExport = @()

    Write-Host "Getting List of all Users" -ForegroundColor Cyan

  #  $MFAObject = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails'
  #  Write-Host $MFA.value -ForegroundColor Red -BackgroundColor Green

    
    $UserListObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName,onPremisesSamAccountName,id,jobTitle'



    #Last SignIn only with BETA APi, So we use /beta/ and not /V1.0/ PROBLEM: Rights>Admin needed .... https://docs.microsoft.com/en-us/graph/api/user-list?view=graph-rest-beta&tabs=http#example-5-list-the-last-sign-in-time-of-users-in-a-specific-time-range
    
    
    $UserList = $UserListObj.value 
    $UList = $UserList.displayName 
    # Write-Host $UserList
    # $UserList.Id
    $nextList = $UserListObj.'@odata.nextLink'
    $ALLMembers = $null
    If($UserListObj.'@odata.nextLink'){
     Write-Host "It contains more Users, Wait a Second while i'm getting them all...." -ForegroundColor Cyan
 
     $ALLMembers += Get-AddMembers($nextList)
 
    }
 
     Write-Host "Building User Objects" -ForegroundColor Green
    $AllMembers += $UserListObj.value
     #Ausgabe der Nutzerliste
    # Write-Host $AllMembers

        $HeaderForTransitiveRoles = $Headers
        try{
        $HeaderForTransitiveRoles.Add('ConsistencyLevel','eventual')
        }catch{

        }

     foreach($User in $AllMembers){    

#Get transitive Role Assignments: (Roles only display direct Members!) API STILL IN BETA - LOTS OF REQUESTS TO DO ONLY IF NEEDED!


    if($transitive){
        $UserID = $User.id
        $UserRoleListObj = Invoke-RestMethod -Headers $HeaderForTransitiveRoles -Uri "https://graph.microsoft.com/beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=principalId eq '$UserID'"
       # Write-Host $HeaderForTransitiveRoles

        # Get ALL Rolenames

        $AllUserRoles = @()

        foreach( $RoledefinitionID in $UserRoleListObj.value.roleDefinitionId){

            
            $oneRole
            #Get Rolenames
            try{
                $RoleName =  Invoke-RestMethod -Headers $Headers "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$RoledefinitionID"
                $oneRole = $RoleName.displayName
                
            }catch{
                $oneRole = $RoledefinitionID
            }
            #Get RoleName:
            $AllUserRoles += $oneRole
            $oneRole = $null  
            
        }

    }else{
        $AllUserRoles = "Not Evaluated"
    }

        if($cli){
            Write-Host $User.displayName - $User.id - $User.userPrincipalName  "OnPremName: " $User.onPremisesSamAccountName  "Job: " $User.jobTitle  "Roles: " $AllRoles -ForegroundColor White 
        }
        #Write-Host $user
        $OnPremCheck = "No OnPrem"
         if($User.onPremisesSamAccountName){
            $onPremCheck = $User.onPremisesSamAccountName
         }
         $UserExport +=[PSCustomObject]@{
            Displayname = $User.displayName
            UserPrincipalName = $User.userPrincipalName
            OnPremisesSecurityIdentifier = $OnPremCheck
            JobTitle = $User.jobTitle
            Roles = $AllUserRoles

        }

       
     }    
    Write-Host "All Users got Builded, Starting Export" -ForegroundColor Green



   # Denied
   #$MFAList = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails"
   #Write-Host $MFAList.value



    #Export JSON:
    if(!$NoJSON){
        $UserExport | ConvertTo-Json | Out-File .\JSONExports\Users.json -Append   
    }


     #CSV export, Roles to String -> Else only System.Object[]:
    if(!$NoCSV){
        foreach($UserExportPerson in $UserExport){
            $UserExportPerson.Roles = [system.String]::Join(" ", $UserExportPerson.Roles)
        }
    
    

        try{
                $UserExport | Export-Csv .\CSVExports\UserExport.csv -NoTypeInformation
        }catch{
                Write-Host "CSV couldnt be created" -ForegroundColor Red
        }
    }

    if(!$NoJSON -or !$NoCSV){
        Write-Host "User Export Done!" -ForegroundColor Green 
    }

}

function Get-AddMembers([string]$Link){  #rekursiv - bis alle Mitglieder gefunden wurden

    Write-Host "It contains even more Data! Wait a Second while i'm getting it all...." -ForegroundColor Cyan
    $Fulllist = Invoke-RestMethod -Headers $Headers -Uri $Link
  # Write-Host $Fulllist
   
   If($Fulllist.'@odata.nextLink'){
        $NextLink = $Fulllist.'@odata.nextLink'
       # Write-Host $NextLink -ForegroundColor Cyan
        Get-AddMembers($NextLink)
   }
    return($Fulllist.value) 
}


function Get-Groups{

    $GroupExport = @()

    Write-Host `n"Getting List of all Groups with their Members" `n -ForegroundColor Cyan 
    $GroupListObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/v1.0/groups'   
    $GroupList = $GroupListObj.value

 

    #Print out All Groups
    #Write-Host $GList.displayName `n
   # Write-Host "Getting Group Members" `n

    $GroupIds = $GroupList

    
    $i = 0
    foreach($GID in $GroupList.id){
        $GroupMembersObj =  Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/groups/$GID/members"
         $GroupOwnersObj =  Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/groups/$GID/owners"

        $GroupMembers = $GroupMembersObj.value
        $GroupOwner = $GroupOwnersObj.value

        if($cli){
            Write-Host $GroupList.displayName[$i]  -ForegroundColor Yellow
            Write-Host $GroupMembers.displayName 
        }
        
        [string]$CombinedOwners =$null

        foreach($OwnerName in $GroupOwner.displayName){
            $CombinedOwners = $CombinedOwners + " "+ $OwnerName
        }

        if($CombinedOwners){
            if($cli){
                Write-Host Owners: $CombinedOwners -ForegroundColor Green
            }
        } 
        if($CombinedOwners){
            $CheckedOwner = $CombinedOwners
        }else{
            $CheckedOwner = "No Owner"
        }

        foreach($MemberName in $GroupMembers.displayName){

            $GroupExport +=[PSCustomObject]@{
            Groupname = $GroupList.displayName[$i]
            Member = $MemberName
            Owner = $CheckedOwner
            }
        }
        Write-Host `n
    $i++    
    }
    $i=0 #reset i

    ####EXPORT CSV AND JSON
    if(!$NoCSV){
        $GroupExport | Export-Csv .\CSVExports\Groups.csv -NoTypeInformation
    }
    if(!$NoJSON){
        $GroupExport | ConvertTo-Json | Out-File .\JSONExports\Groups.json -Append   
    }
}


function Get-AzADRoles{ #ServicePricipals are Missing?!
  
   
    #729827e3-9c14-49f7-bb1b-9608f156bbb8 <- HelpDeskID   $expand=roleDefinition <- for definition/Roles

    $RoleExport = @()

   Write-Host `n
    Write-Host "Trying to get Identitys with Roles Attached" -ForegroundColor Cyan 
 


    try{  #Nameresolve isnt working for Customroles... 

        
        $AllIdentitysWithRoles= Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal"
    
        $RoledefIDs = $AllIdentitysWithRoles.value.roleDefinitionId
 
        $i = 0
        $k=0
        $l = 0
        $RoleNameVal = $null
        $RoleNameValOld = $null
        $RoleIDBackup = $null
        #https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$filter=DisplayName eq 'Conditional Access Administrator'&$select=rolePermissions <- To get Permissions 
        
          foreach($RoleDefID in $RoleDefIDs){
            try{
                $RoleNameObj= Invoke-RestMethod -Headers $Headers "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$RoledefID"
          
            }catch{
                $RoleIDBackup = $RoleDefID
            }

            if($null -eq $RoleIDBackup){   #If Backup is not Needed:
                $RoleNameVal = $RoleNameObj.displayName
            }else{                          #if Backup is needed - Rolename not found, Take it as name & reset Backup
                $RoleNameVal = $RoleIDBackup
                $RoleIDBackup = $null 
            }

            if($RoleNameValOld -eq $null){
                    $i = $AllIdentitysWithRoles.value.roleDefinitionId.IndexOf($RoleDefID)
                    if($cli){
                        Write-Host $RoleNameVal -ForegroundColor Yellow
                        Write-Host $AllIdentitysWithRoles.value.principal.displayName[$i] <# "UPN: "$AllIdentitysWithRoles.value.principal.userPrincipalName[$i]#> -ForegroundColor Green
                    }

                    $RoleExport  +=[PSCustomObject]@{
                        RoleName = $RoleNameVal
                        Member = $AllIdentitysWithRoles.value.principal.displayName[$i]
                    }

                    $RoleNameValOld = $RoleNameVal
                    $global:RoleCount++
                    
            }
            elseif($RoleNameValOld -eq $RoleNameVal){      #if Role is the same, only add a member & Count up
                    $k++
                    if($cli){
                        Write-Host $AllIdentitysWithRoles.value.principal.displayName[$i + $k] -ForegroundColor Green
                    }

                    $RoleExport[$RoleExport.Length-1].Member += ", "+ $AllIdentitysWithRoles.value.principal.displayName[$i + $k]

            }else{ # if its not the same Rolename or lvl 1-> Write Rolename as well!
                    
                    $i = $AllIdentitysWithRoles.value.roleDefinitionId.IndexOf($RoleDefID)
                    if($cli){
                        Write-Host `n
                        Write-Host $RoleNameVal -ForegroundColor Yellow
                        Write-Host $AllIdentitysWithRoles.value.principal.displayName[$i] -ForegroundColor Green
                    }

                    $RoleExport  +=[PSCustomObject]@{
                        RoleName = $RoleNameVal
                        Member = $AllIdentitysWithRoles.value.principal.displayName[$i]
                    }

                    $RoleNameValOld = $RoleNameVal
                    $global:RoleCount++
                    $k = 0 #reset k
                        
                }
            }
       
        $RoleNameVal = $RoleNameObj.displayName #update Name after iteration to check it in the next
        

        
       # Write-Host $RoleExport -ForegroundColor Red
        
    
        }catch{  #if rights for other options arent given or Other Errors occur, fall to this backupplan:
            Write-Host "Error while trying to get all Roles" -ForegroundColor Red
            Write-Host "Starting Backupplan! - CLI only" -ForegroundColor Cyan

                $AllRolesObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'
                $AllRoles = $AllRolesObj.value
                $AllRolesID = $AllRolesObj.value.id


                $i =0
                foreach($ADID in $AllRolesID){
                    
                    $AllRoleMembers = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$ADID/members"
                    if($AllRoleMembers.value.displayName -ne $null){
                        if($cli -or $true){
                            Write-Host $AllRoles[$i].displayName    

                            $RoleExport  +=[PSCustomObject]@{
                                RoleName = $AllRoles[$i].displayName 
                                Member = $null
                            }
                            Write-Host $RoleExport

                            foreach($User in $AllRoleMembers.value.displayName){
                                Write-Host $User -ForegroundColor Green
                                Write-Host $RoleExport
                                Write-Host $i -BackgroundColor White -ForegroundColor black
                            }
                            Write-Host `n
                        }
                    }
                    $i++
                }
                $i = 0

                Write-Host $RoleExport
            } 


        #Export JSON:
            if(!$NoJSON){
                $RoleExport | ConvertTo-Json | Out-File .\JSONExports\Roles.json -Append   
            }


            if(!$NoCSV){
                try{
                        $RoleExport | Export-Csv .\CSVExports\Roles.csv -NoTypeInformation
                }catch{
                        Write-Host "CSV couldnt be created" -ForegroundColor Red
                }
            }

            if(!$NoJSON -or !$NoCSV){
                Write-Host "Role Export Done!" -ForegroundColor Green 
            }

   }

            


function Get-AllDevices{ 

    $DeviceExport = @()
    Write-Host `n
    Write-Host "Getting all Devices" -ForegroundColor Cyan
    $DevicesObj = Invoke-RestMethod -Headers $Headers -Uri 'https://graph.microsoft.com/v1.0/devices'
    $FirstDevices = $DevicesObj.value
    $AllDevices = $null
    $nextDevices = $DevicesObj.'@odata.nextLink'
    if($nextDevices){
            Write-Host "GETTING MORE DEVICES!" -ForegroundColor Red -BackgroundColor Green
            $ALLDevices += Get-AddMembers($nextDevices)
    }

    $AllDevices += $FirstDevices
  #  Write-Host $AllDevices
    

    foreach($DName in $ALLDevices){

        $DeviceID = $DName.id
        $DeviceUsers = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/devices/$DeviceID/registeredUsers"
      #  Write-Host $DeviceUsers.value.displayName


       if($cli){
            Write-Host $DName.displayName -ForegroundColor Yellow
            Write-Host User: $DeviceUsers.value.displayName `nOS: $DName.operatingSystem `nManagedstatus: $DName.isManaged `n
       }
        $DeviceExport +=[PSCustomObject]@{
            id = $DName.displayName
            User = $DeviceUsers.value.displayName
            OS = $DName.operatingSystem
            Managedstatus = $DName.isManaged
            LastLogin = $DName.approximateLastSignInDateTime
            
         }
    }

    ###Create CSV and JSON ###
    if(!$NoCSV){
        $DeviceExport | Export-Csv .\CSVExports\Devices.csv -NoTypeInformation
    }
    if(!$NoJSON){
        $DeviceExport | ConvertTo-Json | Out-File .\JSONExports\Devices.json -Append 
    }

   # Write-Host $DeviceExport
    #TODO: Managedstatus needed?
}






function Get-Me{    #NEED TO UPGRADE TO TRANSITIVE ASSIGNEMENTS!
    Write-Host `n
    Write-Host "Overview over current Account" -ForegroundColor Black -BackgroundColor White

    $ME = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me"        # Get Infos for current Account
	$UPN = $Me.id
	
	$ME2 = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me?`$select=onPremisesSamAccountName"
	
#	Write-Host $ME2
	
	if($ME2.onPremisesSamAccountName){
	
		Write-Host "Name: " $ME.displayName `n "UPN: " $ME.userPrincipalName `n "Local-Name: " $ME2.onPremisesSamAccountName `n  -ForegroundColor Green
	
	}
	else{
		Write-Host "Name: " $ME.displayName `n "UPN: " $ME.userPrincipalName `n  -ForegroundColor Green
	}
    $MEID = $ME.id 
   
   $MyGroups = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me/memberOf" # Listet Gruppen und Rollen
  
   $Groups =@()
   $Roles =@()

   foreach($Group in $MyGroups.value){
        if( $Group.roleTemplateId -eq $null){
            $Groups += $Group.displayName
        }else{
            $Roles += $Group.displayName
        }
    }
    Write-Host "Your Groups:" -ForegroundColor Yellow

    foreach($GroupName in $Groups){
        Write-Host $GroupName -ForegroundColor Green
    }
    Write-Host `n"Your Roles:" -ForegroundColor Yellow

    foreach($Role in $Roles){
        Write-Host $Role -ForegroundColor Green
    }

    Write-Host `n
    $MyItemsOwned = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me/ownedObjects"
    #Write-Host $MyItemsOwned.value

    Write-Host Owner of: -ForegroundColor Yellow

    foreach($OwnedObject in $MyItemsOwned.value){
        Write-Host $OwnedObject.displayName
    }
    Write-Host `n 
}


function ZipAndClean{
   #Zippen -Force zum ueberschreiben!
   Compress-Archive -Path .\JSONExports\*.json -CompressionLevel "Fastest" -DestinationPath .\JSON -Force
   Compress-Archive -Path .\CSVExports\*.csv -CompressionLevel "Fastest" -DestinationPath .\CSV -Force
   #Remove Tempfiles:
   Remove-Item -Path .\JSONExports -Recurse
   Remove-Item -Path .\CSVExports -Recurse
}



#############################################################################################################################
#############################################################################################################################
##############################################################################################################################
#####################################                                ###############################################################
#####################################          ENUM                 ############################################################
#####################################                               #############################################################
#################################################################################################################################
#########################################################################################################################

function Invoke-ClearSky{
    param(
    [Parameter()]
    [switch]$Transitive,
    [Parameter()]
    [switch]$ExtraRoles,
    [Parameter()]
    [switch]$Help,
    [Parameter()]
    [switch]$NoCSV,
    [Parameter()]
    [switch]$NoJSON,
    [Parameter()]
    [switch]$cli
    )


 
 
 
  if($Help){
    Show-Help
    Break Script
  }
  try{
   $UserLoggedIn = Get-AzContext
  }catch{
    Write-Host "Az-Module not found..."
    Write-Host "Please install the Az PowerShellmodule!"
    Write-Host "Use Install-Module Az"
    Break Script
  }
    if($UserLoggedIn -eq $null){
        Write-Host "Please Login"
        Connect-AzAccount
        $UserLoggedIn = Get-AzContext
        #recheck if login worked:
        if($UserLoggedIn -eq $null){
            Break Script
        }

    }else{
     # Write-Host "Already Logged in => proceeding!" `n
    }
        
    $Headers = Get-AzureGraphToken    
    $global:RoleCount = 0   

#Create Exportdirectorys:
if(!$NoJSON){
    if(!(Test-Path -Path .\JSONExports)){
        New-Item -Path .\JSONExports -ItemType Directory | Out-Null
    }else{
        #Backup-Clear
        Remove-Item -Path .\JSONExports -Recurse
        New-Item -Path .\JSONExports -ItemType Directory | Out-Null
    }
}
if(!$NoCSV){
    if(!(Test-Path -Path .\CSVExports)){
        New-Item -Path .\CSVExports -ItemType Directory | Out-Null
    }else{
        #Backup-Clear
        Remove-Item -Path .\CSVExports -Recurse
        New-Item -Path .\CSVExports -ItemType Directory | Out-Null
    }
}

Get-UserList($Transitive)  #Builds a big object with all Groupd & Roles
Get-Groups

if(($Transitive -and $ExtraRoles) -or !($Transitive)){
    Get-AzADRoles 
}
Get-AllDevices
Get-Me
Get-TenantID

if(!($NoCSV) -and !($NoJSON)){
    Write-Host 'Zipping Files and Cleaning up!'
    Write-Host `n`n
    ZipAndClean
} 
Write-Host "All done! Have Fun!"  -ForegroundColor Cyan 
}




function Show-Help{
    Write-Host `n
    Write-Host "Invoke-ClearSky" -ForegroundColor Green
    Write-Host `t "Get normal overview as CSV and JSON - Exports => no Params!" -ForegroundColor Yellow
    Write-Host `t "-Transitive  =>  Get full transitive Roles in Users but NO extra Roleobject" -ForegroundColor Yellow
    Write-Host `t "-Transitive -ExtraRoles  => Get transitive Roles in Users AND Roleobject" -ForegroundColor Yellow
    Write-Host `t "-cli  =>  Get CLI Output" -ForegroundColor Yellow
    Write-Host `t "-NoCSV  =>  No CSV-Export" -ForegroundColor Yellow
    Write-Host `t "-NoJSON  =>  No JSON-Export" -ForegroundColor Yellow
    Write-Host `n`n

    Write-Host "To Validate a List of possible Users:" -ForegroundColor Green
    Write-Host `t "Get-Content <UserFile.txt> | Get-ValidUsers"
    Write-Host `n`n

    Write-Host "To Create a List of possile Users:" -ForegroundColor Green
    Write-Host `t 'Create-UserList -NamesPart1 ".\Names1.txt"  -NamesPart2 ".\Names2.txt" -Domainname "Domain.xyz" -Link "." '
    #Write-Host `t`t "Link is the connector between Names1 and Names2"
    Write-Host `t " Names and the Link are optional Params" -ForegroundColor Yellow
    Write-Host `n`n

}













#############################################################################################################################
#############################################################################################################################
##############################################################################################################################
#####################################                                ###############################################################
#####################################          Get-Valid Users      ############################################################
#####################################                               #############################################################
#################################################################################################################################
#########################################################################################################################



function Get-ValidUsers{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline)]
        [String]$UserName  
    )
    Process
    {
        $validUsers = @()

            $exists= Request -UserName $UserName 
            if($exists){ 
                $validUsers += $UserName
            }

        #create File with all valid users
        if(!(Test-Path -Path ValidUsers.txt)){
        New-Item -Path . -Name "ValidUsers.txt" -ItemType "file" #| Out-Null
        }

        $validUsers | Out-File -Append .\ValidUsers.txt 

   # Write-Host "Valid User added to -\ValidUsers.txt"

    }
    
}

function Request{


    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$UserName
    )
    Process
    {
        # Create a body for REST API request
        $body = @{
            "username"=$UserName
        }
    
        # Call the API
        $userRequest=Invoke-RestMethod -UseBasicParsing -Uri ("https://login.microsoftonline.com/common/GetCredentialType") -ContentType "application/json; charset=UTF-8" -Method POST -Body ($body|ConvertTo-Json)

        $exists = $false
        if($userRequest.ThrottleStatus -eq 1)
        {
            Write-Warning "Requests throttled!"
            Remove-Variable exists
        }
        else
        {
            $exists = $userRequest.IfExistsResult -eq 0 -or $userRequest.IfExistsResult -eq 6
        }
        $exists
    }
}


#############################################################################################################################
#############################################################################################################################
##############################################################################################################################
#####################################                                ###############################################################
#####################################          Create-UserList      ############################################################
#####################################                               #############################################################
#################################################################################################################################
#########################################################################################################################


function Create-UserList{

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$NamesPart1,
        [Parameter()]
        [String]$NamesPart2,
        [Parameter(Mandatory=$True)]
        [String]$Domainname,
        [Parameter()]
        [String]$link,
        [Parameter()]
        [String]$Outname
        
    )

    if(!$Outname){
        $Outname = ".\Liste.txt"
    }


    $VN = Get-Content -Path $NamesPart1
    $NN = Get-Content -Path $NamesPart2
    


    New-Item -Path ".\" -Name $Outname -ItemType File 

    foreach($name in $VN){
        foreach($nachname in $NN){
            
            Add-Content .\$Outname $name+$Link+$nachname'@'$Domainname

        }

    }

}