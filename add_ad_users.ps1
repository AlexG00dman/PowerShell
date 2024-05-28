#PowerShell
#Script for restore old ad_users (students) to ad ver 0.59 bug fixed
#Запускать с edu_dom 
#csv_students_source
$csv = Import-Csv "C:\temp\new070524.csv" -Delimiter ';' -Encoding UTF8
#ad_server
$ad_server="edudom"
#root_directory_network_storage
$init_dir = "\\edu.edudom\students$"
#institutes 
$inst_list = "ЭН", "ИнMЭТ", "ММТ", "ТИ", "УMС", "ИНТ", "ИНП"
#ad_units
$ou_users = "CN=Users,DC=edudom"
$ou_deleted = "OU=Удалённые,DC=edudom"
$ou_inpit = "OU=App-EDU,DC=edudom"
$ou_sei = "OU=OU-Users,OU=SE-EDU,DC=edudom"



function create_new_user {
    param (
        [string]$stud_id,
        [string]$full_name,
        [string]$description,
	    [string]$pass
    )     
    $Password = ConvertTo-SecureString $pass -AsPlainText -Force
    New-ADUser -server $ad_server -Name $stud_id -SamAccountName $stud_id -DisplayName $full_name -AccountPassword $Password -ChangePasswordAtLogon $true -Description $Description -Enabled $true -Path $ou_users
    create_folder -stud_id $stud_id -home_dir $home_dir
    set_homedrive_link -stud_id $stud_id -home_dir $home_dir
    set_acl -stud_id $stud_id -home_dir $home_dir



    move_user_to_container -stud_id $stud_id

    adduser_to_inst_group
    adduser_to_stud_group
             
    Write-Output "user with number: $stud_number and name: $full_name added to ad successfully"
}


function restore_user {
    param (
         
        [string]$stud_id,
        [string]$full_name,
        [string]$description,
	    [string]$pass,
        [string]$home_dir
    )
    $ad_user_desc = Get-ADUser -Server $ad_server -Identity $stud_id -Properties Description | Select-Object Description 

    #check profile on correct discription
    if ($description -ne $ad_user_desc) { 
        move_folder -stud_id $stud_id -home_dir $home_dir
        move_user_to_container -stud_id $stud_id
        clear_groups -stud_id $stud_id
        adduser_to_inst_group
        adduser_to_stud_group


        set_new_status -stud_id $stud_id -description $description -pass $pass
        #Write-Output "debug 02"
    }   else {
        Write-host "$stud_id 'is ok' skipped ..." -ForegroundColor Red


    }
}



function set_homedrive_link{
    param ([string]$stud_id, [string]$home_dir)
    Set-ADUser -server $ad_server -Identity $stud_id -HomeDirectory $home_dir -HomeDrive 'Z:'
    Write-Output "$stud_id link ok"
}
  
####create_home_dir_
function create_folder {
#check directory empty or not
 param ([string]$home_dir) 
    if (!(Test-Path $home_dir)) {
        New-Item -ItemType Directory -Path $home_dir
        Write-Output "folder $home_dir has been created"
    } else {
        Write-Output "$home_dir exists yet"
    }
}



####set acl for user forlder
function set_acl(){
param ([string]$stud_id,[string]$home_dir)

$acl = Get-Acl -Path $home_dir
$new = "$ad_server\$stud_id","Modify","ContainerInherit,ObjectInherit","None","Allow"

$accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $new
$acl.SetAccessRule($accessRule)
Set-Acl -Path $home_dir -AclObject $acl
Write-output "$stud_id acl ok"
}



function move_folder{
    param ([string]$stud_id, [string]$home_dir)   
    $ad_home_dir = $(Get-ADUser -Identity $stud_id -Server $ad_server -Properties HomeDirectory | Select-Object -ExpandProperty HomeDirectory)
    
    #if ad_home is empty
    if ([string]::IsNullOrEmpty($ad_home_dir)){
            create_folder -home_dir $home_dir
    }
    #if ad_home != home_dir
    elseif ($ad_home_dir.ToString().trim() -ne $home_dir){
        if (Test-Path $ad_home_dir){
            #### Write-Output "$ad_home_dir status 0" debug # #create
            Move-Item $ad_home_dir -Destination $home_dir -Force 
            Write-host "folder $stud_id moved socessfully"
        } else {
            create_folder -home_dir $home_dir
        }
    }
    #if ad_home == home_dir
    elseif ($ad_home_dir.ToString().trim() -eq $home_dir) {
        if (!(Test-Path $home_dir)){
            create_folder -home_dir $home_dir
        }
        else {
            Write-Output "folder of $stud_id is on correct way :D"
        }
    }

    set_acl -stud_id $stud_id -home_dir $home_dir
    set_homedrive_link -stud_id $stud_id -home_dir $home_dir
}



#delete user from all not system groups
function clear_groups (){
    param ([string]$stud_id)
    $groups = Get-ADPrincipalGroupMembership -server $ad_server -Identity $Aduser.sAMAccountName | Where-Object {($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-513")-and ($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-47544")}
    if  (0 -eq  $groups.Count) {
        Write-host "user: $stud_id have only system groups" -ForegroundColor Red 
      
    } else {
    foreach ($stud_group in $groups){
     try{
       Remove-ADGroupMember -server $ad_server -identity $stud_group -Members $Aduser.sAMAccountName -Confirm:$false 
       Write-Output "user: $stud_id removed from $stud_group"
	}catch{
       Write-Output "something happened ... :D"  
    }
  }
}
}



#check existence users in group of SSTU University
function adduser_to_univer_group(){
    $stud_id = $($row.number)
      
    try {
        $Result = Get-ADGroup -Identity "sstu_students" -Server $ad_server
        if ($null -ne $Result) {                       
            $instUsers = Get-ADGroupMember -Server $ad_server -Identity $inst -Recursive | Select-Object -ExpandProperty Name
            if ($instUsers -contains $stud_id) {
                Write-Host "$stud_id member of $inst"
            } else {
                Add-ADGroupMember -Server $ad_server -Identity $inst -Members $stud_id
                Write-Output "$stud_id added in the $inst"
            }
        }
    } catch {
      Write-Host "$Inst Group does not exist." -ForegroundColor Red
    }
}



#check existence user in Institute's groups 
function adduser_to_inst_group(){
    $stud_id = $($row.number)
    $part_one = $($row.description.Split(' ')[0])
    $inst = $part_one + "-студенты"
  
    try {
        $Result = Get-ADGroup -Identity $inst -Server $ad_server
        if ($null -ne $Result) {                       
            $instUsers = Get-ADGroupMember -Server $ad_server -Identity $inst -Recursive | Select-Object -ExpandProperty Name
            if ($instUsers -contains $stud_id) {
                Write-Host "user: $stud_id member of $inst"
            } else {
                Add-ADGroupMember -Server $ad_server -Identity $inst -Members $stud_id
                Write-Output "user: $stud_id added to the $inst"
            }
        }
    } catch {
      Write-Host "$Inst Group does not exist." -ForegroundColor Red
    }
}



# check users exist in stud_group or not
function adduser_to_stud_group(){
    $stud_id = $($row.number)
    $inst_abbr = $($row.description.Split(' ')[0])
    $group_name = $($row.description.Split(' ')[1])
    $eduform = $($row.edu_form_pref)
    $str_group = $eduform + $inst_abbr + "_" + $group_name.Replace("-", "_")
  
    try {
        $Result = Get-ADGroup -Identity $str_group -Server $ad_server
        if ($null -ne $Result) {                       
            $groupUsers = Get-ADGroupMember -Server $ad_server -Identity $str_group -Recursive | Select-Object -ExpandProperty Name
            if ($groupUsers -contains $stud_id) {
                Write-Host "user: $stud_id member of $str_group"
            } else {
                Add-ADGroupMember -Server $ad_server -Identity $str_group -Members $stud_id
                Write-Output "user: $stud_id added in the $str_group"
            }
        }
    } catch {
        Write-Host "$str_group Group does not exist." -ForegroundColor Red
    }
}



#move user to container 'users'
function move_user_to_container(){
param ([string]$stud_id)
    
    $Aduser = Get-ADUser -Identity $stud_id -Server $ad_server
     
        if ($Aduser.DistinguishedName.Contains("$ou_deleted")) {
            Write-Output "user: $stud_id have container 'OU=Удалённые'"
            Move-ADObject -Server $ad_server -Identity:$Aduser.DistinguishedName -TargetPath: $ou_users
        } else {       
           Write-Output "user: $stud_id have container 'Users'"
           move_user_to_inst_container -stud_id $stud_id
        }
}





#move user to inst aproptiate inst container
function move_user_to_inst_container() {
    $inst = $($row.description.Split(' ')[0])
    $Aduser = Get-ADUser -Identity $row.number -Server $ad_server
    #Write-Output "$stud_id"
    if ($inst -eq $inst_list[6]) {
        if ($Aduser.DistinguishedName.Contains("$ou_inpit")) {
            Write-Output "user: $stud_id have container $ou_inpit yet"
        } else {
            Move-ADObject -Server $ad_server -Identity:$Aduser.DistinguishedName -TargetPath: $ou_inpit
            Write-Output "user: $stud_id moved to container $ou_inpit"
        }
    } elseif ($inst -eq $inst_list[5]) {
        if ($Aduser.DistinguishedName.Contains($ou_sei)) {
            Write-Output "user: $stud_id have container 'EI-EDU' yet"
        } else {
            Move-ADObject -Server $ad_server -Identity:$Aduser.DistinguishedName -TargetPath: $ou_sei
            Write-Output "user: $stud_id moved to container 'EI-EDU'"
        }
    } else {
        ##something not recognized ...." 
    }
}


#enable and set new_description
function set_new_status{
     param (
        [string]$stud_id,
        [string]$full_name,
        [string]$description,
	    [string]$pass
    )
    $new_description = $description
    $user_status = Get-ADUser -Identity $stud_id -Properties Enabled | Select-Object -ExpandProperty Enabled
    
    Write-Output $user_status
    if ($false -eq $user_status) { 
        
        $new_pass = ConvertTo-SecureString $pass -AsPlainText -Force              
        Set-ADAccountPassword -Identity $stud_id -NewPassword $new_pass -Reset            
        Set-ADUser -Identity $stud_id -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true -Description $new_description
        Write-Output "user: $stud_id Restored, password: Reseted, Description is: $new_decription "
        #Set-ADUser -Identity $stud_id -ChangePasswordAtLogon $true
    } else {
        Set-ADUser -Identity $stud_id -Description $new_description
        Write-Output "Description is: $new_description"
    }
}



function check_user{
    param (
        [string]$stud_id,
        [string]$full_name,
        [string]$description,
	    [string]$pass,
        [string]$home_dir      
    )

    $home_dir="$home_dir$stud_id"


    try {
        $Aduser = Get-ADUser -server $ad_server -Identity $stud_id
        if ($Aduser) {
            #$ad_user_desc = Get-ADUser -Server $ad_server -Identity $stud_id -Properties Description | Select-Object Description
            #call function restore_user
            restore_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass -home_dir $home_dir
        } #else {
            #call function create_user
        #    Write-Output "user $stud_id is New!"
        #    create_new_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass -home_dir $home_dir
        #}
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Output "user $stud_id is New!"
        create_new_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass -home_dir $home_dir
    } catch {
        Write-Output $_
        #something happened ... 
    }

}

#    try {
#       $Aduser = Get-ADUser -server $ad_server -Identity $stud_id -ErrorAction Stop
#        #call function restore_user      
#        restore_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass -home_dir $home_dir
#    } catch {
#	    #call function create_user
#        Write-Output "user $stud_id is New!"
#        #create_new_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass -home_dir $home_dir
#        
#    }



#foreach all students in csv_list
foreach ($row in $csv) {
    #number
    $students = "$($row.number)"
    #firstname lastname surname
    $full_name = "$($row.full_name)"
    #description
    $description = "$($row.description)"
    #bithday (pass)
    $pass = "$($row.bdate)"
    #prefix 
    $pref = "$($row.edu_form_pref)"
    

    $inst_abbr = $($row.description.Split(' ')[0])
    $group_name = $($row.description.Split(' ')[1]).Substring(0, $($row.description.Split(' ')[1]).Length - 3).Replace("-", "_")
    #$group_name = $($row.description.Split(' ')[1])
    $home_dir = "$init_dir\dev\$pref\$inst_abbr\$group_name\"

    foreach ($stud_number in $students) {
        $inst = $($row.description.Split(' ')[0])

        if ($inst -in $inst_list){
        check_user -stud_id $stud_number -full_name $full_name -description $description -pass $pass -home_dir $home_dir
        }else{
            write-Output "$stud_number skip because 'inst not in list'"    
        }             
        write-Output "======================================================================="
    }
}

