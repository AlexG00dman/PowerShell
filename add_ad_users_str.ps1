#PowerShell
#Script for restore old ad_users (students) to ad ver 0.59 FORK 

#student info
$str_student = "152218;Фамилия Имя Отчество;Институт б1-группа-21 2022_2027(годы обучения);17061998 (дата_рождения);z_(форма_обучения)"


#ad_server
$ad_server="edudom"
#root_directory_network_storage
$init_dir = "\\my-edu.edudom\students$"
#institutes 
$inst_list = "ЭН", "ИнMЭТ", "ММТ", "ТИ", "УMС", "ИНТ", "ИНП"
#ad_units
$ou_users = "CN=Users,DC=edudom"
$ou_deleted = "OU=Удалённые,DC=edudom"
$ou_inpit = "OU=App-EDU,DC=edudom"
$ou_sei = "OU=OU-Users,OU=SE-EDU,DC=edudom"


#student split string
$str_student = $str_student.Split(';')
#stud_number
$stud_id = $str_student[0]
#firstname_lastname_surname
$full_name = $str_student[1]
#description
$description = $str_student[2]
#bithday(pass)
$pass = $str_student[3]
#prefix
$pref = $str_student[4]

#description
$description = $description.Split(' ')
#institut_name
$inst_abbr = $description[0]
#group_name_for_home_drive
$group_folder = $description[1].Substring(0, $description[1].Length - 3).Replace("-", "_")
#home_dir
$home_dir = "$init_dir\dev\$pref\$inst_abbr\$group_folder\$stud_id"
#student_group_name
$group_name = $pref + $inst_abbr + "_" + $($description[1]).Replace("-", "_")




function create_new_user {
   
    $Password = ConvertTo-SecureString $pass -AsPlainText -Force
    New-ADUser -server $ad_serv -Name $stud_id -SamAccountName $stud_id -DisplayName $full_name -AccountPassword $Password -ChangePasswordAtLogon $true -Description $str_student[2] -Enabled $true -Path $ou_users
    create_home_dir 
    set_homedrive_link 
    set_acl 
    move_user_to_container #-stud_id $stud_id #+#
    move_user_to_inst_container #-stud_id $stud_id #+#
    adduser_to_inst_group #-stud_id $stud_id -inst_abbr $inst_abbr #+#
    adduser_to_stud_group #-stud_id $stud_id -group_name $group_name #+#         
    Write-Output "user with number: $stud_id and name: $full_name added to ad successfully"

}


function restore_user {
    $ad_user_desc = Get-ADUser -Server $ad_serv -Identity $stud_id -Properties Description | Select-Object Description 
    #check profile on correct discription
    if ($description -ne $ad_user_desc) { 
        move_folder
        move_user_to_container
        clear_groups
        adduser_to_inst_group
        adduser_to_stud_group


        set_new_status 
        #Write-Output "debug 02"
    }   else {
        Write-host "$stud_id 'is ok' skipped ..." -ForegroundColor Red


    }
}






function move_folder{
    $ad_home_dir = $(Get-ADUser -Identity $stud_id -Server $ad_serv -Properties HomeDirectory | Select-Object -ExpandProperty HomeDirectory)
    
    #if ad_home is empty
    if ([string]::IsNullOrEmpty($ad_home_dir)){
            create_home_dir 
    }
    #if ad_home != home_dir
    elseif ($ad_home_dir.ToString().trim() -ne $home_dir){
        if (Test-Path $ad_home_dir){
            #### Write-Output "$ad_home_dir status 0" debug # #create
            Move-Item $ad_home_dir -Destination $home_dir -Force 
            Write-host "folder $stud_id moved socessfully"
        } else {
            create_home_dir
        }
    }
    #if ad_home == home_dir
    elseif ($ad_home_dir.ToString().trim() -eq $home_dir) {
        if (!(Test-Path $home_dir)){
            create_home_dir  
        }
        else {
            Write-Output "home_dir of $stud_id is on correct way :D"
        }
    }

    set_acl 
    set_homedrive_link 
}


  
####create_home_dir_
function create_home_dir {
#check directory empty or not
    if (!(Test-Path $home_dir)) {
        New-Item -ItemType Directory -Path $home_dir
        Write-Output "folder $home_dir has been created"
    } else {
        Write-Output "$home_dir exists yet"
    }
}

####set acl for user forlder
function set_acl{

$acl = Get-Acl -Path $home_dir
$new = "$ad_serv\$stud_id","Modify","ContainerInherit,ObjectInherit","None","Allow"

$accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $new
$acl.SetAccessRule($accessRule)
Set-Acl -Path $home_dir -AclObject $acl
Write-output "$stud_id acl ok"
}



function set_homedrive_link{
    Set-ADUser -server $ad_serv -Identity $stud_id -HomeDirectory $home_dir -HomeDrive 'Z:'
    Write-Output "$stud_id link ok"
}




#delete user from all not system groups
function clear_groups{
    $groups = Get-ADPrincipalGroupMembership -server $ad_serv -Identity $Aduser.sAMAccountName | Where-Object {($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-513")-and ($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-47544")}
    if  (0 -eq  $groups.Count) {
        Write-host "user: $stud_id have only system groups" -ForegroundColor Red 
      
    } else {
    foreach ($stud_group in $groups){
     try{
       Remove-ADGroupMember -server $ad_serv -identity $stud_group -Members $Aduser.sAMAccountName -Confirm:$false 
       Write-Output "user: $stud_id removed from $stud_group"
	}catch{
       Write-Output "something happened ... :D"  
    }
  }
}
}


#check existence users in group of TU University
function adduser_to_univer_group{
    try {
        $Result = Get-ADGroup -Identity "tu_students" -Server $ad_serv
        if ($null -ne $Result) {                       
            $instUsers = Get-ADGroupMember -Server $ad_serv -Identity $inst_abbr -Recursive | Select-Object -ExpandProperty Name
            if ($instUsers -contains $stud_id) {
                Write-Host "$stud_id member of $inst"
            } else {
                Add-ADGroupMember -Server $ad_serv -Identity $inst_abbr -Members $stud_id
                Write-Output "$stud_id added in the $inst"
            }
        }
    } catch {
      Write-Host "$Inst_abbr Group does not exist." -ForegroundColor Red
    }
}

#check existence user in Institute's groups 
function adduser_to_inst_group{
    $inst_abbr = $inst_abbr + "-студенты"  
    try {
        $Result = Get-ADGroup -Identity $inst_abbr -Server $ad_serv
        if ($null -ne $Result) {                       
            $instUsers = Get-ADGroupMember -Server $ad_serv -Identity $inst_abbr -Recursive | Select-Object -ExpandProperty Name
            if ($instUsers -contains $stud_id) {
                Write-Host "user: $stud_id member of $inst_abbr"
            } else {
                Add-ADGroupMember -Server $ad_serv -Identity $inst_abbr -Members $stud_id
                Write-Output "user: $stud_id added to the $inst_abbr"
            }
        }
    } catch {
      Write-Host "$Inst_abbr Group does not exist." -ForegroundColor Red
    }
}



# check users exist in group_name or not
function adduser_to_stud_group{
    try {
        $Result = Get-ADGroup -Identity $group_name -Server $ad_serv
        if ($null -ne $Result) {
            $groupUsers = Get-ADGroupMember -Server $ad_serv -Identity $group_name -Recursive | Select-Object -ExpandProperty Name
            if ($groupUsers -contains $stud_id) {
                Write-Host "user: $stud_id member of $group_name"
            } else {
                Add-ADGroupMember -Server $ad_serv -Identity $group_name -Members $stud_id
                Write-Output "user: $stud_id added in the $group_name"
            }
        }
    } catch {
        Write-Host "$group_name Group does not exist." -ForegroundColor Red
    }
}



#move user to container 'users'
function move_user_to_container{
    $Aduser = Get-ADUser -Identity $stud_id -Server $ad_serv
        if ($Aduser.DistinguishedName.Contains("$ou_deleted")) {
           Write-Output "user: $stud_id have container 'OU=Удалённые'"
           Move-ADObject -Server $ad_serv -Identity:$Aduser.DistinguishedName -TargetPath: $ou_users
        } else {
           Write-Output "user: $stud_id have container 'Users'"
           move_user_to_inst_container -stud_id $stud_id
        }
}



#move user to inst aproptiate inst container
function move_user_to_inst_container{
    $Aduser = Get-ADUser -Identity $stud_id -Server $ad_serv
    if ($inst_abbr -eq $inst_list[6]) {
        if ($Aduser.DistinguishedName.Contains("$ou_inpit")) {
            Write-Output "user: $stud_id have container $ou_inpit yet"
        } else {
            Move-ADObject -Server $ad_serv -Identity:$Aduser.DistinguishedName -TargetPath: $ou_inpit
            Write-Output "user: $stud_id moved to container $ou_inpit"
        }
    } elseif ($inst_abbr -eq $inst_list[5]) {
        if ($Aduser.DistinguishedName.Contains($ou_sei)) {
            Write-Output "user: $stud_id have container 'EI-EDU' yet"
        } else {
            Move-ADObject -Server $ad_serv -Identity:$Aduser.DistinguishedName -TargetPath: $ou_sei
            Write-Output "user: $stud_id moved to container 'EI-EDU'"
        }
    } else {
        ##something not recognized ...."
    }
}

#enable and set new_description
function set_new_status{
    $new_description = $str_student[2]
    $user_status = Get-ADUser -Identity $stud_id -Properties Enabled | Select-Object -ExpandProperty Enabled
    
    Write-Output $user_status
    if ($false -eq $user_status) { 
        
        $new_pass = ConvertTo-SecureString $pass -AsPlainText -Force              
        Set-ADAccountPassword -Identity $stud_id -NewPassword $new_pass -Reset            
        Set-ADUser -server $ad_serv -Identity: $stud_id -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true -Description $new_description -Confirm:$false
        Write-Output "user: $stud_id Restored, password: Reseted, Description is: $new_decription "
        #Set-ADUser -Identity $stud_id -ChangePasswordAtLogon $true
    } else {
        Set-ADUser -server $ad_serv -Identity: $stud_id -Description $new_description -Confirm:$false
        Write-Output "Description is: $new_description"
}
}



function check_user{

    try {
        $Aduser = Get-ADUser -server $ad_serv -Identity $stud_id
        if ($Aduser) {
            #$ad_user_desc = Get-ADUser -Server $ad_serv -Identity $stud_id -Properties Description | Select-Object Description
        #call function create user
		    
        restore_user 
       # } else {
            #call function create_user
            #Write-Output "user $stud_id is New!"
            #create_new_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass -home_dir $home_dir
        }
    } catch {
      #Write-Output $_
      #something happened ...
	   #call function restore_user
       Write-Output "user $stud_id exist in ad!"
       create_new_user 
       }
}



if ($inst_abbr -in $inst_list){
   check_user 
   }else{
   write-Output "$stud_number skip because 'inst not in list'"
}


