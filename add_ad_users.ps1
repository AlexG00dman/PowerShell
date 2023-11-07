#PowerShell
#Script for restore old ad_users (students) to ad ver 0.55

#csv_students_source
$csv = Import-Csv "C:\temp\students.csv" -Delimiter ';' -Encoding UTF8
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



function restore_user {
    param (
         
        [string]$stud_id,
        [string]$full_name,
        [string]$description,
	    [string]$pass
    )
    $ad_user_desc = Get-ADUser -Server $ad_server -Identity $stud_id -Properties Description | Select-Object Description
  
    #check profile on correct discription
    if ($description -ne $ad_user_desc) { 
    
        clear_groups
        adduser_to_inst_group
        adduser_to_stud_group
        move_folder -stud_id $stud_id
        move_user_to_container -stud_id $stud_id
        set_new_status -stud_id $stud_id -description $description -pass $pass
        Write-Output "debug 02"

  
    }   else {
        Write-host "$stud_id 'is ok' skipped" -ForegroundColor Red
    }
}



function set_homedrive_link{
    param ([string]$stud_id)
    Set-ADUser -server $ad_server -Identity $stud_id -HomeDirectory $home_dir -HomeDrive 'Z:'
    Write-Output "$stud_id link ok"
}
  


####create_home_dir_
function create_folder {
#check directory empty or not
    if (!(Test-Path $home_dir)) {
        New-Item -ItemType Directory -Path $home_dir
        Write-Output "folder $home_dir has been created"
    } else {
        Write-Output "$home_dir exists yet"
    }
}




####set acl for user forlder
function set_acl(){
param ([string]$stud_id)

$acl = Get-Acl -Path $home_dir
$new = "$ad_server\$stud_id","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $new
$acl.SetAccessRule($accessRule)
Set-Acl -Path $home_dir -AclObject $acl
Write-output "$stud_id acl ok"
}



function move_folder{
    param ([string]$stud_id)   
    $home_dir="$home_dir$stud_id"
    $ad_home_dir = $(Get-ADUser -Identity $stud_id -Server $ad_server -Properties HomeDirectory | Select-Object -ExpandProperty HomeDirectory)
     
    # ad_home is empty
    Write-Output $new_home_dir
    if ([string]::IsNullOrEmpty($ad_home_dir)){
        create_folder
        set_acl -stud_id $stud_id -home_dir $home_dir
        set_homedrive_link -stud_id $stud_id -home_dir $home_dir
    }
    # ad_home != home_dir
    elseif ($ad_home_dir.ToString().trim() -ne $home_dir){
        # folder exists !
        if (Test-Path $ad_home_dir){
            #### Write-Output "$ad_home_dir status 0" debug # #create
            Move-Item $ad_home_dir -Destination $home_dir-Force
            set_acl -stud_id $stud_id -home_dir $home_dir
            set_homedrive_link -stud_id $stud_id -home_dir $home_dir
            Write-host "folder $stud_id moved socesfully"
        }
        # folder not exists !
        else {
            create_folder
            set_acl -stud_id $stud_id -home_dir $home_dir
            set_homedrive_link -stud_id $stud_id -home_dir $home_dir
        }
    }
    # if ad_home == home_dir  
    elseif ($ad_home_dir.ToString().trim() -eq $home_dir) {
        if (!(Test-Path $home_dir)){
            create_folder
            set_acl -stud_id $stud_id -home_dir $home_dir
            set_homedrive_link -stud_id $stud_id -home_dir $home_dir
        }
        else {
            Write-Output "ok in correct way :D"
        }
    }
}



#delete user from all not system groups
function clear_groups (){
    $groups = Get-ADPrincipalGroupMembership -server $ad_server -Identity $Aduser.sAMAccountName | Where-Object {($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-513")-and ($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-47544")}
    if  (0 -eq  $groups.Count) {
        Write-host "Exists in system groups only" -ForegroundColor Red 
      
    } else {
    foreach ($StdGrp in $groups){
     try{
       Remove-ADGroupMember -server $ad_server -identity $StdGrp -Members $Aduser.sAMAccountName -Confirm:$false 
       Write-Output user: "$StdId removed from $StdGrp.name"
	}catch{
       Write-Output "User in system groups only"  
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
                Write-Host "$stud_id exists in $inst"
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
                Write-Host "$stud_id exists in $inst"
            } else {
                Add-ADGroupMember -Server $ad_server -Identity $inst -Members $stud_id
                Write-Output "$stud_id added in the $inst"
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
                Write-Host "$stud_id exists in $str_group"
            } else {
                Add-ADGroupMember -Server $ad_server -Identity $str_group -Members $stud_id
                Write-Output "$stud_id added in the $str_group"
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
            Write-Output "in $Aduser.sAMAccountName is in container 'OU=Удалённые'"
            Move-ADObject -Server $ad_server -Identity:$Aduser.DistinguishedName -TargetPath: $ou_users
        } else {       
           Write-Output "user $Aduser.sAMAccountName moved in container 'Users'"
           move_user_to_inst_container
        }
}



#move user to inst aproptiate inst container
function move_user_to_inst_container() {
    $inst = $($row.description.Split(' ')[0])
    $Aduser = Get-ADUser -Identity $row.number -Server $ad_server

    if ($inst -eq $inst_list[6]) {
        if ($Aduser.DistinguishedName.Contains("$ou_inpit")) {
            Write-Output "Student  $Aduser.sAMAccountName in container $ou_inpit yet"
        } else {
            Move-ADObject -Server $ad_server -Identity:$Aduser.DistinguishedName -TargetPath: $ou_inpit
            Write-Output "Student: $Aduser.sAMAccountName moved to container $ou_inpit"
        }
    } elseif ($inst -eq $inst_list[5]) {
        if ($Aduser.DistinguishedName.Contains($ou_sei)) {
            Write-Output "Student  $Aduser.sAMAccountName in containere $ou_sei yet"
        } else {
            Move-ADObject -Server $ad_server -Identity:$Aduser.DistinguishedName -TargetPath: $ou_sei
            Write-Output "Student $Aduser.sAMAccountName moved to container $ou_sei"
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
        Set-ADUser -Identity $stud_id -Enabled $true -ChangePasswordAtLogon $true -Description $new_description
        Set-ADAccountPassword -Identity $stud_id -NewPassword $new_pass -Reset
        Write-Output "Status: $stud_id Restored, password: Reseted, Description is: $new_decription "
        #Set-ADUser -Identity $stud_id -ChangePasswordAtLogon $true
    } else {
        Set-ADUser -Identity $stud_id -Description $new_description
        Write-Output "Description is: $new_description"
}
}



function create_user{
    param (
        [string]$stud_id,
        [string]$full_name,
        [string]$description,
	[string]$pass
    )
    Write-Host $stud_id

    try {
        $Aduser = Get-ADUser -server $ad_server -Identity $stud_id -ErrorAction Stop
        #call function restore_user      
        restore_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass
    } catch {
	    #call function create_user
        create_new_user -stud_id $stud_id -full_name $full_name -description $description -pass $pass
        
      }
}



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
    

    $inst_abbr = $($row.description.Split(' ')[0])
    $group_name = $($row.description.Split(' ')[1]).Substring(0, $($row.description.Split(' ')[1]).Length - 3).Replace("-", "_")
    #$group_name = $($row.description.Split(' ')[1])
    $home_dir = "$init_dir\$inst_abbr\$group_name\"


    foreach ($stud_number in $students) {
        $inst = $($row.description.Split(' ')[0])

        if ($inst -in $inst_list){
        create_user -stud_id $stud_number -full_name $full_name -description $description -pass $pass -home_dir $home_dir
        }else{
            write-Output "$stud_number skip because 'inst not in list'"    
        }             
        
    }
}
