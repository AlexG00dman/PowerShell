#powershell
#редакция 0.3.91
#Скрипт для отключения, перемещения и добавления описания description, удаления студентов из групп, удаления ссылки на домашнюю директорию 
#Удаление из групп нагружает сервер AD рекомендуется выполнять отдельно от других операций 

#C помощью скрипта можно выполнять раздельно:
#1. отключение студентов
#DisableUsers
#2. добавление описания
#AddDescription 
#3. перемещение студентов в контейнер "удаленные"
#MoveUsers
#4. удаление студентов из групп удаляет группы (занимает значительное время!!!)
#ClearGroups
#5. удаление ссылок на домашнюю директорию
#ClearHomeDir

#csv список должен иметь следующие поля number; full_name; description (номер зачетки; фио; описание) 
$CSV = Import-Csv "C:\temp\new_students.csv"  -Delimiter ';'

$my_serv = my_dom

#функция проверка наличия студента в AD
function GetUsr{
param ([string]$description, [string]$stud_id)
    try{
        $Aduser=$(Get-ADUser -server $my_serv -Identity $stud_id -Property DistinguishedName,sAMAccountName,DisplayName,Description)
        Write-output "Зачетка:$StdId Имя:"$Aduser.DisplayName""
        Write-output $Aduser.Description
     

    ###Вызов необходимых функции НЕОБХОДИМО РАССКОМЕНТИРОВАТЬ НУЖНОЕ!!!!
	#вызов функции отключения студентов
    #DisableUsers $Ad_std_user
    #вызов функциии добавить описание

    AddDescription -stud_id $stud_id -description $description
    #вызов функции перемещения студентов в контейнер "удаленные"
    #MoveUsers $Ad_std_user
    #Получение групп пользователей и (удаление пользователей из групп вызов 2х функций)
	#ClearGroups $Ad_std_user        
    #setHomeDir $Ad_std_user
            Write-Output $stud_id $description
	}catch{
        Write-host "$Students $FullName студент не найден в Ad" -ForegroundColor Red          
    }       
}

function ClearGroups ($Ad_std_user){
    $groups = Get-ADPrincipalGroupMembership -server $my_serv -Identity $Aduser.sAMAccountName | Where {($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-513")-and ($_.SID -ne "S-1-5-21-1660514390-1878642582-2000023620-47544")}
    if ($Groups.Count -eq 0) {
        Write-host "состоит только в системных группах $my_serv" -ForegroundColor Red 
      
    } else {
    foreach ($StdGrp in $groups){
     try{
       Remove-ADGroupMember -server $my_serv -identity $StdGrp -Members $Aduser.sAMAccountName -Confirm:$false 
       Write-Output пользователь: "$StdId удален из группы $StdGrp.name"
	}catch{
       Write-Output "состоит только в системных группах $my_serv"  
    }
  }
}
}

#функция отключить учётную запись 
function DisableUsers ($Ad_std_user){
    Disable-ADAccount -Server "$my_serv" -Identity: $Aduser.sAMAccountName -Confirm:$False
    Write-Output "$StdId пользователь выключен"
}

#функция добавить описание
function AddDescription{
param ([string]$stud_id, [string]$description)

###$Aduser=$(Get-ADUser -server $my_serv -Identity $stud_id -Property DistinguishedName,sAMAccountName)
    #Добавить запись в описание
    #Write-Output $Aduser.SamAccountName
    #Set-ADUser -server $my_serv -Identity: $Aduser.sAMAccountName -description "Удалён по причине окончания обучения 2023 г." -Confirm:$false
    $description = "$description (академический отпуск)"
    Set-ADUser -server $my_serv -Identity: $stud_id -description $description -Confirm:$false
    #Write-Output ""
}


function MoveUsers(){
#Переместить учетную запись в контейнер удаленые 
    if ($Aduser.DistinguishedName.Contains("OU=Удалённые")){
		Write-Output "пользователь  $Aduser.sAMAccountName  уже в контейнере удаленные"
	}else{
		Move-ADObject -Server $my_serv -Identity:$Aduser.DistinguishedName  -TargetPath:"OU=Удалённые,DC=$my_serv"
		Write-Output "пользователь $Aduser.sAMAccountName перемещен в контейнер 'удаленные'"
    }
}
 
#функция добавления домашней директории homeDirectory (добавляет только ссылкуб без создания папки)
function setHomeDir ($Ad_std_user){
    Write-Host $home_dir
    #Set-ADUser -server $my_serv  $Aduser.sAMAccountName -HomeDirectory $home_dir -HomeDrive 'Z:'
    Set-ADUser -server $my_serv $Aduser.sAMAccountName -HomeDirectory $null -HomeDrive '$null'
}


#Проверка перебор номеров зачеток для проверки существования в AD
$CSV | ForEach-Object {
    $stud_id = $_.number
    $home_dir = $_.home_dir
    $description = $_.description
    GetUsr -stud_id $stud_id -description $description
   # write $stud_id $description
}

