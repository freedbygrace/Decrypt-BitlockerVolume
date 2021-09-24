#Requires -Version 3 -Modules ('Bitlocker', 'Storage')

<#
    .SYNOPSIS
    Provides the ability to remove Bitlocker disk encryption from all volumes located on fixed hard disks. Removable disk(s) will not be included.
          
    .DESCRIPTION
    By default, only the operating system volume will be decrypted. Modify the regular expression parameter(s) to achieve the desired scenario.
    Because the "Decrypt-BitlockerVolume" command is asynchronous, a Do-Until loop will be used in order to track the decrpytion process on each volume and keep the script from exiting until the decryption is completed.
          
    .PARAMETER DriveTypeExpression
    A regular expression that correctly includes values from the "DriveType" property as seen in the example below.

    DriveLetter FriendlyName FileSystemType DriveType HealthStatus OperationalStatus SizeRemaining      Size
    ----------- ------------ -------------- --------- ------------ ----------------- -------------      ----
    C           OS           NTFS           Fixed     Healthy      OK                    164.69 GB 475.69 GB
                WinRE_DRV    NTFS           Fixed     Healthy      OK                    503.32 MB   1000 MB
                SYSTEM       FAT32          Fixed     Healthy      OK                    225.49 MB    256 MB

    .PARAMETER DriveLetterInclusionExpression
    A regular expression that correctly includes the desired drive letters of encrypted volumes. By default, only the operating system volume is included.

    Examples:
    All Volumes - ^[a-zA-Z]$
    Specific Volumes - ^[C]$
    Multiple Volumes - ^[E|H|K]$

    .PARAMETER DriveLetterExclusionExpression
    A regular expression that correctly excludes the desired drive letters of encrypted volumes. By default, only volumes without a drive letter are excluded.

    Examples:
    Specific Volumes - ^[C]$
    Multiple Volumes - ^[E|H|K]$

    .PARAMETER VolumeStatusExpression
    A regular expression that correctly includes the bitlocker volume status of an encryptable volume.

    VolumeType      Mount CapacityGB VolumeStatus           Encryption KeyProtector              AutoUnlock Protection
                    Point                                   Percentage                           Enabled    Status    
    ----------      ----- ---------- ------------           ---------- ------------              ---------- ----------
    OperatingSystem C:        475.69 FullyDecrypted         0          {}                                   Off       

    .PARAMETER DebugMode
    Allows for the testing of this scripts functionality, but not actually perform volume decryption.
    
    .PARAMETER LogDir
    A valid folder path. If the folder does not exist, it will be created. This parameter can also be specified by the alias "LogPath".

    .PARAMETER ContinueOnError
    Ignore failures.
          
    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File "%FolderPathContainingScript%\%ScriptName%.ps1"

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File "%FolderPathContainingScript%\%ScriptName%.ps1" -ScriptParameter "%ScriptParameterValue%"

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File "%FolderPathContainingScript%\%ScriptName%.ps1" -SwitchParameter
  
    .NOTES
    The Disable-BitLocker cmdlet disables BitLocker Drive Encryption for a BitLocker volume. When you run this cmdlet, it removes all key protectors and begins decrypting the content of the volume.

    If the volume that hosts the operating system contains any automatic unlocking keys, the cmdlet does not proceed. You can use the Clear-BitLockerAutoUnlock cmdlet to remove all automatic unlocking keys. Then you can disable BitLocker for the volume.

    For an overview of BitLocker, see BitLocker Drive Encryption Overview on TechNet.
          
    .LINK
    https://docs.microsoft.com/en-us/powershell/module/bitlocker/disable-bitlocker?view=windowsserver2019-ps
#>

[CmdletBinding()]
  Param
    (        	     
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('DTE')]
        [Regex]$DriveTypeExpression = "^Fixed$",

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('DLIE')]
        [Regex]$DriveLetterInclusionExpression = "^[$($Env:SystemDrive.Replace(':', ''))]$",

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('DLEE')]
        [Regex]$DriveLetterExclusionExpression = "^.{0,0}$",

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('VSE')]
        [Regex]$VolumeStatusExpression = "^FullyDecrypted$",

        [Parameter(Mandatory=$False)]
        [Switch]$DebugMode,
            
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('LogPath')]
        [System.IO.DirectoryInfo]$LogDir,
            
        [Parameter(Mandatory=$False)]
        [Switch]$ContinueOnError
    )
        
Function Get-AdministrativePrivilege
    {
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
        Write-Output -InputObject ($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    }

If ((Get-AdministrativePrivilege) -eq $False)
    {
        [System.IO.FileInfo]$ScriptPath = "$($MyInvocation.MyCommand.Path)"
        [String[]]$ArgList = @('-ExecutionPolicy Bypass', '-NoProfile', '-NoExit', '-NoLogo', "-File `"$($ScriptPath.FullName)`"")
        $Null = Start-Process -FilePath "$([System.Environment]::SystemDirectory)\WindowsPowershell\v1.0\powershell.exe" -WorkingDirectory "$([System.Environment]::SystemDirectory)" -ArgumentList ($ArgList) -WindowStyle Normal -Verb RunAs -PassThru
    }
Else
    {
        #Determine the date and time we executed the function
          $ScriptStartTime = (Get-Date)
  
        #Define Default Action Preferences
            $Script:DebugPreference = 'SilentlyContinue'
            $Script:ErrorActionPreference = 'Stop'
            $Script:VerbosePreference = 'SilentlyContinue'
            $Script:WarningPreference = 'Continue'
            $Script:ConfirmPreference = 'None'
    
        #Load WMI Classes
          $Baseboard = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Baseboard" -Property * | Select-Object -Property *
          $Bios = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_Bios" -Property * | Select-Object -Property *
          $ComputerSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_ComputerSystem" -Property * | Select-Object -Property *
          $OperatingSystem = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_OperatingSystem" -Property * | Select-Object -Property *
          $MSSystemInformation = Get-WmiObject -Namespace "root\WMI" -Class "MS_SystemInformation" -Property * | Select-Object -Property *

        #Retrieve property values
          $OSArchitecture = $($OperatingSystem.OSArchitecture).Replace("-bit", "").Replace("32", "86").Insert(0,"x").ToUpper()

        #Define variable(s)
          $DateTimeLogFormat = 'dddd, MMMM dd, yyyy @ hh:mm:ss.FFF tt'  ###Monday, January 01, 2019 @ 10:15:34.000 AM###
          [ScriptBlock]$GetCurrentDateTimeLogFormat = {(Get-Date).ToString($DateTimeLogFormat)}
          $DateFileFormat = 'yyyyMMdd'  ###20190403###
          [ScriptBlock]$GetCurrentDateFileFormat = {(Get-Date).ToString($DateFileFormat)}
          $DateTimeFileFormat = 'yyyyMMdd_HHmmss'  ###20190403_115354###
          [ScriptBlock]$GetCurrentDateTimeFileFormat = {(Get-Date).ToString($DateTimeFileFormat)}
          [System.IO.FileInfo]$ScriptPath = "$($MyInvocation.MyCommand.Definition)"
          [System.IO.DirectoryInfo]$ScriptDirectory = "$($ScriptPath.Directory.FullName)"
          [System.IO.DirectoryInfo]$ContentDirectory = "$($ScriptDirectory.FullName)\Content"
          [System.IO.DirectoryInfo]$FunctionsDirectory = "$($ScriptDirectory.FullName)\Functions"
          [System.IO.DirectoryInfo]$ModulesDirectory = "$($ScriptDirectory.FullName)\Modules"
          [System.IO.DirectoryInfo]$ToolsDirectory = "$($ScriptDirectory.FullName)\Tools"
          [System.IO.DirectoryInfo]$ToolsDirectory_OSAll = "$($ToolsDirectory.FullName)\All"
          [System.IO.DirectoryInfo]$ToolsDirectory_OSArchSpecific = "$($ToolsDirectory.FullName)\$($OSArchitecture)"
          [System.IO.DirectoryInfo]$System32Directory = [System.Environment]::SystemDirectory
          [System.IO.DirectoryInfo]$ProgramFilesDirectory = "$($Env:SystemDrive)\Program Files"
          [System.IO.DirectoryInfo]$ProgramFilesx86Directory = "$($Env:SystemDrive)\Program Files (x86)"
          [System.IO.FileInfo]$PowershellPath = "$($System32Directory.FullName)\WindowsPowershell\v1.0\powershell.exe"
          [System.IO.DirectoryInfo]$System32Directory = "$([System.Environment]::SystemDirectory)"
          $IsWindowsPE = Test-Path -Path 'HKLM:\SYSTEM\ControlSet001\Control\MiniNT' -ErrorAction SilentlyContinue
          [System.Text.RegularExpressions.RegexOptions[]]$RegexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [System.Text.RegularExpressions.RegexOptions]::Multiline
          [ScriptBlock]$GetRandomGUID = {[System.GUID]::NewGUID().GUID.ToString().ToUpper()}
          $TextInfo = (Get-Culture).TextInfo
          [Int[]]$ErrorCodeRange = 6000..6999
	
        #Log task sequence variables if debug mode is enabled within the task sequence
          Try
            {
                [System.__ComObject]$TSEnvironment = New-Object -ComObject "Microsoft.SMS.TSEnvironment"
              
                If ($Null -ine $TSEnvironment)
                  {
                      $IsRunningTaskSequence = $True
                      
                      [Boolean]$IsConfigurationManagerTaskSequence = [String]::IsNullOrEmpty($TSEnvironment.Value("_SMSTSPackageID")) -eq $False
                      
                      Switch ($IsConfigurationManagerTaskSequence)
                        {
                            {($_ -eq $True)}
                              {
                                  [String]$LogMessage = "A Microsoft Endpoint Configuration Manager (MECM) task sequence was detected."
                                  Write-Verbose -Message ($LogMessage) -Verbose   
                              }
                                      
                            {($_ -eq $False)}
                              {
                                  [String]$LogMessage = "A Microsoft Deployment Toolkit (MDT) task sequence was detected."
                                  Write-Verbose -Message ($LogMessage) -Verbose
                              }
                        }
                  }
            }
          Catch
            {
                $IsRunningTaskSequence = $False
            }

        #Determine the default logging path if the parameter is not specified and is not assigned a default value
          Switch (($Null -ieq $LogDir) -or ([String]::IsNullOrEmpty($LogDir)))
            {
                {($_ -eq $True)}
                  {
                      Switch ($IsRunningTaskSequence)
                        {
                            {($_ -eq $True)}
                              {
                                  Switch ($IsConfigurationManagerTaskSequence)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [String]$_SMSTSLogPath = "$($TSEnvironment.Value('_SMSTSLogPath'))"
                                          }
                              
                                        {($_ -eq $False)}
                                          {
                                              [String]$_SMSTSLogPath = "$($TSEnvironment.Value('LogPath'))"
                                          }
                                    }

                                  Switch ([String]::IsNullOrEmpty($_SMSTSLogPath))
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [System.IO.DirectoryInfo]$TSLogDirectory = "$($Env:Windir)\Temp\SMSTSLog"    
                                          }
                                    
                                        {($_ -eq $False)}
                                          {
                                              Switch ($True)
                                                {
                                                    {(Test-Path -Path ($_SMSTSLogPath) -PathType Container)}
                                                      {
                                                          [System.IO.DirectoryInfo]$TSLogDirectory = ($_SMSTSLogPath)
                                                      }
                                    
                                                    {(Test-Path -Path ($_SMSTSLogPath) -PathType Leaf)}
                                                      {
                                                          [System.IO.DirectoryInfo]$TSLogDirectory = Split-Path -Path ($_SMSTSLogPath) -Parent
                                                      }
                                                }    
                                          }
                                    }
                                         
                                  [System.IO.DirectoryInfo]$LogDir = "$($TSLogDirectory.FullName)\$($ScriptPath.BaseName)"
                              }
                  
                            {($_ -eq $False)}
                              {
                                  Switch ($IsWindowsPE)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [System.IO.FileInfo]$MDTBootImageDetectionPath = "$($Env:SystemDrive)\Deploy\Scripts\Litetouch.wsf"
                                      
                                              [Boolean]$MDTBootImageDetected = Test-Path -Path ($MDTBootImageDetectionPath.FullName)
                                              
                                              Switch ($MDTBootImageDetected)
                                                {
                                                    {($_ -eq $True)}
                                                      {
                                                          [System.IO.DirectoryInfo]$LogDir = "$($Env:SystemDrive)\MININT\SMSOSD\OSDLOGS\$($ScriptPath.BaseName)"
                                                      }
                                          
                                                    {($_ -eq $False)}
                                                      {
                                                          [System.IO.DirectoryInfo]$LogDir = "$($Env:Windir)\Temp\SMSTSLog"
                                                      }
                                                }
                                          }
                                          
                                        {($_ -eq $False)}
                                          {
                                              [System.IO.DirectoryInfo]$LogDir = "$($Env:Windir)\Logs\Software\$($ScriptPath.BaseName)"
                                          }
                                    }   
                              }
                        }
                  }              
            }

        #Start transcripting (Logging)
          Try
            {
                [System.IO.FileInfo]$ScriptLogPath = "$($LogDir.FullName)\$($ScriptPath.BaseName)_$($GetCurrentDateFileFormat.Invoke()).log"
                If ($ScriptLogPath.Directory.Exists -eq $False) {[Void][System.IO.Directory]::CreateDirectory($ScriptLogPath.Directory.FullName)}
                Start-Transcript -Path "$($ScriptLogPath.FullName)" -IncludeInvocationHeader -Force
            }
          Catch
            {
                If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message)"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                $ErrorMessage = "[Error Message: $($ExceptionMessage)][ScriptName: $($_.InvocationInfo.ScriptName)][Line Number: $($_.InvocationInfo.ScriptLineNumber)][Line Position: $($_.InvocationInfo.OffsetInLine)][Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                Write-Error -Message "$($ErrorMessage)"
            }
		
        #Log any useful information                                     
          [String]$CmdletName = $MyInvocation.MyCommand.Name
                                        
          $LogMessage = "Script `"$($CmdletName)`" is beginning. Please Wait..."
          Write-Verbose -Message $LogMessage -Verbose
                                    
          $LogMessage = "The following parameters and values were provided to the `"$($CmdletName)`" script." 
          Write-Verbose -Message $LogMessage -Verbose

          $ScriptProperties = Get-Command -Name ($MyInvocation.MyCommand.Source)
                    
          $ScriptParameters = $ScriptProperties.Parameters
                
          ForEach ($Parameter In ($ScriptParameters.Keys.GetEnumerator() | Sort-Object -Descending -Unique))
            {
                [String]$ParameterName = $Parameter
        
                Switch (([String]::IsNullOrEmpty($ParameterName) -eq $False) -and ($ParameterName -inotmatch '^Password$|^.*PW.*$|^Passphrase$|^.*Encryption.*$|^.*Key.*$') -and ($ParameterName -inotmatch '^Debug|ErrorAction|ErrorVariable|InformationAction|InformationVariable|OutBuffer|OutVariable|PipelineVariable|WarningAction|WarningVariable$'))
                  {
                      {($_ -eq $True)}
                        {
                            $ParameterProperties = Get-Variable -Name $ParameterName -ErrorAction SilentlyContinue
                      
                            $ParameterValueCount = $ParameterProperties.Value | Measure-Object | Select-Object -ExpandProperty Count
                          
                            Switch ($ParameterValueCount)
                              {
                                  {($_ -gt 1)}
                                    {
                                        $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ", "
                                        $LogMessage = "$($ParameterName): $($ParameterValueStringFormat)"
                                        Write-Verbose -Message "$($LogMessage)" -Verbose
                                    }
                              
                                  {($_ -eq 1)}
                                    {
                                        $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                        $LogMessage = "$($ParameterName): $($ParameterValueStringFormat)"
                                        Write-Verbose -Message "$($LogMessage)" -Verbose
                                    }
                            
                                  Default
                                    {
                                        $ParameterValueStringFormat = ($ParameterProperties.Value | ForEach-Object {"`"$($_)`""}) -Join ', '
                                        $LogMessage = "$($ParameterName): $($ParameterValueStringFormat)"
                                        Write-Verbose -Message "$($LogMessage)" -Verbose
                                    }
                              }   
                        }       
                  }
            }
                  
          $LogMessage = "Execution of script `"$($CmdletName)`" began on $($ScriptStartTime.ToString($DateTimeLogFormat))"
          Write-Verbose -Message $LogMessage -Verbose

          $LogMessage = "IsWindowsPE = $($IsWindowsPE.ToString())`r`n"
          Write-Verbose -Message "$($LogMessage)"

          $LogMessage = "Script Path = $($ScriptPath.FullName)"
          Write-Verbose -Message "$($LogMessage)" -Verbose
          
        #Log hardware information
          $MSSystemInformationMembers = $MSSystemInformation | Get-Member | Where-Object {($_.MemberType -imatch '^NoteProperty$|^Property$') -and ($_.Name -imatch '^Base.*|Bios.*|System.*$') -and ($_.Name -inotmatch '^.*Major.*|.*Minor.*|.*Properties.*$')} | Sort-Object -Property @('Name')
  
          $LogMessage = "Attempting to display device information properties from the `"$($MSSystemInformation.__CLASS)`" WMI class located within the `"$($MSSystemInformation.__NAMESPACE)`" WMI namespace. Please Wait..."
          Write-Verbose -Message "$($LogMessage)" -Verbose
  
          ForEach ($MSSystemInformationMember In $MSSystemInformationMembers)
            {
                [String]$MSSystemInformationMemberName = ($MSSystemInformationMember.Name)
                [String]$MSSystemInformationMemberValue = $MSSystemInformation.$($MSSystemInformationMemberName)
        
                Switch ([String]::IsNullOrEmpty($MSSystemInformationMemberValue))
                  {
                      {($_ -eq $False)}
                        {
                            $LogMessage = "$($MSSystemInformationMemberName) = $($MSSystemInformationMemberValue)"
                            Write-Verbose -Message "$($LogMessage)" -Verbose
                        }
                  }
            }

        #region Import Dependency Modules
          If (($ModulesDirectory.Exists -eq $True) -and ($ModulesDirectory.GetDirectories().Count -gt 0))
            {
                $Modules = Get-Module -Name "$($ModulesDirectory.FullName)\*" -ListAvailable -ErrorAction Stop 

                $ModuleGroups = $Modules | Group-Object -Property @('Name')

                ForEach ($ModuleGroup In $ModuleGroups)
                  {
                      $LatestModuleVersion = $ModuleGroup.Group | Sort-Object -Property @('Version') -Descending | Select-Object -First 1
      
                      If ($LatestModuleVersion -ine $Null)
                        {
                            $LogMessage = "Attempting to import dependency powershell module `"$($LatestModuleVersion.Name)`" [Version: $($LatestModuleVersion.Version.ToString())]. Please Wait..."
                            Write-Verbose -Message "$($LogMessage)" -Verbose
                            Import-Module -Name "$($LatestModuleVersion.Path)" -Global -DisableNameChecking -Force -ErrorAction Stop
                        }
                  }
            }
        #endregion

        #region Dot Source Dependency Scripts
          #Dot source any additional script(s) from the functions directory. This will provide flexibility to add additional functions without adding complexity to the main script and to maintain function consistency.
            Try
              {
                  If ($FunctionsDirectory.Exists -eq $True)
                    {
                        [String[]]$AdditionalFunctionsFilter = "*.ps1"
        
                        $AdditionalFunctionsToImport = Get-ChildItem -Path "$($FunctionsDirectory.FullName)" -Include ($AdditionalFunctionsFilter) -Recurse -Force | Where-Object {($_ -is [System.IO.FileInfo])}
        
                        $AdditionalFunctionsToImportCount = $AdditionalFunctionsToImport | Measure-Object | Select-Object -ExpandProperty Count
        
                        If ($AdditionalFunctionsToImportCount -gt 0)
                          {                    
                              ForEach ($AdditionalFunctionToImport In $AdditionalFunctionsToImport)
                                {
                                    Try
                                      {
                                          $LogMessage = "Attempting to dot source the functions contained within the dependency script `"$($AdditionalFunctionToImport.Name)`". Please Wait... [Script Path: `"$($AdditionalFunctionToImport.FullName)`"]"
                                          Write-Verbose -Message "$($LogMessage)" -Verbose
                          
                                          . "$($AdditionalFunctionToImport.FullName)"
                                      }
                                    Catch
                                      {
                                          $ErrorMessage = "[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                                          Write-Error -Message "$($ErrorMessage)"
                                      }
                                }
                          }
                    }
              }
            Catch
              {
                  $ErrorMessage = "[Error Message: $($_.Exception.Message)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                  Write-Error -Message "$($ErrorMessage)"           
              }
        #endregion

        #Perform script action(s)
          Try
            {                              
                #If necessary, create, get, and or set any task sequence variable(s).   
                  Switch ($IsRunningTaskSequence)
                    {
                        {($_ -eq $True)}
                          {
                              $LogMessage = "A task sequence is currently running.`r`n"
                              Write-Verbose -Message "$($LogMessage)" -Verbose

                              [String[]]$TaskSequenceVariablesToRetreive = @()
                                $TaskSequenceVariablesToRetreive += 'OSDComputerName'
                                
                                [String]$TaskSequenceVariablesToRetrievePSVariablePrefix = "X"
                              
                                ForEach ($TaskSequenceVariableToRetrieve In $TaskSequenceVariablesToRetreive)
                                  {
                                      [String]$TaskSequenceVariableToRetrieveName = "$($TaskSequenceVariableToRetrieve)"
                                      [String]$TaskSequenceVariableToRetrieveValue = "$($TSEnvironment.Value($TaskSequenceVariableToRetrieveName))"
                                      [String]$TaskSequenceVariableToRetrievePSVariableName = "$($TaskSequenceVariablesToRetrievePSVariablePrefix)$($TaskSequenceVariableToRetrieveName)"
                                                
                                      Switch ($TaskSequenceVariableToRetrieveName)
                                        {
                                            {($_ -imatch 'PW|Password|Passphrase|Phrase|Secret|Key')}
                                              {
                                                  [String]$LogMessage = "Attempting to retrieve the task sequence variable of `"$($TaskSequenceVariableToRetrieveName)`" and set the powershell variable of `"$($TaskSequenceVariableToRetrievePSVariableName)`" to the specified value. Please Wait...`r`n"
                                                  Write-Verbose -Message "$($LogMessage)" -Verbose
                                              }
                                              
                                            Default
                                              {
                                                  [String]$LogMessage = "Attempting to retrieve the task sequence variable of `"$($TaskSequenceVariableToRetrieveName)`" and set the powershell variable of `"$($TaskSequenceVariableToRetrievePSVariableName)`" to a value of `"$($TaskSequenceVariableToRetrieveValue)`". Please Wait...`r`n"
                                                  Write-Verbose -Message "$($LogMessage)" -Verbose
                                              }
                                        }
                                                                              
                                      $Null = Set-Variable -Name "$($TaskSequenceVariableToRetrievePSVariableName)" -Value ($TaskSequenceVariableToRetrieveValue) -Force        
                                  }
                          }
                    }

                #Tasks defined here will execute whether a task sequence is running or not
                  $Volumes = Get-Volume | Where-Object {([String]::IsNullOrEmpty($_.DriveLetter) -eq $False)} | Sort-Object -Property @('Size')
                  
                  [Int]$Script:BitlockerVolumeCount = 0
                  
                  :VolumeLoop ForEach ($Volume In $Volumes)
                    {
                        [String]$VolumeFriendlyName = "$($Volume.FileSystemLabel)"
                        [String]$VolumeDriveLetter = "$($Volume.DriveLetter):"
                        
                        $LogMessage = "Now processing volume `"$($VolumeFriendlyName)`" [DriveLetter: $($VolumeDriveLetter)]. Please Wait..."
                        Write-Verbose -Message ($LogMessage) -Verbose
                    
                        Switch ($Volume.DriveType -imatch $DriveTypeExpression.ToString())
                          {
                              {($_ -eq $True)}
                                {
                                    $LogMessage = "The volume drive type of `"$($Volume.DriveType)`" matches the regular expression of `"$($DriveTypeExpression.ToString())`""
                                    Write-Verbose -Message ($LogMessage) -Verbose
                            
                                    Switch (($Volume.DriveLetter -imatch $DriveLetterInclusionExpression.ToString()) -and ($Volume.DriveLetter -inotmatch $DriveLetterExclusionExpression.ToString()))
                                      {
                                          {($_ -eq $True)}
                                            {          
                                                $LogMessage = "The volume drive letter of `"$($VolumeDriveLetter)`" matches the regular expression of `"$($DriveLetterInclusionExpression.ToString())`" and does not match the regular expression of `"$($DriveLetterExclusionExpression.ToString())`""
                                                Write-Verbose -Message ($LogMessage) -Verbose
                                        
                                                $BitlockerVolumeInfo = Get-BitLockerVolume -MountPoint "$($VolumeDriveLetter)" -ErrorAction SilentlyContinue
                                                
                                                Switch ($Null -ine $BitlockerVolumeInfo)
                                                  {
                                                      {($_ -eq $True)}
                                                        {
                                                            [Regex]$DecryptionProgressExpression = "^DecryptionInProgress$"

                                                            Switch ($True)
                                                              {
                                                                  {($BitlockerVolumeInfo.VolumeStatus -imatch $VolumeStatusExpression.ToString())}
                                                                    {
                                                                        [String]$WarningMessage = "The volume status of Bitlocker volume `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)] is currently `"$($BitlockerVolumeInfo.VolumeStatus)`". Skipping."
                                                                        Write-Warning -Message ($WarningMessage) -Verbose
                                                
                                                                        Break VolumeLoop
                                                                    }
                                                      
                                                                  {($BitlockerVolumeInfo.VolumeStatus -imatch $DecryptionProgressExpression.ToString())}
                                                                    {
                                                                        [String]$WarningMessage = "The volume status of Bitlocker volume `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)] is currently `"$($BitlockerVolumeInfo.VolumeStatus)`". Encryption percentage is currently $($BitlockerVolumeInfo.EncryptionPercentage)%. Skipping."
                                                                        Write-Warning -Message ($WarningMessage) -Verbose
                                                
                                                                        Break VolumeLoop
                                                                    }
                                            
                                                                  {($BitlockerVolumeInfo.VolumeStatus -inotmatch $VolumeStatusExpression.ToString())}
                                                                    {
                                                                        $LogMessage = "The volume status of `"$($BitlockerVolumeInfo.VolumeStatus)`" does not match the regular expression of `"$($VolumeStatusExpression.ToString())`""
                                                                        Write-Verbose -Message ($LogMessage) -Verbose
                                                                
                                                                        Switch ($DebugMode.IsPresent)
                                                                          {
                                                                              {($_ -eq $True)}
                                                                                {
                                                                                    $LogMessage = "DEBUG MODE: Attempting to begin decryption of `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)]. Please Wait..."
                                                                                    Write-Verbose -Message ($LogMessage) -Verbose
                                                                            
                                                                                    $LogMessage = "DEBUG MODE: Actual decryption of volume `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)] WILL NOT be performed!"
                                                                                    Write-Verbose -Message ($LogMessage) -Verbose
                                                                                }
                                                                                
                                                                              {($_ -eq $False)}
                                                                                {
                                                                                    $Null = $Script:BitlockerVolumeCount++
                                                                
                                                                                    Try
                                                                                      {
                                                                                          $LogMessage = "Attempting to begin decryption of volume `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)]. Please Wait..."
                                                                                          Write-Verbose -Message ($LogMessage) -Verbose
                                                                                      
                                                                                          $Null = Disable-BitLocker -MountPoint ($BitlockerVolumeInfo.MountPoint)

                                                                                          Do
                                                                                            {
                                                                                                $BitlockerVolumeInfo = Get-BitLockerVolume -MountPoint ($BitlockerVolumeInfo.MountPoint)
                                          
                                                                                                Switch ($BitlockerVolumeInfo.EncryptionPercentage)
                                                                                                  {
                                                                                                      {($_ -ne 0)}
                                                                                                        {
                                                                                                            $LogMessage = "Waiting for the decryption of Bitlocker volume `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)] to complete. Encryption percentage is currently $($BitlockerVolumeInfo.EncryptionPercentage)%. Please Wait..."
                                                                                                            Write-Verbose -Message ($LogMessage) -Verbose
                                                  
                                                                                                            [String]$ActivityMessage = "Waiting for the decryption of Bitlocker volume `"$($VolumeFriendlyName)`" [DriveLetter: $($BitlockerVolumeInfo.MountPoint)] to complete."
                                                                                                            [String]$StatusMessage = "$($ActivityMessage) - $($BitlockerVolumeInfo.EncryptionPercentage)%"
                                                                                                            Write-Progress -Activity ($ActivityMessage) -Status ($StatusMessage) -PercentComplete ($BitlockerVolumeInfo.EncryptionPercentage)
                                                          
                                                                                                            [Int]$SecondsToWait = 30
                                                                                                      
                                                                                                            $LogMessage = "Pausing script execution for $($SecondsToWait) second(s). Please Wait..."
                                                                                                            Write-Verbose -Message ($LogMessage) -Verbose
                                                                                                      
                                                                                                            $Null = Start-Sleep -Seconds ($SecondsToWait)
                                                                                                        }
                                                                                                  }   
                                                                                            }
                                                                                          Until
                                                                                            ((Get-BitLockerVolume -MountPoint ($BitlockerVolumeInfo.MountPoint)).VolumeStatus -imatch $VolumeStatusExpression.ToString())
                                          
                                                                                          Write-Progress -Activity ($ActivityMessage) -Completed
                                                                                      }
                                                                                    Catch
                                                                                      {
                                                                                          If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message -Join "`r`n`r`n")"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                                                                                          $ErrorMessage = "[Error Message: $($ExceptionMessage)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                                                                                          Write-Error -Message "$($ErrorMessage)"
                                                                                      }
                                                                                }
                                                                          }
                                                                    }
                                                              }
                                                        }
                                                        
                                                      {($_ -eq $False)}
                                                        {
                                                            [String]$WarningMessage = "Volume `"$($VolumeFriendlyName)`" [DriveLetter: $($VolumeDriveLetter)] is not a Bitlocker enabled volume. Skipping."
                                                            Write-Warning -Message ($WarningMessage) -Verbose
                                                        }
                                                  }
                                            }
                                             
                                          {($_ -eq $False)}
                                            {
                                                [String]$WarningMessage = "Volume `"$($VolumeFriendlyName)`" [DriveLetter: $($VolumeDriveLetter)] has a drive letter that does not match the regular expression of `"$($DriveLetterInclusionExpression.ToString())`" and matches the regular expression of `"$($DriveLetterExclusionExpression.ToString())`". Skipping."
                                                Write-Warning -Message ($WarningMessage) -Verbose
                                            }
                                      }
                                }
                                
                              {($_ -eq $False)}
                                {
                                    [String]$WarningMessage = "Volume `"$($VolumeFriendlyName)`" [DriveLetter: $($VolumeDriveLetter)] has a drive type of `"$($Volume.DriveType)`" and does not match the regular expression of `"$($DriveTypeExpression.ToString())`". Skipping."
                                    Write-Warning -Message ($WarningMessage) -Verbose
                                }
                          }
                    }
                    
                  Switch ($True)
                    {              
                        {($Script:BitlockerVolumeCount -gt 0)}
                          {
                              $LogMessage = "Attempting to clear Bitlocker auto unlock protector(s). Please Wait..."
                              Write-Verbose -Message ($LogMessage) -Verbose
                      
                              $Null = Clear-BitLockerAutoUnlock -ErrorAction Continue
                      
                              $TPMInformation = Get-TPM -ErrorAction SilentlyContinue
                              
                              Switch ($Null -ine $TPMInformation)
                                {
                                    {($_ -eq $True)}
                                      {
                                          Switch ($TPMInformation.OwnerClearDisabled)
                                            {
                                                {($_ -eq $True)}
                                                  {
                                                      $LogMessage = "The TPM cannot be cleared from within the operating system. No further action will be taken."
                                                      Write-Verbose -Message ($LogMessage) -Verbose
                                                  }
                                
                                                {($_ -eq $False)}
                                                  {
                                                      $LogMessage = "Attempting to clear the TPM and disable auto-provisioning. Please Wait..."
                                                      Write-Verbose -Message ($LogMessage) -Verbose
                            
                                                      Try
                                                        {
                                                            $Null = Disable-TPMAutoProvisioning
                                      
                                                            $Null = Clear-TPM
                                                        }
                                                      Catch
                                                        {
                                                            If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message -Join "`r`n`r`n")"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                                                            $ErrorMessage = "[Error Message: $($ExceptionMessage)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                                                            Write-Error -Message "$($ErrorMessage)" 
                                                        }
                                                  }
                                            }
                                      }
                                      
                                    {($_ -eq $False)}
                                      {
                                          [String]$WarningMessage = "A TPM could not be detected on device `"$($Env:ComputerName)`"."
                                          Write-Warning -Message ($WarningMessage) -Verbose
                                      }
                                }
                          }
                          
                        {($Script:BitlockerVolumeCount -eq 0)}
                          {
                              [String]$WarningMessage = "$($Script:BitlockerVolumeCount) Bitlocker encrypted volume(s) could be found on device `"$($Env:ComputerName)`". No further action will be taken."
                              Write-Warning -Message ($WarningMessage) -Verbose    
                          }
                    }
  
                #If necessary, create, get, and or set any task sequence variable(s).   
                  Switch ($IsRunningTaskSequence)
                    {
                        {($_ -eq $True)}
                          {
                              $LogMessage = "A task sequence is currently running.`r`n"
                              Write-Verbose -Message "$($LogMessage)" -Verbose

                              [Hashtable]$TaskSequenceVariablesToSet = @{}
                                #$TaskSequenceVariablesToSet.Add('OSDComputerName', ($XOSDComputerName))
                              
                                ForEach ($TaskSequenceVariableToSet In ($TaskSequenceVariablesToSet.GetEnumerator() | Sort-Object -Property @('Key')))
                                  {
                                      [String]$TaskSequenceVariableToSetName = "$($TaskSequenceVariableToSet.Key)"
                                      [String]$TaskSequenceVariableToSetValue = "$($TaskSequenceVariableToSet.Value)"
                                      
                                      Switch ($TaskSequenceVariableToSetName)
                                        {
                                            {($_ -imatch 'PW|Password|Passphrase|Phrase|Secret|Key')}
                                              {
                                                  [String]$LogMessage = "Attempting to set the task sequence variable of `"$($TaskSequenceVariableToSetName)`" to the specified value. Please Wait...`r`n"
                                                  Write-Verbose -Message "$($LogMessage)" -Verbose
                                              }
                                              
                                            Default
                                              {
                                                  [String]$LogMessage = "Attempting to set the task sequence variable of `"$($TaskSequenceVariableToSetName)`" to a value of `"$($TaskSequenceVariableToSetValue)`". Please Wait...`r`n"
                                                  Write-Verbose -Message "$($LogMessage)" -Verbose
                                              }
                                        }
                                                                              
                                      $Null = $TSEnvironment.Value($TaskSequenceVariableToSetName) = "$($TaskSequenceVariableToSetValue)"       
                                  }        
                          }
                        
                        {($_ -eq $False)}
                          {
                              $LogMessage = "There is no task sequence running.`r`n"
                              Write-Verbose -Message "$($LogMessage)"
                          }
                    }
                  
                #Determine the date and time the function completed execution
                  $ScriptEndTime = (Get-Date)

                  $LogMessage = "Script execution of `"$($CmdletName)`" ended on $($ScriptEndTime.ToString($DateTimeLogFormat))"
                  Write-Verbose -Message $LogMessage -Verbose

                #Log the total script execution time  
                  $ScriptExecutionTimespan = New-TimeSpan -Start ($ScriptStartTime) -End ($ScriptEndTime)

                  $LogMessage = "Script execution took $($ScriptExecutionTimespan.Hours.ToString()) hour(s), $($ScriptExecutionTimespan.Minutes.ToString()) minute(s), $($ScriptExecutionTimespan.Seconds.ToString()) second(s), and $($ScriptExecutionTimespan.Milliseconds.ToString()) millisecond(s)"
                  Write-Verbose -Message $LogMessage -Verbose
                    
                  $LogMessage = "Script `"$($CmdletName)`" is completed."
                  Write-Verbose -Message $LogMessage -Verbose
        
                #Stop transcripting (Logging)
                  Try
                    {
                        [Int]$Script:ErrorCode = 0
                      
                        [String]$WarningMessage = "Exiting script `"$($ScriptPath.FullName)`" with exit code $($Script:ErrorCode)."
                        Write-Warning -Message ($WarningMessage) -Verbose
                        
                        Stop-Transcript -Verbose
                  
                        #$Null = [System.Environment]::Exit($Script:ErrorCode)
                    }
                  Catch
                    {
                        If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message)"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                        $ErrorMessage = "[Error Message: $($ExceptionMessage)][ScriptName: $($_.InvocationInfo.ScriptName)][Line Number: $($_.InvocationInfo.ScriptLineNumber)][Line Position: $($_.InvocationInfo.OffsetInLine)][Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                        Write-Error -Message "$($ErrorMessage)"
                    }
            }
          Catch
            {
                If ([String]::IsNullOrEmpty($_.Exception.Message)) {$ExceptionMessage = "$($_.Exception.Errors.Message -Join "`r`n`r`n")"} Else {$ExceptionMessage = "$($_.Exception.Message)"}
          
                $ErrorMessage = "[Error Message: $($ExceptionMessage)]`r`n`r`n[ScriptName: $($_.InvocationInfo.ScriptName)]`r`n[Line Number: $($_.InvocationInfo.ScriptLineNumber)]`r`n[Line Position: $($_.InvocationInfo.OffsetInLine)]`r`n[Code: $($_.InvocationInfo.Line.Trim())]`r`n"
                Write-Error -Message "$($ErrorMessage)" -ErrorAction Continue
        
                If ($ContinueOnError.IsPresent -eq $False)
                  { 
                      If ([String]::IsNullOrEmpty($Script:ErrorCode) -eq $True)
                        {
                            [Int]$Script:ErrorCode = $ErrorCodeRange.GetValue(0)
                        }
                        
                      [String]$WarningMessage = "Exiting script `"$($ScriptPath.FullName)`" with exit code $($Script:ErrorCode)."
                      Write-Warning -Message ($WarningMessage) -Verbose
                      
                      Stop-Transcript -Verbose
                  
                      $Null = [System.Environment]::Exit($Script:ErrorCode)
                  }
                Else
                  {
                      Stop-Transcript -Verbose
                  }
            }
    }
