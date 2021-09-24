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
