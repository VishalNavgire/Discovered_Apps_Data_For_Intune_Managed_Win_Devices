<#
            .Author             - Vishal Navgire
            .Created on         - 24-Aug-2025
            .Co-Author(s)       - N/A
            .Reviwer(s)         - N/A
            .Intended Audience  - 
            .Target Device Type - Windows Machines. 

        .DESCRIPTION 
            Authenticates to Microsoft Graph API using the given Intune Admin credentials.
            Creates Discovered Apps data from all Windows devices managed via Intune report in the Csv format and saved them to parent root directory 'C:\Temp\Intune_Reporting'.
          
            Accessing Discovered Apps from Intune console requires hoping from one blade to another and finally combining them into a single csv file.

        Pre-reqs
            1. Register enterprise application in the Tenant with Delegated rights.
            2. Add API permissions as follows:
                DeviceManagementManagedDevices.Read.All
               
        References:
            https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/reports-export-graph-available-reports#next-steps  
            https://learn.microsoft.com/en-us/graph/permissions-reference#reportsreadall 


            Version Control:
            24-Aug-2025 :: v1.0
#>
Function Install-MgGraph-WithUsageTracking 
    {

        <#
            .Author - Vishal Navgire
            .Created on - 31-May-2025
            .Co-Author(s)       - N/A
            .Reviwer(s)         - N/A
            .Intended Audience  - 
            .Target Device Type - Windows Machines. 

        .DESCRIPTION 
         1. Installs Microsoft Graph module that contains following sub modules :
                Microsoft.Graph
                Microsoft.Graph.Applications
                Microsoft.Graph.Authentication
                Microsoft.Graph.BackupRestore
                Microsoft.Graph.Beta.DeviceManagement
                Microsoft.Graph.Bookings
                Microsoft.Graph.Calendar
                Microsoft.Graph.ChangeNotifications
                Microsoft.Graph.CloudCommunications
                Microsoft.Graph.Compliance
                Microsoft.Graph.CrossDeviceExperiences
                Microsoft.Graph.DeviceManagement
                Microsoft.Graph.DeviceManagement.Administration
                Microsoft.Graph.DeviceManagement.Enrollment
                Microsoft.Graph.DeviceManagement.Functions
                Microsoft.Graph.Devices.CloudPrint
                Microsoft.Graph.Devices.CorporateManagement
                Microsoft.Graph.Devices.ServiceAnnouncement
                Microsoft.Graph.DirectoryObjects
                Microsoft.Graph.Education
                Microsoft.Graph.Files
                Microsoft.Graph.Groups
                Microsoft.Graph.Identity.DirectoryManagement
                Microsoft.Graph.Identity.Governance
                Microsoft.Graph.Identity.Partner
                Microsoft.Graph.Identity.SignIns
                Microsoft.Graph.Mail
                Microsoft.Graph.Notes
                Microsoft.Graph.People
                Microsoft.Graph.PersonalContacts
                Microsoft.Graph.Planner
                Microsoft.Graph.Reports
                Microsoft.Graph.SchemaExtensions
                Microsoft.Graph.Search
                Microsoft.Graph.Security
                Microsoft.Graph.Sites
                Microsoft.Graph.Teams
                Microsoft.Graph.Users
                Microsoft.Graph.Users.Actions
                Microsoft.Graph.Users.Functions

            2. Scope of module installation :  
            The scope (CurrentUser vs AllUsers) only determines where the module is installed:
            CurrentUser: Installs to the user's profile ($env:USERPROFILE\Documents\PowerShell\Modules)
            AllUsers: Installs to a system-wide location (C:\Program Files\PowerShell\Modules)

            3. Tracks N/w consumption. 

    Pre-reqs :
    Register an Enterprise application in your tenant with Delegated access. 

    Version Control:
    31-May-2025 :: v1.0

        #>
        [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory=$true)]
                    [string]$TenantId,

                    [Parameter(Mandatory=$true)]
                    [string]$EnterpriseAppId
                )

        Function Get-NetworkUsage 
            {
                $Stats = Get-NetAdapterStatistics
                return  ($Stats | Measure-Object -Property ReceivedBytes -Sum).Sum +
                        ($Stats | Measure-Object -Property SentBytes -Sum).Sum
            }

        # Ensure script is running as Administrator
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
            {
                Write-Error "Please run this script as Administrator."
                return
            }

        # Record network usage before operation
        $BeforeUsage = Get-NetworkUsage

        # Check Microsoft.Graph module status
        $InstalledVersion = (Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)
        $OnlineVersion    = (Find-Module -Name Microsoft.Graph -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)

        If ($InstalledVersion -eq $OnlineVersion)
            {
                Write-Host " "
                Write-Host "Microsoft.Graph module version '$InstalledVersion' is already installed." -ForegroundColor Cyan
            } 
        Else 
            {
                Write-Host "Installing or updating Microsoft.Graph module..." -ForegroundColor Yellow
                Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber

                $AfterUsage = Get-NetworkUsage
                $DataUsedBytes = $AfterUsage - $BeforeUsage
                $DataUsedMB = [math]::Round($DataUsedBytes / 1MB, 2)
                $DataUsedGB = [math]::Round($DataUsedBytes / 1GB, 2)

                Write-Host "Data consumed for Microsoft.Graph module installation: $DataUsedMB MB / $DataUsedGB GB" -ForegroundColor Green
            }

        # Connect to Microsoft Graph
        Try 
            {

                Write-Host "Authentication with Microsoft Graph is in progress. Please wait...." -F Yellow
                Write-Host " "
                Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "Reports.Read.All" -TenantId $TenantId -ClientId $EnterpriseAppId -NoWelcome -ErrorAction Stop

                $Authenticated_UPN = (Get-MgContext | Select-Object -Property Account).Account

                # Check if $Authenticated_UPN has a value (is NOT null or empty)
                If (!([string]::IsNullOrEmpty($Authenticated_UPN))) 
                    {
                        # If $Authenticated_UPN is NOT null or empty (meaning it has a value), then return $True
                        Return $True

                    } 
            }
        Catch 
            {
                Write-Warning "Failed to connect to Microsoft Graph. Check credentials or permissions."
                Return $False
            }
    }
    
$TenantId            = Read-Host "`nEnter you Tenant ID here"
$Ent_App_Id          = Read-Host "`nEnter you Enterprise App ID here"
$Ms_Garph_Connection = Install-MgGraph-WithUsageTracking -TenantId $TenantId -EnterpriseAppId $Ent_App_Id 
$stopwatch           = [System.Diagnostics.Stopwatch]::StartNew()

#Create a New folder if not exist already.
Function New-FolderCreate
    {
        [CmdletBinding()]
                        param 
                            (
                                [Parameter(Mandatory = $true)]
                                [ValidateNotNullOrEmpty()]
                                [string]$ZipFolderPath
                            )

                            begin {$null}
                        
                            process 
                                {
                                    If (-not (Test-Path -Path $ZipFolderPath)) 
                                        {
                                            Try 
                                                {
                                                    New-Item -Path $ZipFolderPath -ItemType Directory -Force | Out-Null
                                                } 
                                            Catch 
                                                {
                                                    Write-Error "Failed to create directory: $_"
                                                    Exit
                                                }
                                        }
                                }
                        
                            end {$null}
    }
Function Remove-ZipArchives 
    {
        [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
        param 
            (
                [Parameter(Mandatory = $true)]
                [ValidateScript({Test-Path $_ })]
                [string]$Path,

                [Parameter()]
                [switch]$Recurse
            )

        Begin 
            {
                # Write-Verbose "Looking for .zip files in: $Path"
            }

        Process 
            {
                $ZipFiles = Get-ChildItem -Path $Path -Filter "*.zip" -File -Recurse:$Recurse

                If ($zipFiles.Count -gt 0) 
                    {
                        $Counter = 1
                        Foreach ($Zip in $zipFiles) 
                            {
                                Remove-Item -Path $Zip.FullName -Force
                                Write-Host "$($Counter): Removed previous old ZipFile name '$($Zip.FullName).`n"
                                $Counter ++
                            }
                    }

                # Write-Host "✅ Deleted $($zipFiles.Count) ZIP file(s) from '$Path'."
            }
    }

Function Invoke-CombineCsvReports
    {
        [CmdletBinding()]
                param (
                    [Parameter(Mandatory = $true)]
                    [ValidateScript({ Test-Path $_ })]
                    [string]$ZipFolder,
            
                    [Parameter()]
                    [string]$OutputFolder = "$ZipFolder\Combined",
            
                    [Parameter()]
                    [string]$ExtractTempFolder = "$ZipFolder\Extract", 

                    [Parameter()]
                    [string]$DesignatedFileName = $Null
                )

        Begin 
            {
                # Create output and temp folders if they don't exist
                If (-not (Test-Path $OutputFolder)) 
                    {
                        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
                    }
        
                If (-not (Test-Path $ExtractTempFolder)) 
                    {
                        New-Item -ItemType Directory -Path $ExtractTempFolder -Force | Out-Null
                    }
        
                    $Timestamp = (Get-Date).ToString("dd_MMMM_yyyy_hh_mm_ss_tt")
                    $OutputCsv = Join-Path -Path $OutputFolder -ChildPath "$($DesignatedFileName)_$Timestamp.csv"
            }

        Process 
            {
                # Write-Verbose "Extracting ZIP files from: $ZipFolder"
                Get-ChildItem -Path $ZipFolder -Filter *.zip | ForEach-Object {
                                                                                    Expand-Archive -Path $_.FullName -DestinationPath $ExtractTempFolder -Force
                                                                            }
        
                # Write-Verbose "Combining CSV files..."
                $CsvFiles = Get-ChildItem -Path $ExtractTempFolder -Filter *.csv -Recurse
                $First = $True
        
                Foreach ($Csv in $CsvFiles) 
                    {
                        If ($First) 
                            {
                                Get-Content $csv.FullName | Out-File -FilePath $OutputCsv -Encoding UTF8
                                $First = $False
                            } 
                        Else 
                            {
                                Get-Content $csv.FullName | Select-Object -Skip 1 | Out-File -FilePath $OutputCsv -Append -Encoding UTF8
                            }
                    }
            }

        End 
            {
                # Write-Verbose "Cleaning up temporary extraction folder..."
                Remove-Item -Path $ExtractTempFolder -Recurse -Force
                Start-Sleep 1
        
                Write-Host "`nCSV files extracted and combined into: $OutputCsv`n" -F Green
            }
    }

Function Invoke-IntuneManagedWindowsDevicesDiscoveredApps
    {
        <#
            .Author             - Vishal Navgire
            .Created on         - 19-May-2025
            .Co-Author(s)       - N/A
            .Reviwer(s)         - N/A
            .Intended Audience  - 
            .Target Device Type - Windows Machines. 

        .DESCRIPTION 
            Authenticates to Microsoft Graph API.
            Fetches all discovered apps from each Intune managed devices.
            Exports each result to a separate CSV file named after the script.

            Pre-reqs
            Api permission DeviceManagementManagedDevices.Read.All required to be delegated on your registered MS Entra ID App.

            Version Control:
            19-May-2025 :: v1.0

        #>

        $ZipFolder = 'C:\Temp\Intune_Reporting\IntuneManaged_WindowsDevice_DiscoveredApps'

        # Ensure output directory exists
        $OutputParentDir = $ZipFolder
        New-FolderCreate -ZipFolderPath $OutputParentDir
        Remove-ZipArchives -Path $ZipFolder

        $All_Intune_Managed_Deviecs_Data =  Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/devicemanagement/manageddevices"
        $All_Windows_Intune_Managed_Deviecs_Data = ($All_Intune_Managed_Deviecs_Data.Value | Where-Object {$_.operatingSystem -eq "Windows"})

        $Counter_ForEachWinDeviceRunState = 1

        Foreach($ForEach_WinDevice in $($All_Windows_Intune_Managed_Deviecs_Data))
            {
                Write-Host "[$($Counter_ForEachWinDeviceRunState)]: Collecting Discovered Apps Info for Device Name: $($ForEach_WinDevice.DeviceName) || Intune ID: $($ForEach_WinDevice.Id.ToUpper()). " -ForegroundColor Magenta
                $Json_Payload = @{
                                    ReportName        = "AppInvByDevice"
                                    Filter            = "(DeviceId eq '$($ForEach_WinDevice.Id)')"
                                    LocalizationType  = "LocalizedValuesAsAdditionalColumn"
                                    Format            = "csv"
                                }

                $ExportJob = Invoke-MgGraphRequest -Method Post -Uri https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs -Body $($Json_Payload | ConvertTo-Json -Depth 100)

                If ($ExportJob.Status -ne "Completed" -and $ExportJob.Id)

                    {
                        Do 
                            {
                                Start-Sleep -Seconds 1
                                $ExportJobStatus = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs/$($ExportJob.Id)"
                            } 
                        While ($ExportJobStatus.Status -eq "InProgress")
                        If ($ExportJobStatus.Status -eq "Completed" -and $ExportJobStatus.url)
                                {
                                    $FileName = Join-Path -Path $OutputParentDir -ChildPath "$(($ForEach_WinDevice.DeviceName).Replace(" ","_").ToUpper()+ "_" +$($ForEach_WinDevice.Id).ToUpper()).Zip"
                                    Invoke-WebRequest -Uri $($ExportJobStatus.url) -Method Get -OutFile $FileName 
                                }
                    }
                
                $Counter_DeviceRunStatesByProactiveRemediation ++
            }
        Invoke-CombineCsvReports -ZipFolder $ZipFolder -DesignatedFileName "Intune_Managed_Windows_Device_Discovered_Apps_Report"
    }


If ($Ms_Garph_Connection -eq $True)
    { 

        Write-Host ("---" * 25) -F Yellow
        Write-Host "`nConnected to Microsoft Graph:`n" -ForegroundColor Green
        Get-MgContext | Select-Object -Property Account, TenantId, ClientId, AppName | Format-List
        Write-Host ("---" * 25) -F Yellow

        Invoke-IntuneManagedWindowsDevicesDiscoveredApps

        $Stopwatch.Stop()
        $ElapsedTime = "{0:00 Hours}:{1:00 Minutes}:{2:00 Seconds}" -f $stopwatch.Elapsed.Hours, $stopwatch.Elapsed.Minutes, $stopwatch.Elapsed.Seconds
        Write-Host "`nTotal execution time of this Powershell code : $ElapsedTime`n" -F Yellow
        
        Start-Process 'C:\Temp\Intune_Reporting'
    }
Else 
    {
        Write-Host "Failed to authenticate with Microsoft Graph API. Rerun this powershell code with valid credentials." -F Red
        Start-Sleep 5
        Exit

    }
