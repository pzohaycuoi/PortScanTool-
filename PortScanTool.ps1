[CmdletBinding()]
param (
    # domain name for dns scan
    [Parameter(Mandatory = $true)]
    [string]
    $DomainName
)

############################### COMMON FUNCTION ###############################

# create folder for specifed domain to store result data
function New-ResultFolder {
    param (
        # define name of the folder
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        # define the path for creation of the folder
        [Parameter()]
        [string]
        $Path = ".\result\"
    )
    begin {
        $name = $Name.Replace(".", "-")
    }
    process {
        $items_in_path = Get-ChildItem -Path $Path
        if (-not ($items_in_path.name -contains $name)) {
            $folder = New-Item -Path $Path -Name $name -ItemType Directory
        }
        else {
            $folder = $items_in_path | Where-Object { $_.Name -eq $Name }
        }
    }
    end {
        return $folder
    }
}

# create child folder for each run inside the specified domain folder
function New-ChildFolder {
    param (
        # define the path for creation of the folder
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )
    begin {
        $cur_time = Get-Date -Format "ddMMyyyy-HHmmss"
    }
    process {
        $folder = New-Item -Path $Path -Name $cur_time -ItemType Directory
    }
    end {
        return $folder
    }
}

# create folder to store the actual data inside the child folder
function New-DataFolder {
    param (
        # define the path for creation of the folder
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )
    begin {}
    process {
        $dns_folder = New-Item -Path $Path -Name "dns" -ItemType Directory
        $res_dns_folder = New-Item -Path $Path -Name "resolveddns" -ItemType Directory
        $port_folder = New-Item -Path $Path -Name "port" -ItemType Directory
    }
    end {
        return $dns_folder, $res_dns_folder, $port_folder 
    }
}

# create file function
function New-File {
    param (
        # define name of the file
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        # define extenstion for the file
        [Parameter(Mandatory = $true)]
        [string]
        $Extension,
        # define the path for creation of the file
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )
    begin {
        # create name for the file
        $name = $Name.Replace(".", "-")
        $cur_time = Get-Date -Format "ddMMyyyy-HHmmss"
        $file_name = "$name-$cur_time.$Extension"
    }
    process {
        $file = New-Item -Path $Path -Name $file_name -ItemType File
    }
    end {
        return $file
    }
}

############################### LOGIC FUNCTION ###############################

# scan for sub domain
function Invoke-DNSScan {
    param (
        # input domain name for scan
        [Parameter(Mandatory = $true)]
        [string]
        $DomainName,
        # define file path to store the data
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [string]
        $FilePath
    )
    begin {}
    process {
        $null = python .\Sublist3r\sublist3r.py -d $DomainName -o $FilePath
        $data = Get-Content -Path $FilePath
    }
    end {   
        return $data
    }
}

# lookup for the dns ip address
function Invoke-FindIPAddress {
    param (
        # input dns data to lookup the ip address
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [System.Array]
        $DNS,
        # define file path to store the data
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [string]
        $FilePath
    )
    begin {}
    process {
        foreach ($dns_record in $DNS) {
            if ($dns_record -ne "") {
                Resolve-DnsName -Name $dns_record -Type A | `
                    Select-Object "Address", "IPAddress", "QueryType", "IP4Address", "Name", "Type", "CharacterSet", "Section", "DataLength", "TTL" | `
                    Export-Csv -path $FilePath -NoTypeInformation -Force -Append
                $data = Import-Csv -Path $FilePath
            }
            else {
                continue
            }
        }
    }
    end {
        return $data
    }
}

function Invoke-PortScan {
    param (
        # input ip address data to scan open port
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [System.Array]
        $DNSData,
        # define file path to store the data
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true)]
        [System.Array]
        $FilePath
    )
    begin {
        Import-Module PoshNmap
        $cname_dns_file = $FilePath[0]
        $open_port_file = $FilePath[1]
        $closed_port_file = $FilePath[2]
        $port_prop_list = @("Protocol", "Port", "State")
        $dns_record_prop_list = @("IP4Address", "Name", "QueryType", "Section", "TTL")
        $port_general_prop_list = @("OpenPorts")
    }
    process {
        # nmap scan for open port
        foreach ($dns_record in $DNSData) {
            if ($dns_record.QueryType -ne "CNAME") {
                $nmap_scan = Invoke-Nmap $dns_record.Address | Select-Object Status, OpenPorts, Ports
                if ($null -ne $nmap_scan) {
                    foreach ($port in $nmap_scan.Ports) {
                        $finalized_object = [PSCustomObject]@{}
                        foreach ($dns_record_prop in $dns_record_prop_list) {
                            $finalized_object | Add-Member -Name $dns_record_prop -Type NoteProperty -Value $dns_record.$dns_record_prop -Force
                        }
                        foreach ($port_general_prop in $port_general_prop_list) {
                            $finalized_object | Add-Member -Name $port_general_prop -Type NoteProperty -Value $nmap_scan.$port_general_prop -Force
                        }
                        foreach ($port_prop in $port_prop_list) {
                            $finalized_object | Add-Member -Name $port_prop -Type NoteProperty -Value $port.$port_prop -Force
                        }
                        # because the services property is an object so need to loop to get the data
                        $serviceStrList = ""
                        foreach ($service in $nmap_scan.ports.services.name) {
                            $serviceStrList += "$service,"
                        }
                        $serviceStrList = $serviceStrList.Substring(0,$serviceStrList.Length-1) # delete last "," char
                        $finalized_object | Add-Member -Name "Services" -Type NoteProperty -Value $serviceStrList -Force
                        $finalized_object | Export-Csv -path $open_port_file -NoTypeInformation -Force -Append 
                    }   
                }
                else {
                    $dns_record | Export-Csv -path $closed_port_file -NoTypeInformation -Force -Append
                }
            }
            else {
                $dns_record | Export-Csv -path $cname_dns_file -NoTypeInformation -Force -Append
            }
        }
        $cname_data = Import-Csv -Path $cname_dns_file
        $open_port_data = Import-Csv -Path $open_port_file
        $closed_port_data = Import-Csv -Path $closed_port_file
    }
    end {
        return $cname_data, $open_port_data, $closed_port_data
    }
}

############################### PROCESS ###############################

# create all needed folders
$result_folder = New-ResultFolder -Name $DomainName
$child_folder = New-ChildFolder -Path $result_folder.FullName
$dns_folder, $res_dns_folder, $port_folder = New-DataFolder -Path $child_folder

# create all needed files
$dns_file = New-File -Name $DomainName -Path $dns_folder -Extension "txt"
$res_dns_file = New-File -Name "$DomainName-res-dns" -Path $res_dns_folder -Extension "csv"
$cname_dns_file = New-File -Name "$DomainName-cname" -Path $res_dns_folder -Extension "csv"
$open_port_file = New-File -Name "$DomainName-open-port" -Path $port_folder -Extension "csv"
$closed_port_file = New-File -Name "$DomainName-closed-port" -Path $port_folder -Extension "csv"

# dns scan
$dns_scan = Invoke-DNSScan -DomainName $DomainName -FilePath $dns_file.FullName

# lookup 
$nslookup = Invoke-FindIPAddress -DNS $dns_scan -FilePath $res_dns_file

# port scan
$FilePaths = @($cname_dns_file.FullName, $open_port_file.FullName, $closed_port_file.FullName) # file path array to store the data
Invoke-PortScan -DNSData $nslookup -FilePath $FilePaths
