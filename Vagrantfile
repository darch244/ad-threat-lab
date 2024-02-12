# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# ad-threat-lab — 3-Tier Enterprise Active Directory attack simulation sandbox.
#
#   DC01        Windows Server 2022  ->  Domain Controller (CORP.LOCAL)
#   WS01        Windows 11           ->  Domain-joined workstation
#   UBUNTU-SEC  Ubuntu 22.04         ->  Attacker / Audit host
#
# Usage:
#   vagrant up                      # full 3-node lab
#   vagrant provision dc01          # re-run domain provisioning
#   vagrant destroy -f              # tear everything down
#
# Requirements: Vagrant 2.3+, VirtualBox 7+ (or libvirt via the --provider flag).

VAGRANTFILE_API_VERSION = "2"

LAB_NETWORK = "192.168.56.0/24"
DC01_IP  = "192.168.56.10"
WS01_IP  = "192.168.56.20"
SEC_IP   = "192.168.56.30"

CORP_MEMORY   = 4096
CORP_CPUS     = 2
WS_MEMORY     = 2048
SEC_MEMORY    = 2048
SEC_CPUS      = 2

DSRM_PASSWORD = ENV["AD_LAB_DSRM"] || "Dsrc!Corp2k22"
ADMIN_USER    = ENV["AD_LAB_ADMIN"] || "vagrant"
ADMIN_PASS    = ENV["AD_LAB_ADMIN_PASS"] || "Vagrant!Lab22445"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # ---- Common SSH settings for the Linux host -----------------------------
  config.ssh.username = "vagrant"

  # ------------------------------------------------------------------------
  # DC01 - Windows Server 2022 Domain Controller
  # ------------------------------------------------------------------------
  config.vm.define "dc01" do |dc|
    dc.vm.box = "gusztavvargadr/windows-server-2022-standard"
    dc.vm.hostname = "DC01"
    dc.vm.network "private_network", ip: DC01_IP
    dc.vm.synced_folder ".", "C:\\lab", type: "smb", smb_username: ADMIN_USER,
                         smb_password: ADMIN_PASS, mount_options: ["vers=3.0"]

    dc.vm.provider "virtualbox" do |vb|
      vb.name = "ad-threat-lab-dc01"
      vb.memory = CORP_MEMORY
      vb.cpus = CORP_CPUS
      vb.gui = false
      vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
      vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    end

    # Windows provisioners run over WinRM.
    dc.vm.boot_timeout = 1200
    dc.winrm.username = ADMIN_USER
    dc.winrm.password = ADMIN_PASS

    # Disable the password-expiry / first-login wall that stalls WinRM.
    dc.vm.provision "shell", inline: <<-SCRIPT
      $u = [adsi]"WinNT://localhost/Administrator,user"
      $u.SetPassword("#{ADMIN_PASS}")
      $u.SetInfo()
      net user Administrator "#{ADMIN_PASS}" /active:yes
      reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f
      Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" `
        -Name AutoAdminLogon -Value 1
      Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" `
        -Name DefaultUserName -Value "Administrator"
      Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" `
        -Name DefaultPassword -Value "#{ADMIN_PASS}"
      Set-ExecutionPolicy Bypass -Scope Process -Force
    SCRIPT

    # Provision the AD forest. Re-runnable: provision.ps1 is idempotent.
    dc.vm.provision "shell", path: "automation/provision.ps1", args: [
      "-DsrmPassword", DSRM_PASSWORD,
      "-LabNetwork", LAB_NETWORK,
    ]
  end

  # ------------------------------------------------------------------------
  # WS01 - Windows 11 domain-joined workstation
  # ------------------------------------------------------------------------
  config.vm.define "ws01" do |ws|
    ws.vm.box = "gusztavvargadr/windows-11-enterprise"
    ws.vm.hostname = "WS01"
    ws.vm.network "private_network", ip: WS01_IP
    ws.vm.synced_folder ".", "C:\\lab", type: "smb", smb_username: ADMIN_USER,
                         smb_password: ADMIN_PASS, mount_options: ["vers=3.0"]

    ws.vm.provider "virtualbox" do |vb|
      vb.name = "ad-threat-lab-ws01"
      vb.memory = WS_MEMORY
      vb.cpus = 2
      vb.gui = false
    end
    ws.vm.boot_timeout = 1200
    ws.winrm.username = ADMIN_USER
    ws.winrm.password = ADMIN_PASS

    ws.vm.provision "shell", inline: <<-SCRIPT
      Set-ExecutionPolicy Bypass -Scope Process -Force
      net user Administrator "#{ADMIN_PASS}" /active:yes
    SCRIPT

    # Join the machine to CORP.LOCAL and reboot. Placement into a Tier-1 OU
    # communicates "workstation" to the tiering model used by the acl_scanner.
    ws.vm.provision "shell", inline: <<-SCRIPT
      $ErrorActionPreference = "Stop"
      $pass = ConvertTo-SecureString "#{ADMIN_PASS}" -AsPlainText -Force
      $cred = New-Object System.Management.Automation.PSCredential("CORP\\#{ADMIN_USER}", $pass)
      Add-Computer -DomainName "corp.local" -Credential $cred -OUPath "OU=Computers,OU=Tier1,DC=corp,DC=local" -Restart
    SCRIPT
  end

  # ------------------------------------------------------------------------
  # UBUNTU-SEC - Attacker / Audit host
  # ------------------------------------------------------------------------
  config.vm.define "ubuntu-sec" do |sec|
    sec.vm.box = "generic/ubuntu2204"
    sec.vm.hostname = "UBUNTU-SEC"
    sec.vm.network "private_network", ip: SEC_IP
    sec.vm.synced_folder ".", "/opt/ad-threat-lab"

    sec.vm.provider "virtualbox" do |vb|
      vb.name = "ad-threat-lab-ubuntu-sec"
      vb.memory = SEC_MEMORY
      vb.cpus = SEC_CPUS
      vb.gui = false
    end

    sec.vm.provision "shell", inline: <<-SCRIPT
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq python3-pip python3-venv git nmap masscan dnsutils \
        krb5-user smbclient ldap-utils libpam-krb5 netcat-openbsd jq
      cd /opt/ad-threat-lab
      python3 -m venv .venv
      .venv/bin/pip install --upgrade pip -q
      .venv/bin/pip install -r requirements.txt -q
      # Offensive tooling used by the playbooks (attacker-host toolset):
      .venv/bin/pip install impacket ldap3 -q          # included via requirements
      # BloodHound/SharpHound, Rubeus & Mimikatz are typically run from DC01/WS01
      # or a Windows jump host; see playbooks for exact usage + defensive artifacts.
      echo "UBUNTU-SEC ready." | tee /tmp/ubuntu-sec-ready
    SCRIPT
  end
end