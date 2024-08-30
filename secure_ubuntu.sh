#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Bitte führen Sie das Skript als root aus."
  exit
fi

# Update and upgrade the system
echo "System wird aktualisiert und auf den neuesten Stand gebracht..."
apt-get update && apt-get upgrade -y

# SSH Configuration
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.old"

echo "Eine Sicherung der aktuellen SSHD-Konfiguration wird erstellt..."
cp $SSHD_CONFIG $SSHD_BACKUP

# Function to update SSHD config
update_sshd_config() {
  echo "SSH Konfiguration wird angepasst..."

  # Port
  read -p "Möchten Sie den SSH-Port auf 2222 ändern? (y/n): " change_port
  if [[ "$change_port" == "y" ]]; then
    sed -i "/^#Port 22/c\Port 2222" $SSHD_CONFIG
  fi

  # PermitRootLogin
  read -p "Möchten Sie den Root-Login verbieten? (y/n): " permit_root_login
  if [[ "$permit_root_login" == "y" ]]; then
    sed -i "/^#PermitRootLogin prohibit-password/c\PermitRootLogin no" $SSHD_CONFIG
  fi

  # AllowUsers
  read -p "Geben Sie die Benutzer ein, die SSH-Zugang haben sollen (getrennt durch Leerzeichen): " ssh_users
  if [[ ! -z "$ssh_users" ]]; then
    sed -i "/^#AllowUsers/c\AllowUsers $ssh_users" $SSHD_CONFIG
  fi

  # PubkeyAuthentication
  sed -i "/^#PubkeyAuthentication/c\PubkeyAuthentication yes" $SSHD_CONFIG

  # AuthenticationMethods
  sed -i "/^#AuthenticationMethods/c\AuthenticationMethods publickey,keyboard-interactive" $SSHD_CONFIG

  # AuthorizedKeysFile
  sed -i "/^#AuthorizedKeysFile/c\AuthorizedKeysFile .ssh/authorized_keys" $SSHD_CONFIG

  # PasswordAuthentication
  read -p "Möchten Sie die Passwortauthentifizierung deaktivieren und nur SSH-Schlüsselauthentifizierung zulassen? (y/n): " disable_password_auth
  if [[ "$disable_password_auth" == "y" ]]; then
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' $SSHD_CONFIG
  fi

  # Check for duplicate entries
  awk '!seen[$0]++' $SSHD_CONFIG > temp && mv temp $SSHD_CONFIG

  echo "Die SSHD-Konfiguration wurde aktualisiert und überprüft."
  echo "Die alte Konfiguration wurde in $SSHD_BACKUP gespeichert."
}

update_sshd_config

# Fail2Ban Installation
echo "Fail2Ban ist ein Tool zur Verhinderung von Brute-Force-Angriffen."
read -p "Möchten Sie Fail2Ban installieren? (y/n): " install_fail2ban
if [[ "$install_fail2ban" == "y" ]]; then
  apt-get install fail2ban -y

  echo "[sshd]
enabled = true
port = 2222
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600" > /etc/fail2ban/jail.local

  systemctl restart fail2ban
  echo "Fail2Ban wurde installiert und konfiguriert."
fi

# Unattended Security Updates
echo "Automatische Sicherheitsupdates stellen sicher, dass Ihr System immer auf dem neuesten Stand ist."
read -p "Möchten Sie automatische Sicherheitsupdates aktivieren? (y/n): " install_unattended_upgrades
if [[ "$install_unattended_upgrades" == "y" ]]; then
  apt-get install unattended-upgrades -y
  dpkg-reconfigure -plow unattended-upgrades

  sed -i 's|//\ "${distro_id}:${distro_codename}-security";|    "${distro_id}:${distro_codename}-security";|' /etc/apt/apt.conf.d/50unattended-upgrades
  sed -i 's|Unattended-Upgrade::Mail "root@localhost";|// Unattended-Upgrade::Mail "my_user@my_domain.com";|' /etc/apt/apt.conf.d/50unattended-upgrades

  echo "Automatische Sicherheitsupdates wurden aktiviert."
fi

# xautolock und i3lock Installation
echo "Automatisches Sperren des Bildschirms erhöht die physische Sicherheit."
apt-get install xautolock i3lock -y
echo 'xautolock -time 5 -locker "i3lock" &' >> ~/.xsession
echo "Bildschirm wird nach 5 Minuten Inaktivität automatisch gesperrt."

# SWAP File Setup
echo "Prüfen, ob ein SWAP-File existiert..."
if ! swapon -s | grep -q "swapfile"; then
  echo "Kein SWAP-File gefunden. Erstellen eines 4G SWAP-Files..."
  fallocate -l 4G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
  echo "0" > /proc/sys/vm/swappiness
  echo "vm.swappiness = 0" >> /etc/sysctl.conf
  echo "SWAP-File wurde erstellt und aktiviert."
else
  echo "SWAP-File ist bereits vorhanden."
fi

# IP Spoofing Schutz
echo "IP-Spoofing-Schutz wird eingerichtet..."
echo -e "order bind,hosts\nnospoof on" >> /etc/host.conf
echo "IP-Spoofing-Schutz wurde aktiviert."

# UFW Firewall Konfiguration
echo "Eine Firewall schützt Ihr System vor unerwünschtem Datenverkehr."
read -p "Möchten Sie die UFW-Firewall konfigurieren? (y/n): " configure_ufw
if [[ "$configure_ufw" == "y" ]]; then
  apt-get install ufw -y
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 2222/tcp
  ufw enable
  echo "UFW-Firewall wurde konfiguriert."
fi

# Intrusion Detection System (IDS)
echo "Ein Intrusion Detection System (IDS) kann unerwünschte Systemänderungen erkennen."
read -p "Möchten Sie AIDE (Advanced Intrusion Detection Environment) installieren und konfigurieren? (y/n): " install_aide
if [[ "$install_aide" == "y" ]]; then
  apt-get install aide -y
  aideinit
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  echo "AIDE wurde installiert und initialisiert."
fi

# NTP Konfiguration
echo "Die Synchronisation der Systemzeit ist wichtig für Protokollierung und Überwachung."
read -p "Möchten Sie den NTP-Dienst installieren? (y/n): " install_ntp
if [[ "$install_ntp" == "y" ]]; then
  apt-get install ntp -y
  echo "NTP-Dienst wurde installiert und konfiguriert."
fi

# IPv6 deaktivieren (falls nicht benötigt)
echo "IPv6 deaktivieren, wenn es nicht benötigt wird, kann zusätzliche Sicherheit bieten."
read -p "Möchten Sie IPv6 deaktivieren? (y/n): " disable_ipv6
if [[ "$disable_ipv6" == "y" ]]; then
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
  sysctl -p
  echo "IPv6 wurde deaktiviert."
fi

# Rootkits-Scanner Installation
echo "Rootkits-Scanner können helfen, schädliche Software auf dem System zu erkennen."
read -p "Möchten Sie rkhunter installieren und ausführen? (y/n): " install_rkhunter
if [[ "$install_rkhunter" == "y" ]]; then
  apt-get install rkhunter -y
  rkhunter --check --skip-keypress
  echo "Rootkits-Scanner rkhunter wurde installiert und ausgeführt."
fi

# Sysctl Hardening
echo "Sicherheitsoptimierungen für den Netzwerk-Stack über sysctl."
read -p "Möchten Sie Sicherheitsoptimierungen für den Netzwerk-Stack durchführen? (y/n): " harden_sysctl
if [[ "$harden_sysctl" == "y" ]]; then
  echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
  echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
  echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
  sysctl -p
  echo "Sicherheitsoptimierungen für den Netzwerk-Stack wurden angewendet."
fi

echo "Sicherheitskonfiguration abgeschlossen!"
