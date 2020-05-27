#!/bin/bash
if [ "$EUID" -ne 0 ]; then
	echo "Script must be run as root"
	exit 1
fi

#1.1.1 unload filesystems
if [ ! -f /etc/modprobe.d/CIS.conf ]; then
	touch /etc/modprobe.d/CIS.conf
fi

for i in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat; do
	if ! grep -q "install $i /bin/true" /etc/modprobe.d/CIS.conf; then
		echo "install $i /bin/true" >> /etc/modprobe.d/CIS.conf
		rmmod $i
	fi
done

#1.1.2 Separate partiion for /tmp
if [[ ! $(mount | grep -G "\s/tmp\s") ]]; then
	echo "1.1.2 /tmp must be on a sperate partition, not fixing"
	exit 1
fi

#1.1.3,4,5 nodev,nosuid,noexec for /tmp
tmp_array=($(awk '/\s\/tmp\s/{print $0}' < /etc/fstab))
if [[ ${tmp_array[3]} != "defaults,nodev,nosuid,noexec" ]]; then
	sed -i '/\s\/tmp\s/d' /etc/fstab
	tmp_array[3]="defaults,nodev,nosuid,noexec"
	new_tmp=$(printf "%s " "${tmp_array[@]}")
	echo $new_tmp >> /etc/fstab
fi

#1.1.6 Separate partition for /var
if [[ ! $(mount | grep -G "\s/var\s") ]]; then
        echo "1.1.6 /var must be on a sperate partition, not fixing"
        exit 1
fi

#1.1.7 Separate partiton for /var/tmp, bind to /tmp to fix 1.1.8,9,10
if [[ ! $(mount | grep -G "\s/var/tmp\s") ]]; then
	echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab	
fi

#1.1.11,12,13
for i in /home /var/log /var/log/audit; do
	if [[ ! $(mount | grep -G "\s$i\s") ]]; then
		echo "$i must be on a separate partition, not fixing"
		exit 1
	fi

done

#1.1.14 Ensure nodev on /home
tmp_array=($(awk '/\s\/home\s/{print $0}' < /etc/fstab))
if [[ ${tmp_array[3]} != "defaults,nodev" ]]; then
        sed -i '/\s\/home\s/d' /etc/fstab
        tmp_array[3]="defaults,nodev"
        new_tmp=$(printf "%s " "${tmp_array[@]}")
        echo $new_tmp >> /etc/fstab
fi

#1.1.15,16,17 Ensure nodev,nosuid,noexec
if ! grep -q "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" /etc/fstab; then
	sed -i '/\s\/dev\/shm\s/d' /etc/fstab
	echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
fi

#1.1.21 Ensure sticky bit is set on all world-writable directories
if [[ $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null) ]]; then
	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
fi

#1.1.22 Disable automounting
systemctl disable autofs 2>/dev/null

#1.2.1,2 Ensure package manager repositories are configured and gpg keys are configured
#yum repolist -q
#rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'
#read -t 10 -p "Verify gpg + repo, will continue in 10s"

#1.2.3 Ensure gpgcheck is globally activated
grep -Gq ^gpgcheck=1 /etc/yum.conf
if [ $? -ne 0 ]; then
	sed -i '/gpgcheck=/g' /etc/yum.conf
	echo "gpgcheck=1" >> /etc/yum.conf
fi

#1.3.1 Install aide
rpm --quiet -q aide || yum -y -q install aide
if [ ! -f /var/lib/aide/aide.db.gz ]; then
	aide --init
	mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

#1.3.2 Ensure filesystem integrity is regularly checked
if [[ ! $(crontab -u root -l 2>/dev/null | grep aide) ]]; then
	(crontab -l && echo "0 5 * * * /usr/sbin/aide --check") | crontab -u root -
fi

#1.4.1 Ensure permission on bootloader config are configured
if [ -f /boot/grub2/grub.cfg ]; then
	chown root:root /boot/grub2/grub.cfg
	chmod og-rwx /boot/grub2/grub.cfg
fi

if [ -f /boot/grub2/user.cfg ]; then
	chown root:root /boot/grub2/user.cfg
	chmod og-rwx /boot/grub2/user.cfg
fi

#1.4.2 Ensure bootloader password is set
grep -q "^GRUB2_PASSWORD" /boot/grub2/user.cfg
if [ $? -ne 0 ]; then
	echo "Grub password must be set"
	grub2-setpassword
fi

#1.4.3 Ensure authentication required for single user mode
if ! grep -q "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" /usr/lib/systemd/system/rescue.service; then
	sed -i '/^ExecStart=.*\/usr\/bin\/systemctl/d' /usr/lib/systemd/system/rescue.service
	sed -i '/Type\=idle/i ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"' /usr/lib/systemd/system/rescue.service
fi

if ! grep -q "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" /usr/lib/systemd/system/emergency.service; then
	sed -i '/^ExecStart=.*\/usr\/bin\/systemctl/d' /usr/lib/systemd/system/emergency.service
        sed -i '/Type\=idle/i ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"' /usr/lib/systemd/system/emergency.service
fi

#1.5.1 Ensure core dumps are restricted
if ! grep -q "hard core" /etc/security/limits.conf /etc/security/limits.d/*; then
	echo "* hard core 0" >> /etc/security/limits.d/10-CIS.conf
fi

grep -q "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
if [ $? -ne 0 ] && [[ $(sysctl fs.suid_dumpable) == "fs.suid_dumpable = 0" ]]; then
	echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/CIS.conf 
	sysctl -w fs.suid_dumpable=0
fi

#1.5.3 Ensure address space layout randomization (ASLR) is enabled
grep -q "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
if [ $? -ne 0 ] && [[ $(sysctl kernel.randomize_va_space) == "kernel.randomize_va_space = 2" ]]; then
	echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/CIS.conf
	sysctl -w kernel.randomize_va_space=2
fi

#1.5.4 Ensure prelink is disabled
if rpm -q --quiet prelink; then
	prelink -ua
	yum remove prelink -y -q
fi

#1.6.1 Ensure SELinux is not disabled in bootloader config
if grep -iE "enforcing\s?=\s?0\|selinux\s?=\s?0" /boot/grub2/grub.cfg; then
	sed -i -r 's/selinux\s?=\s?0//g' /etc/default/grub
	sed -i -r 's/enforcing\s?=\s?0//g' /etc/default/grub
	grub2-mkconfig -o /boot/grub2/grub.cfg
fi

#1.6.1.2 Ensur SELinux state is enforcing
if ! grep -q "SELINUX=enforcing" /etc/selinux/config; then
	sed -i '/SELINUX=/g' /etc/selinux/config
	echo "SELINUX=enforcing" >> /etc/selinux/config
fi

#1.6.1.3 Ensure SELinux policy is configured
if ! grep -q "SELINUXTYPE=targeted" /etc/selinux/config; then
	sed -i '/SELINUXTYPE=/g' /etc/selinux/config
	echo "SELINUXTYPE=targeted" >> /etc/selinux/config 
fi

#1.6.1.4,5 Ensure SETroubleshoot + MCS Translation Service is not installed
for i in setroubleshoot mcstrans; do
	if rpm -q --quiet $i; then
        	yum remove $i -y -q
	fi
done

#1.6.1.6 Ensure no unconfied daemons exist
if [[ $(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }') ]]; then
	echo "Investigate unconfied daemons. They may need to have an existing security context assigned to them or a policy built from them."
fi

#1.6.2 Ensure SELinux is installed
rpm --quiet -q libselinux || yum -y -q install libselinux

#1.7.1.1 #Esnure motd is configured
if [[ $(egrep '(\\v|\\r|\\m|\\s)' /etc/motd) ]]; then
	echo "/etc/motd needs fixing, adding temporary solution"
	echo "MOTD" >> /etc/motd
fi

#1.7.1.2 Ensure local warning banner
if [[ $(egrep '(\\v|\\r|\\m|\\s)' /etc/issue) ]]; then
	echo "/etc/issue need fixing, adding temporary solution"
	truncate -s 0 /etc/issue
	echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue
fi

#1.7.1.3 Ensure remote login warning banner is configured properly
if [[ $(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net) ]]; then
	echo "/etc/issue.net need fixing, adding temporary solution"
	truncate -s 0 /etc/issue.net
	echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue.net
fi

#1.7.1.4,5,6 Ensure permission on /etc/{motd,issue,issue.net} are configured
for i in motd issue issue.net; do
	if [ -f /etc/$i ]; then
		chown root:root /etc/$i
		chmod 644 /etc/$i
	fi
done

#1.8 Ensure updates, patches and additional security software are installed
yum check-update -q --security
if [ $? -ne 0 ]; then
	yum update --security -y -q
fi

#2.1.1,2,3,4,5,6,7 inetd Services
for i in chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream time-dgram time-stream tftp xinetd; do
	if [[ $(systemctl is-enabled $i 2>/dev/null) == "enabled" ]]; then
		systemctl disable $i
	fi
done

#2.2.1.1 Ensure time sync is in use
rpm --quiet -q chrony || yum -y -q install chrony

#2.2.1.2 ensure ntp is configured
if [ $(grep -cE "^(server|pool)" /etc/chrony.conf) -eq 0 ]; then
	for i in {0..3}; do
		echo "server ${i}.centos.pool.ntp.org iburst" >> /etc/chrony.conf
	done
fi

if [[ $(grep -E "^allow" /etc/chrony.conf) ]]; then
	sed -i '/^allow/g' /etc/chrony.conf
fi

grep -q "\-u chrony" /etc/sysconfig/chronyd
if [ $? -ne 0 ]; then
	sed -i "/^OPTIONS=/g" /etc/sysconfig/chronyd
	echo "OPTIONS=\"-u chrony\"" >> /etc/sysconfig/chronyd
fi

#2.2.2 Ensure X Window System is not installed
rpm -qa --quiet xorg-x11* || yum remove -y -q xorg-x11*

#2.2.3-14,16-21 Ensure certain services are not enabled
for i in avahi-daemon cups dhcpd slapd nfs nfs-server rpcbind named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socker rlogin.socket rexec.socket telnet.socket tftp.socket rsyncd ntalk; do
        if [[ $(systemctl is-enabled $i 2>/dev/null) == "enabled" ]]; then
                systemctl disable $i
        fi
done

#2.2.15 Ensure mail trainsfer agent is configured for local-only mode
if [[ $(ss -tuln | grep LISTEN.*:25 | grep -Ev "(127.0.0.1|\[::1\]):25\s") ]]; then
	sed -i "/^inet_interfaces/g" /etc/postfix/main.cf
	echo "inet_interfaces = localhost" >> /etc/postfix/main.cf
	systemctl restart postfix
fi

#2.3.1-5 Ensure specific packages are not installed
for i in ypbind rsh talk telnet openldap-clients; do
	rpm -q --quiet $i || yum remove -q -y $i 2>/dev/null
done

#3.1.1 Ensure IP forwarding is disabled
if ! $(grep -q "net\.ipv4\.ip_forward" /etc/sysctl.conf /etc/sysctl.d/*); then
        echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/CIS.conf
        sysctl -w net.ipv4.ip_forward=0
	sysctl -w net.ipv4.route.flush=1
fi

#3.1.2 Ensure packet redirect sending is disabled
if ! grep -q "net\.ipv4\.conf\.all\.send_redirects\|net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.1 Ensure source routed packets are not accepted
if ! grep -q "net\.ipv4\.conf\.default\.accept_source_route\|net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.conf.all.accept_source_route=0
	sysctl -w net.ipv4.conf.default.accept_source_route=0
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.2 Ensure ICMP redirects are not accepted
if ! grep -q "net\.ipv4\.conf\.default\.accept_redirects\|net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.3 Ensure secure ICMP redirects are not accepted
if ! grep -q "net\.ipv4\.conf\.all\.secure_redirects\|net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv4.conf.all.secure_redirects = 0\nnet.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.4 Ensure suspicious packets are logged
if ! grep -q "net\.ipv4\.conf\.all\.log_martians\|net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.conf.all.log_martians=1
	sysctl -w net.ipv4.conf.default.log_martians=1
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.5 Ensure broadcast ICMP requests are ignored
if ! grep -q "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.6 Ensure bogues ICMP responses are ignored
if ! grep -q "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.7 Ensure reverse path filtering is enabled
if ! grep -q "net\.ipv4\.conf\.all\.rp_filter\|net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.conf.all.rp_filter=1
	sysctl -w net.ipv4.conf.default.rp_filter=1
	sysctl -w net.ipv4.route.flush=1
fi

#3.2.8 Ensure TCP SYN Cookies is enabled
if ! grep -q "net\.ipv4\.tcp_syncookies"  /etc/sysctl.conf /etc/sysctl.d/*; then
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv4.tcp_syncookies=1
	sysctl -w net.ipv4.route.flush=1
fi

#3.3.1 Ensure IPv6 router advertisments are not accepted
if ! grep -q "net\.ipv6\.conf\.all\.accept_ra\|net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv6.conf.all.accept_ra = 0\nnet.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv6.conf.all.accept_ra=0
	sysctl -w net.ipv6.conf.default.accept_ra=0
	sysctl -w net.ipv6.route.flush=1
fi

#3.3.2 Ensure IPv6 redirects are not accepted
if ! grep -q "net\.ipv6\.conf\.all\.accept_redirect\|net\.ipv6\.conf\.default\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/*; then
	echo -e "net.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/CIS.conf
	sysctl -w net.ipv6.conf.all.accept_redirects=0
	sysctl -w net.ipv6.conf.default.accept_redirects=0
	sysctl -w net.ipv6.route.flush=1
fi

#3.3.3 Ensure IPv6  is disabled - skipped

#3.4.1 Ensure TCP Wrappers is installed
rpm --quiet -q tcp_wrappers || yum -y -q install tcp_wrappers

#3.4.2 Ensure /etc/hosts.allow is configured
if ! grep -qE "^ALL: " /etc/hosts.allow; then
	echo "Configure /etc/hosts.allow as needed"
fi

#3.4.3 Ensure /etc/hosts.deny is configured
if ! grep -qE "^ALL: ALL$" /etc/hosts.deny; then
	echo "ALL: ALL" >> /etc/hosts.deny
fi

#3.4.4,5 Permissions + owner on hosts.deny and hosts.allow
chown root:root /etc/hosts.{allow,deny}
chmod 644 /etc/hosts.{allow,deny}

#3.5.1-4 Disable network protocols
for i in dccp sctp rds tipc; do
        if ! grep -q "install $i /bin/true" /etc/modprobe.d/CIS.conf; then
                echo "install $i /bin/true" >> /etc/modprobe.d/CIS.conf
                rmmod $i 2>/dev/null
        fi
done

#3.6.1 Ensure iptables is installed
rpm --quiet -q iptables || yum -y -q install iptables
rpm --quiet -q iptables-services || yum -y -q install iptables-services

#Flush iptables rules
iptables -F
#3.6.2 Ensure default deny firewall policy
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
#3.6.3 Ensure loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
#3.6.4 Ensure outbound and established connections are configured
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
#3.6.5 Open inbound ssh(tcp port 22) connections (should be all open ports but lets go for just ssh)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

iptables-save > /etc/sysconfig/iptables

#3.7 Ensure wireless interfaces are disabled - skipped

#4.1.1.1 Ensure audit log storage size is configured
if ! grep -q "max_log_file = 8" /etc/audit/auditd.conf; then
        sed -i "/^max_log_file =/g" /etc/audit/auditd.conf
        echo "max_log_file = 8" >> /etc/audit/auditd.conf
fi

#4.1.1.2 Ensure system is disabled when audit logs are full
if ! grep -q "space_left_action = email\|action_mail_acct = root\|admin_space_left_action = halt" /etc/audit/auditd.conf; then
	sed -i "/^space_left_action =/g" /etc/audit/auditd.conf
	sed -i "/^action_mail_acct =/g" /etc/audit/auditd.conf
	sed -i "/^admin_space_left_action =/g" /etc/audit/auditd.conf
	echo -e "space_left_action = email\naction_mail_acct = root\nadmin_space_left_action = halt" >> /etc/audit/auditd.conf
fi

#4.1.1.3 Ensure audit logs are not automatically deleted - skipped, let it rotate

#4.1.2 Ensure auditd service is enabled
if [[ $(systemctl is-enabled auditd 2>/dev/null) != "enabled" ]]; then
	systemctl enable auditd
fi

#4.1.3 Ensure auditing for processes that start prior to auditd is enabled
if ! grep "^\s*linux" /boot/grub2/grub.cfg | grep -q audit=1; then
	regex="=\"([^\"]+)"
	if [[ $(grep "GRUB_CMDLINE_LINUX=" /etc/default/grub) =~ $regex ]]; then
		new_cmdline="${BASH_REMATCH[0]#=\"} audit=1"
		sed -i "/^GRUB_CMDLINE_LINUX=/g" /etc/default/grub
		sed -i '/^$/d' /etc/default/grub
		echo "GRUB_CMDLINE_LINUX=\"$new_cmdline\"" >> /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg
	fi
fi
 
#4.1.4 Ensure events that modify date and time information are collected
for i in "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" "-a always,exit -F arch=b64 -S clock_settime -k time-change" "-a always,exit -F arch=b32 -S clock_settime -k time-change" "-w /etc/localtime -p wa -k time-change"; do 
	if ! grep -q -- "$i" /etc/audit/rules.d/*; then
		echo "$i" >> /etc/audit/rules.d/CIS-time-changes.rules
	fi
done

#4.1.5 Ensure events that modify user / group information are ollected
for i in "-w /etc/group -p wa -k identity" "-w /etc/passwd -p wa -k identity" "-w /etc/gshadow -p wa -k identity" "-w /etc/shadow -p wa -k identity" "-w /etc/security/opasswd -p wa -k identity"; do
	if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-group-user-changes.rules
        fi
done

#4.1.6 Ensure events taht modify the systems network environment are collected
for i in "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" "-w /etc/issue -p wa -k system-locale" "-w /etc/issue.net -p wa -k system-locale" "-w /etc/hosts -p wa -k system-locale" "-w /etc/sysconfig/network -p wa -k system-locale" "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-network-changes.rules
        fi
done

#4.1.7 Ensure events that modify the systems mandatory access controls are collected
for i in "-w /etc/selinux/ -p wa -k MAC-policy" "-w /usr/share/selinux/ -p wa -k MAC-policy"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-mac-changes.rules
        fi
done

#4.1.8 Ensure login and logout events are collected
for i in "-w /var/log/lastlog -p wa -k logins" "-w /var/run/faillock/ -p wa -k logins"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-login-logout-events.rules
        fi
done

#4.1.9 Ensure session initiation information is collected
for i in "-w /var/run/utmp -p wa -k session" "-w /var/log/wtmp -p wa -k logins" "-w /var/log/btmp -p wa -k logins"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-session-events.rules
        fi
done

#4.1.10 Ensure discretionary access control permission modification events are collected
for i in "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-modification-events.rules
        fi
done

#4.1.11 Ensure unsuccessful unauthorized file access attempts are collected
for i in "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"; do 
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-fileaccess-events.rules
        fi
done

#4.1.12 Ensure use of privileged commands is collected. Assuming / will pick up everything
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' | while read i; do
	if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-privileged-commands.rules
        fi
done

#4.1.13 Ensure successful file system mounts are collected
for i in "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-system-mounts.rules
        fi
done

#4.1.14 Ensure file deletion events by users are collected
for i in "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-file-deletion.rules
        fi
done

#4.1.15 Ensure changes to system administration scope (sudoers) is collected
for i in "-w /etc/sudoers -p wa -k scope" "-w /etc/sudoers.d/ -p wa -k scope"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-sudoers-changes.rules
        fi
done

#4.1.16 Ensure systemd administrator actions (sudolog) are collected
for i in "-w /var/log/sudo.log -p wa -k actions"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-sudolog.rules
        fi
done

#4.1.17 Ensure kernel module loading and unloading is collected
for i in "-w /sbin/insmod -p x -k modules" "-w /sbin/rmmod -p x -k modules" "-w /sbin/modprobe -p x -k modules" "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"; do
        if ! grep -q -- "$i" /etc/audit/rules.d/*; then
                echo "$i" >> /etc/audit/rules.d/CIS-kernel-module.rules
        fi
done

#4.1.18 Ensure the audit configuration is immutable
if ! grep -q -- "-e 2" /etc/audit/rules.d/*; then
	echo "-e 2" >> /etc/audit/rules.d/CIS-audit-immutable.rules
fi

#4.2.1.1 Ensure rsyslog service is enabled
if [[ $(systemctl is-enabled rsyslog 2>/dev/null) != "enabled" ]]; then
        systemctl enable rsyslog
fi

#4.2.1.2 Ensure logging is configured. Far too system specific, up to each and every system owner to fix. Just print a warning
echo "Configure important sources of information to send to syslog by configuring /etc/rsyslog.conf and files in /etc/rsyslog.d/"

#4.2.1.3 Ensure rsyslog default file permissiosn configured
if ! grep -q "module(load=\"builtin:omfile\"" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
	echo "module(load=\"builtin:omfile\" FileCreateMode=\"0640\")" >> /etc/rsyslog.d/CIS.conf
fi

#4.2.1.4 Send to remote host
if ! grep -q "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
	echo "Sending of syslog to a remote host must be configured by adding a line such as *.* @@192.168.1.55"
fi

#4.2.1.5 Ensure remote rsyslog is not on
if grep -qE "^\\\$ModLoad (imtcp|imudp|imptcp)" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
	sed -i -E "/^\\\$ModLoad (imtcp|imudp|imptcp)/d" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
fi

#4.2.2.1-5 Syslog-ng stuff skipped, we're already using rsyslog

#4.2.3 Ensure rsyslog is installed
rpm -q --quiet rsyslog || yum remove -q -y rsyslog 2>/dev/null

#4.2.4 Ensure permissions on all logfiles are configured
find /var/log -type f -exec chmod g-wx,o-rwx {} +

#4.3 Ensure logrotate is configured... just some echo going on here
echo "Verify your logrotate settings /etc/logrotate.conf and /etc/logrotate.d to avoid filling up the system logs"

#5.1.1 Ensure cron daemon is enabled
if [[ $(systemctl is-enabled crond 2>/dev/null) != "enabled" ]]; then
        systemctl enable crond
fi

#5.1.2-7 Ensure permissions on certain files used by cron are configured
chown root:root /etc/{crontab,cron.hourly,cron.daily,cron.weekly,cron.montly,cron.d,cron.allow,at.allow} 2>/dev/null
chmod og-rwx /etc/{crontab,cron.hourly,cron.daily,cron.weekly,cron.monthly,cron.d,cron.allow,at.allow} 2>/dev/null

#5.1.8 Ensure at/cron is restricted to authorized users
rm -f /etc/{at,cron}.deny 2>/dev/null

#5.2.1 Ensure permission on /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

#5.2.2 Ensure SSH protocol is set to 2 
if ! grep -q "^Protocol 2" /etc/ssh/sshd_config; then
        sed -i "/^Protocol/g" /etc/ssh/sshd_config
	echo "Protocol 2" >> /etc/ssh/sshd_config
fi

#5.2.3 Ensure SSH LogLevel is set to INFO
if ! grep -q "^LogLevel INFO" /etc/ssh/sshd_config; then
        sed -i "/^LogLevel/g" /etc/ssh/sshd_config
        echo "LogLevel INFO" >> /etc/ssh/sshd_config
fi

#5.2.4 Ensure SSH X11 Forwarding is disabled
if ! grep -q "^X11Forwarding no" /etc/ssh/sshd_config; then
        sed -i "/^X11Forwarding/g" /etc/ssh/sshd_config
        echo "X11Forwarding no" >> /etc/ssh/sshd_config
fi

#5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
if ! grep -qE "^MaxAuthTries [1-4]" /etc/ssh/sshd_config; then
        sed -i "/^MaxAuthTries/g" /etc/ssh/sshd_config
        echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
fi

#5.2.6 Ensure SSH IgnoreRhosts is enabled
if ! grep -q "^IgnoreRhosts yes" /etc/ssh/sshd_config; then
        sed -i "/^IgnoreRhosts/g" /etc/ssh/sshd_config
        echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
fi

#5.2.7 Ensure SSH HostbasedAuthentication is disabled
if ! grep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config; then
	sed -i "/HostbasedAuthentication/g" /etc/sshd_config
	echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
fi

#5.2.8 Ensure SSH root login is disabled
if ! grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        sed -i "/PermitRootLogin/g" /etc/sshd_config
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

#5.2.9 Ensure SSH PermitEmptyPasswords is disabled
if ! grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config 
        sed -i "/PermitEmptyPasswords/g" /etc/sshd_config
        echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
fi

#5.2.10 Ensure SSH PermitUserEnvironment is disabled
if ! grep -q "^PermitUserEnvironment no" /etc/sshd_config; then 
        sed -i "/PermitUserEnvironment/g" /etc/sshd_config
        echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
fi

#5.2.11 Ensure only approved MAC algorithms are used
if ! grep -q "^MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" /etc/sshd_config; then
	sed -i "/MACs/g" /etc/sshd_config
	echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/sshd_config
fi

#5.2.12 Ensure SSH Idle Tiemout Interval is configured
if ! grep -qE "^(ClientAliveInterval 300|ClientAliveCountMax 0)" /etc/ssh/sshd_config; then
	sed -i "/ClientAliveInterval/g" /etc/ssh/sshd_config
	sed -i "/ClientAliveCountMax/g" /etc/ssh/sshd_config
	echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
	echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
fi

#5.2.13 Ensure SSH LoginGraceTime is set to one minute or less
if ! grep -q "LoginGraceTime 60" /etc/ssh/sshd_config; then
	sed -i "/LoginGraceTime/g" /etc/ssh/sshd_config
	echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
fi

#5.2.14 Ensure SSH access is limited, just echo a suggestion or two
echo "SSH access should be limited, look into using AllowGroups and/or AllowUsers if possible"

#5.2.15 Ensure SSH warning banner is configured
if ! grep -q "^Banner /etc/issue.net" /etc/ssh/sshd_config; then
	sed -i "/Banner/g" /etc/ssh/sshd_config
	echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
fi
