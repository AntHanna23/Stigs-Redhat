###############################################################################
# Anthony Hanna(Intern)
# $ Must be ran as root
#
###############################################################################

###############################################################################
# There must be no .shosts files on the system. (V-72277)
###############################################################################
(>&2 echo "Remediating rule 1/236: 'no_user_host_based_files'")

# Identify local mounts
MOUNT_LIST=$(df --local | awk '{ print $6 }')

# Find file on each listed mount point
for cur_mount in ${MOUNT_LIST}
do
	find ${cur_mount} -xdev -type f -name ".shosts" -exec rm -f {} \;
done


###############################################################################
# There must be no shosts.equiv files on the system. (V-72279)
###############################################################################
(>&2 echo "Remediating rule 2/236: 'no_host_based_files'")

# Identify local mounts
MOUNT_LIST=$(df --local | awk '{ print $6 }')

# Find file on each listed mount point
for cur_mount in ${MOUNT_LIST}
do
	find ${cur_mount} -xdev -type f -name "shosts.equiv" -exec rm -f {} \;
done


###############################################################################
# The rsh-server package must not be installed. (V-71967)
###############################################################################
(>&2 echo "Remediating rule 3/236: 'package_rsh-server_removed'")

# CAUTION: This remediation script will remove rsh-server
#	   from the system, and may remove any packages
#	   that depend on rsh-server. Execute this
#	   remediation AFTER testing on a non-productionww
#	   system!

if rpm -q --quiet "rsh-server" ; then
    yum remove -y "rsh-server"
fi


###############################################################################
# The telnet-server package must not be installed. (V-72077)
###############################################################################
(>&2 echo "Remediating rule 4/236: 'package_telnet-server_removed'")

# CAUTION: This remediation script will remove telnet-server
#	   from the system, and may remove any packages
#	   that depend on telnet-server. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "telnet-server" ; then
    yum remove -y "telnet-server"
fi


###############################################################################
# The ypserv package must not be installed. (V-71969)
###############################################################################
(>&2 echo "Remediating rule 5/236: 'package_ypserv_removed'")

# CAUTION: This remediation script will remove ypserv
#	   from the system, and may remove any packages
#	   that depend on ypserv. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "ypserv" ; then
    yum remove -y "ypserv"
fi


###############################################################################
# The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support. (V-72301)
###############################################################################
(>&2 echo "Remediating rule 7/236: 'package_tftp-server_removed'")

# CAUTION: This remediation script will remove tftp-server
#	   from the system, and may remove any packages
#	   that depend on tftp-server. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "tftp-server" ; then
    yum remove -y "tftp-server"
fi


###############################################################################
# SNMP community strings must be changed from the default. (V-72313)
###############################################################################
(>&2 echo "Remediating rule 9/236: 'snmpd_not_default_password'")

if grep -s "public\|private" /etc/snmp/snmpd.conf | grep -qv "^#"; then
	sed -i "/^\s*#/b;/public\|private/ s/^/#/" /etc/snmp/snmpd.conf
fi
# END fix for 'snmpd_not_default_password'

###############################################################################
# If the cron.allow file exists it must be group-owned by root. (V-72055)
###############################################################################
(>&2 echo "Remediating rule 10/236: 'file_groupowner_cron_allow'")

chgrp 0 /etc/cron.allow
# END fix for 'file_groupowner_cron_allow'

###############################################################################
# If the cron.allow file exists it must be owned by root. (V-72053)
###############################################################################
(>&2 echo "Remediating rule 11/236: 'file_owner_cron_allow'")

chown 0 /etc/cron.allow
# END fix for 'file_owner_cron_allow'

###############################################################################
# An X Windows display manager must not be installed unless approved. (V-72307)
###############################################################################
(>&2 echo "Remediating rule 12/236: 'package_xorg-x11-server-common_removed'")

# CAUTION: This remediation script will remove xorg-x11-server-common
#	   from the system, and may remove any packages
#	   that depend on xorg-x11-server-common. Execute this
#	   remediation AFTER testing on a non-production
#	   system!

if rpm -q --quiet "xorg-x11-server-common" ; then
    yum remove -y "xorg-x11-server-common"
fi
# END fix for 'package_xorg-x11-server-common_removed'

###############################################################################
# The system must be configured to prevent unrestricted mail relaying. (V-72297)
###############################################################################
(>&2 echo "Remediating rule 13/236: 'postfix_prevent_unrestricted_relay'")

if ! grep -q ^smtpd_client_restrictions /etc/postfix/main.cf; then
	echo "smtpd_client_restrictions = permit_mynetworks,reject" >> /etc/postfix/main.cf
else
	sed -i "s/^smtpd_client_restrictions.*/smtpd_client_restrictions = permit_mynetworks,reject/g" /etc/postfix/main.cf
fi
# END fix for 'postfix_prevent_unrestricted_relay'

###############################################################################
# The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications. (V-72231)
###############################################################################
(>&2 echo "Remediating rule 14/236: 'sssd_ldap_configure_tls_ca_dir'")

var_sssd_ldap_tls_ca_dir="/etc/openldap/cacerts"

SSSD_CONF="/etc/sssd/sssd.conf"
LDAP_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*ldap_tls_cacertdir'
DOMAIN_REGEX="[[:space:]]*\[domain\/[^]]*]"

# Try find [domain/..] and ldap_tls_cacertdir in sssd.conf, if it exists, set to CA directory
# if it isn't here, add it, if [domain/..] doesn't exist, add it here for default domain
if grep -qzosP $LDAP_REGEX $SSSD_CONF; then
        sed -i "s~ldap_tls_cacertdir[^(\n)]*~ldap_tls_cacertdir = $var_sssd_ldap_tls_ca_dir~" $SSSD_CONF
elif grep -qs $DOMAIN_REGEX $SSSD_CONF; then
        sed -i "/$DOMAIN_REGEX/a ldap_tls_cacertdir = $var_sssd_ldap_tls_ca_dir" $SSSD_CONF
else
        mkdir -p /etc/sssd
        touch $SSSD_CONF
        echo -e "[domain/default]\nldap_tls_cacertdir = $var_sssd_ldap_tls_ca_dir" >> $SSSD_CONF
fi


###############################################################################
# The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication. (V-71965)
###############################################################################
(>&2 echo "Remediating rule 15/236: 'sssd_ldap_start_tls'")


AUTHCONFIG="/etc/sysconfig/authconfig"
USELDAPAUTH_REGEX="^USELDAPAUTH="
SSSD_CONF="/etc/sssd/sssd.conf"
LDAP_REGEX='[[:space:]]*\[domain\/[^]]*]([^(\n)]*(\n)+)+?[[:space:]]*ldap_id_use_start_tls'
DOMAIN_REGEX="[[:space:]]*\[domain\/[^]]*]"

# Try find USELDAPAUTH in authconfig. If its here set to 'yes', otherwise append USELDAPAUTH=yes
grep -qs "^USELDAPAUTH=" "$AUTHCONFIG" && sed -i 's/^USELDAPAUTH=.*/USELDAPAUTH=yes/g' $AUTHCONFIG
if ! [ $? -eq 0 ]; then
        echo "USELDAPAUTH=yes" >> $AUTHCONFIG
fi

# Try find [domain/..] and ldap_id_use_start_tls in sssd.conf, if it exists, set to 'True'
# if ldap_id_use_start_tls isn't here, add it
# if [domain/..] doesn't exist, add it here for default domain
if grep -qzosP $LDAP_REGEX $SSSD_CONF; then
        sed -i 's/ldap_id_use_start_tls[^(\n)]*/ldap_id_use_start_tls = True/' $SSSD_CONF
elif grep -qs $DOMAIN_REGEX $SSSD_CONF; then
        sed -i "/$DOMAIN_REGEX/a ldap_id_use_start_tls = True" $SSSD_CONF
else
        mkdir -p /etc/sssd
        touch $SSSD_CONF
        echo -e "[domain/default]\nldap_id_use_start_tls = True" >> $SSSD_CONF
fi



###############################################################################
# The operating system must implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM). (V-72427)
###############################################################################
(>&2 echo "Remediating rule 17/236: 'sssd_enable_pam_services'")


SSSD_SERVICES_PAM_REGEX="^[[:space:]]*\[sssd]([^\n]*\n+)+?[[:space:]]*services.*pam.*$"
SSSD_SERVICES_REGEX="^[[:space:]]*\[sssd]([^\n]*\n+)+?[[:space:]]*services.*$"
SSSD_PAM_SERVICES="[sssd]
services = pam"
SSSD_CONF="/etc/sssd/sssd.conf"

# If there is services line with pam, good
# If there is services line without pam, append pam
# If not echo services line with pam
grep -q "$SSSD_SERVICES_PAM_REGEX" $SSSD_CONF || \
	grep -q "$SSSD_SERVICES_REGEX" $SSSD_CONF && \
	sed -i "s/$SSSD_SERVICES_REGEX/&, pam/" $SSSD_CONF || \
	echo "$SSSD_PAM_SERVICES" >> $SSSD_CONF
# END fix for 'sssd_enable_pam_services'

###############################################################################
# The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO)
# time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). (V-72269)
###############################################################################
(>&2 echo "Remediating rule 18/236: 'chronyd_or_ntpd_set_maxpoll'")

var_time_service_set_maxpoll="10"


config_file="/etc/ntp.conf"
/usr/sbin/pidof ntpd || config_file="/etc/chrony.conf"


# Set maxpoll values to var_time_service_set_maxpoll
sed -i "s/^\(server.*maxpoll\) [0-9][0-9]*\(.*\)$/\1 $var_time_service_set_maxpoll \2/" "$config_file"

# Add maxpoll to server entries without maxpoll
grep "^server" "$config_file" | grep -v maxpoll | while read -r line ; do
        sed -i "s/$line/& maxpoll $var_time_service_set_maxpoll/" "$config_file"
done
# END fix for 'chronyd_or_ntpd_set_maxpoll'

###############################################################################
# Kernel core dumps must be disabled unless needed. (V-72057)
###############################################################################
(>&2 echo "Remediating rule 19/236: 'service_kdump_disabled'")


SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'kdump.service'
"$SYSTEMCTL_EXEC" disable 'kdump.service'
"$SYSTEMCTL_EXEC" mask 'kdump.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" list-unit-files | grep -q '^kdump.socket'; then
    "$SYSTEMCTL_EXEC" stop 'kdump.socket'
    "$SYSTEMCTL_EXEC" disable 'kdump.socket'
    "$SYSTEMCTL_EXEC" mask 'kdump.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'kdump.service' || true
# END fix for 'service_kdump_disabled'

###############################################################################
# The SSH daemon must perform strict mode checking of home directory configuration files. (V-72263)
###############################################################################
(>&2 echo "Remediating rule 20/236: 'sshd_enable_strictmodes'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*StrictModes\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "StrictModes yes" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "StrictModes yes" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_enable_strictmodes'

###############################################################################
# The SSH daemon must not allow authentication using an empty password. (V-71939)
###############################################################################
(>&2 echo "Remediating rule 21/236: 'sshd_disable_empty_passwords'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*PermitEmptyPasswords\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_disable_empty_passwords'

###############################################################################
# All network connections associated with SSH traffic must terminate at the end of the session or after 10 minutes of inactivity,
# except to fulfill documented and validated mission requirements. (V-72237)
###############################################################################
(>&2 echo "Remediating rule 22/236: 'sshd_set_keepalive'")

var_sshd_set_keepalive="0"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/ssh/sshd_config' '^ClientAliveCountMax' "$var_sshd_set_keepalive" 'CCE-27082-7' '%s %s'
# END fix for 'sshd_set_keepalive'

###############################################################################
# The operating system must set the session idle delay setting for all connection types. (V-73157)
###############################################################################
(>&2 echo "Remediating rule 23/236: 'sshd_set_idle_timeout'")

sshd_idle_timeout_value="600"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/ssh/sshd_config' '^ClientAliveInterval' $sshd_idle_timeout_value 'CCE-27433-2' '%s %s'
# END fix for 'sshd_set_idle_timeout'

###############################################################################
# The Standard Mandatory DoD Notice and Consent Banner must be displayed immediately prior to, or as part of, remote access logon prompts. (V-72225)
###############################################################################
(>&2 echo "Remediating rule 24/236: 'sshd_enable_warning_banner'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*Banner\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "Banner /etc/issue" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "Banner /etc/issue" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"


###############################################################################
# The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms. (V-72253)
###############################################################################
(>&2 echo "Remediating rule 25/236: 'sshd_use_approved_macs'")

sshd_approved_macs="hmac-sha2-512,hmac-sha2-256,hmac-sha1,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/ssh/sshd_config' '^MACs' "$sshd_approved_macs" 'CCE-27455-5' '%s %s'
# END fix for 'sshd_use_approved_macs'

###############################################################################
# The operating system must not allow users to override SSH environment variables. (V-71957)
###############################################################################
(>&2 echo "Remediating rule 26/236: 'sshd_do_not_permit_user_env'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*PermitUserEnvironment\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PermitUserEnvironment yes" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PermitUserEnvironment yes" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_do_not_permit_user_env'

###############################################################################
# The SSH daemon must not permit Kerberos authentication unless needed. (V-72261)
###############################################################################
(>&2 echo "Remediating rule 27/236: 'sshd_disable_kerb_auth'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*KerberosAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "KerberosAuthentication no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "KerberosAuthentication no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_disable_kerb_auth'

###############################################################################
# The SSH daemon must be configured to only use the SSHv2 protocol. (V-72251)
###############################################################################
(>&2 echo "Remediating rule 28/236: 'sshd_allow_only_protocol2'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*Protocol\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "Protocol 2" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "Protocol 2" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_allow_only_protocol2'

###############################################################################
# The SSH daemon must not allow authentication using RSA rhosts authentication. (V-72239)
###############################################################################
(>&2 echo "Remediating rule 29/236: 'sshd_disable_rhosts_rsa'")
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/ssh/sshd_config' '^RhostsRSAAuthentication' 'no' 'CCE-80373-4' '%s %s'
# END fix for 'sshd_disable_rhosts_rsa'

###############################################################################
# An X Windows display manager must not be installed unless approved. (V-72307)
###############################################################################
(>&2 echo "Remediating rule 30/236: 'sshd_enable_x11_forwarding'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*X11Forwarding\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "X11Forwarding yes" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "X11Forwarding yes" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_enable_x11_forwarding'

###############################################################################
# A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications. (V-72221)
###############################################################################
(>&2 echo "Remediating rule 31/236: 'sshd_use_approved_ciphers'")
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/ssh/sshd_config' '^Ciphers' 'aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc' 'CCE-27295-5' '%s %s'
# END fix for 'sshd_use_approved_ciphers'

###############################################################################
# The operating system must not allow a non-certificate trusted host SSH logon to the system. (V-71959)
###############################################################################
(>&2 echo "Remediating rule 32/236: 'disable_host_auth'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*HostbasedAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'disable_host_auth'

###############################################################################
# The SSH daemon must use privilege separation. (V-72265)
###############################################################################
(>&2 echo "Remediating rule 33/236: 'sshd_use_priv_separation'")

var_sshd_priv_separation="sandbox"

if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*UsePrivilegeSeparation\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "UsePrivilegeSeparation $var_sshd_priv_separation" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "UsePrivilegeSeparation $var_sshd_priv_separation" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_use_priv_separation'

###############################################################################
# The system must display the date and time of the last successful account logon upon an SSH logon. (V-72245)
###############################################################################
(>&2 echo "Remediating rule 34/236: 'sshd_print_last_log'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*PrintLastLog\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PrintLastLog yes" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PrintLastLog yes" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_print_last_log'

###############################################################################
# The SSH daemon must not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed. (V-72259)
###############################################################################
(>&2 echo "Remediating rule 35/236: 'sshd_disable_gssapi_auth'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*GSSAPIAuthentication\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "GSSAPIAuthentication no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "GSSAPIAuthentication no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_disable_gssapi_auth'

###############################################################################
# The SSH daemon must not allow compression or must only allow compression after successful authentication. (V-72267)
###############################################################################
(>&2 echo "Remediating rule 36/236: 'sshd_disable_compression'")

var_sshd_disable_compression="no"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/ssh/sshd_config' '^Compression' "$var_sshd_disable_compression" 'CCE-80224-9' '%s %s'
# END fix for 'sshd_disable_compression'

###############################################################################
# The system must not permit direct logons to the root account using remote access via SSH
###############################################################################
(>&2 echo "Remediating rule 37/236: 'sshd_disable_root_login'")
if [ -e "/etc/ssh/sshd_config" ] ; then
    LC_ALL=C sed -i "/^\s*PermitRootLogin\s\+/Id" "/etc/ssh/sshd_config"
else
    touch "/etc/ssh/sshd_config"
fi
cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
# Insert before the line matching the regex '^Match'.
line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
if [ -z "$line_number" ]; then
    # There was no match of '^Match', insert at
    # the end of the file.
    printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config"
else
    head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
    printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config"
    tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
fi
# Clean up after ourselves.
rm "/etc/ssh/sshd_config.bak"
# END fix for 'sshd_disable_root_login'

###############################################################################
# All networked systems must have SSH installed. (V-72233)
###############################################################################
(>&2 echo "Remediating rule 38/236: 'package_openssh-server_installed'")

if ! rpm -q --quiet "openssh-server" ; then
    yum install -y "openssh-server"
fi
# END fix for 'package_openssh-server_installed'

###############################################################################
# All networked systems must use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission. (V-72235)
###############################################################################
(>&2 echo "Remediating rule 39/236: 'service_sshd_enabled'")

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" start 'sshd.service'
"$SYSTEMCTL_EXEC" enable 'sshd.service'
# END fix for 'service_sshd_enabled'

###############################################################################
# The SSH public host key files must have mode 0644 or less permissive. (V-72255)
###############################################################################
(>&2 echo "Remediating rule 40/236: 'file_permissions_sshd_pub_key'")
find /etc/ssh -regex '^/etc/ssh/.*.pub$' -exec chmod 0644 {} \;
# END fix for 'file_permissions_sshd_pub_key'

###############################################################################
# The SSH private host key files must have mode 0600 or less permissive. (V-72257)
###############################################################################
(>&2 echo "Remediating rule 41/236: 'file_permissions_sshd_private_key'")
find /etc/ssh -regex '^/etc/ssh/.*_key$' -exec chmod 0600 {} \;
# END fix for 'file_permissions_sshd_private_key'

###############################################################################
# The Network File System (NFS) must be configured to use RPCSEC_GSS. (V-72311)
###############################################################################
(>&2 echo "Remediating rule 42/236: 'mount_option_krb_sec_remote_filesystems'")
function include_mount_options_functions {
	:
}

# $1: type of filesystem
# $2: new mount point option
# $3: filesystem of new mount point (used when adding new entry in fstab)
# $4: mount type of new mount point (used when adding new entry in fstab)
function ensure_mount_option_for_vfstype {
        local _vfstype="$1" _new_opt="$2" _filesystem=$3 _type=$4 _vfstype_points=()
        readarray -t _vfstype_points < <(grep -E "[[:space:]]${_vfstype}[[:space:]]" /etc/fstab | awk '{print $2}')

        for _vfstype_point in "${_vfstype_points[@]}"
        do
                ensure_mount_option_in_fstab "$_vfstype_point" "$_new_opt" "$_filesystem" "$_type"
        done
}

# $1: mount point
# $2: new mount point option
# $3: device or virtual string (used when adding new entry in fstab)
# $4: mount type of mount point (used when adding new entry in fstab)
function ensure_mount_option_in_fstab {
	local _mount_point="$1" _new_opt="$2" _device=$3 _type=$4
	local _mount_point_match_regexp="" _previous_mount_opts=""
	_mount_point_match_regexp="$(get_mount_point_regexp "$_mount_point")"

	if [ "$(grep -c "$_mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
		# runtime opts without some automatic kernel/userspace-added defaults
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
					| sed -E "s/(rw|defaults|seclabel|${_new_opt})(,|$)//g;s/,$//")
		[ "$_previous_mount_opts" ] && _previous_mount_opts+=","
		echo "${_device} ${_mount_point} ${_type} defaults,${_previous_mount_opts}${_new_opt} 0 0" >> /etc/fstab
	elif [ "$(grep "$_mount_point_match_regexp" /etc/fstab | grep -c "$_new_opt")" -eq 0 ]; then
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/fstab | awk '{print $4}')
		sed -i "s|\(${_mount_point_match_regexp}.*${_previous_mount_opts}\)|\1,${_new_opt}|" /etc/fstab
	fi
}

# $1: mount point
function get_mount_point_regexp {
		printf "[[:space:]]%s[[:space:]]" "$1"
}

# $1: mount point
function assert_mount_point_in_fstab {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	grep "$_mount_point_match_regexp" -q /etc/fstab \
		|| { echo "The mount point '$1' is not even in /etc/fstab, so we can't set up mount options" >&2; return 1; }
}

# $1: mount point
function remove_defaults_from_fstab_if_overriden {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	if grep "$_mount_point_match_regexp" /etc/fstab | grep -q "defaults,"
	then
		sed -i "s|\(${_mount_point_match_regexp}.*\)defaults,|\1|" /etc/fstab
	fi
}

# $1: mount point
function ensure_partition_is_mounted {
	local _mount_point="$1"
	mkdir -p "$_mount_point" || return 1
	if mountpoint -q "$_mount_point"; then
		mount -o remount --target "$_mount_point"
	else
		mount --target "$_mount_point"
	fi
}
include_mount_options_functions

ensure_mount_option_for_vfstype "nfs[4]?" "sec=krb5:krb5i:krb5p"
# END fix for 'mount_option_krb_sec_remote_filesystems'

###############################################################################
# File systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed. (V-72045)
###############################################################################
(>&2 echo "Remediating rule 43/236: 'mount_option_noexec_remote_filesystems'")
function include_mount_options_functions {
	:
}

# $1: type of filesystem
# $2: new mount point option
# $3: filesystem of new mount point (used when adding new entry in fstab)
# $4: mount type of new mount point (used when adding new entry in fstab)
function ensure_mount_option_for_vfstype {
        local _vfstype="$1" _new_opt="$2" _filesystem=$3 _type=$4 _vfstype_points=()
        readarray -t _vfstype_points < <(grep -E "[[:space:]]${_vfstype}[[:space:]]" /etc/fstab | awk '{print $2}')

        for _vfstype_point in "${_vfstype_points[@]}"
        do
                ensure_mount_option_in_fstab "$_vfstype_point" "$_new_opt" "$_filesystem" "$_type"
        done
}

# $1: mount point
# $2: new mount point option
# $3: device or virtual string (used when adding new entry in fstab)
# $4: mount type of mount point (used when adding new entry in fstab)
function ensure_mount_option_in_fstab {
	local _mount_point="$1" _new_opt="$2" _device=$3 _type=$4
	local _mount_point_match_regexp="" _previous_mount_opts=""
	_mount_point_match_regexp="$(get_mount_point_regexp "$_mount_point")"

	if [ "$(grep -c "$_mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
		# runtime opts without some automatic kernel/userspace-added defaults
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
					| sed -E "s/(rw|defaults|seclabel|${_new_opt})(,|$)//g;s/,$//")
		[ "$_previous_mount_opts" ] && _previous_mount_opts+=","
		echo "${_device} ${_mount_point} ${_type} defaults,${_previous_mount_opts}${_new_opt} 0 0" >> /etc/fstab
	elif [ "$(grep "$_mount_point_match_regexp" /etc/fstab | grep -c "$_new_opt")" -eq 0 ]; then
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/fstab | awk '{print $4}')
		sed -i "s|\(${_mount_point_match_regexp}.*${_previous_mount_opts}\)|\1,${_new_opt}|" /etc/fstab
	fi
}

# $1: mount point
function get_mount_point_regexp {
		printf "[[:space:]]%s[[:space:]]" "$1"
}

# $1: mount point
function assert_mount_point_in_fstab {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	grep "$_mount_point_match_regexp" -q /etc/fstab \
		|| { echo "The mount point '$1' is not even in /etc/fstab, so we can't set up mount options" >&2; return 1; }
}

# $1: mount point
function remove_defaults_from_fstab_if_overriden {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	if grep "$_mount_point_match_regexp" /etc/fstab | grep -q "defaults,"
	then
		sed -i "s|\(${_mount_point_match_regexp}.*\)defaults,|\1|" /etc/fstab
	fi
}

# $1: mount point
function ensure_partition_is_mounted {
	local _mount_point="$1"
	mkdir -p "$_mount_point" || return 1
	if mountpoint -q "$_mount_point"; then
		mount -o remount --target "$_mount_point"
	else
		mount --target "$_mount_point"
	fi
}
include_mount_options_functions

ensure_mount_option_for_vfstype "nfs[4]?" "noexec" "" "nfs4"
# END fix for 'mount_option_noexec_remote_filesystems'

###############################################################################
# File systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed. (V-72041)
###############################################################################
(>&2 echo "Remediating rule 44/236: 'mount_option_nosuid_remote_filesystems'")
function include_mount_options_functions {
	:
}

# $1: type of filesystem
# $2: new mount point option
# $3: filesystem of new mount point (used when adding new entry in fstab)
# $4: mount type of new mount point (used when adding new entry in fstab)
function ensure_mount_option_for_vfstype {
        local _vfstype="$1" _new_opt="$2" _filesystem=$3 _type=$4 _vfstype_points=()
        readarray -t _vfstype_points < <(grep -E "[[:space:]]${_vfstype}[[:space:]]" /etc/fstab | awk '{print $2}')

        for _vfstype_point in "${_vfstype_points[@]}"
        do
                ensure_mount_option_in_fstab "$_vfstype_point" "$_new_opt" "$_filesystem" "$_type"
        done
}

# $1: mount point
# $2: new mount point option
# $3: device or virtual string (used when adding new entry in fstab)
# $4: mount type of mount point (used when adding new entry in fstab)
function ensure_mount_option_in_fstab {
	local _mount_point="$1" _new_opt="$2" _device=$3 _type=$4
	local _mount_point_match_regexp="" _previous_mount_opts=""
	_mount_point_match_regexp="$(get_mount_point_regexp "$_mount_point")"

	if [ "$(grep -c "$_mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
		# runtime opts without some automatic kernel/userspace-added defaults
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
					| sed -E "s/(rw|defaults|seclabel|${_new_opt})(,|$)//g;s/,$//")
		[ "$_previous_mount_opts" ] && _previous_mount_opts+=","
		echo "${_device} ${_mount_point} ${_type} defaults,${_previous_mount_opts}${_new_opt} 0 0" >> /etc/fstab
	elif [ "$(grep "$_mount_point_match_regexp" /etc/fstab | grep -c "$_new_opt")" -eq 0 ]; then
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/fstab | awk '{print $4}')
		sed -i "s|\(${_mount_point_match_regexp}.*${_previous_mount_opts}\)|\1,${_new_opt}|" /etc/fstab
	fi
}

# $1: mount point
function get_mount_point_regexp {
		printf "[[:space:]]%s[[:space:]]" "$1"
}

# $1: mount point
function assert_mount_point_in_fstab {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	grep "$_mount_point_match_regexp" -q /etc/fstab \
		|| { echo "The mount point '$1' is not even in /etc/fstab, so we can't set up mount options" >&2; return 1; }
}

# $1: mount point
function remove_defaults_from_fstab_if_overriden {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	if grep "$_mount_point_match_regexp" /etc/fstab | grep -q "defaults,"
	then
		sed -i "s|\(${_mount_point_match_regexp}.*\)defaults,|\1|" /etc/fstab
	fi
}

# $1: mount point
function ensure_partition_is_mounted {
	local _mount_point="$1"
	mkdir -p "$_mount_point" || return 1
	if mountpoint -q "$_mount_point"; then
		mount -o remount --target "$_mount_point"
	else
		mount --target "$_mount_point"
	fi
}
include_mount_options_functions

ensure_mount_option_for_vfstype "nfs[4]?" "nosuid" "" "nfs4"
# END fix for 'mount_option_nosuid_remote_filesystems'

###############################################################################
# The Red Hat Enterprise Linux operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.
###############################################################################
(>&2 echo "Remediating rule 45/236: 'dconf_gnome_session_idle_user_locks'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_lock 'org/gnome/desktop/session' 'idle-delay' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_session_idle_user_locks'

###############################################################################
#  The Red Hat Enterprise Linux operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.
###############################################################################
(>&2 echo "Remediating rule 46/236: 'dconf_gnome_screensaver_lock_delay'")

var_screensaver_lock_delay="5"
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_settings 'org/gnome/desktop/screensaver' 'lock-delay' "uint32 ${var_screensaver_lock_delay}" 'local.d' '00-security-settings'
dconf_lock 'org/gnome/desktop/screensaver' 'lock-delay' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_lock_delay'

###############################################################################
# The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces.
###############################################################################
(>&2 echo "Remediating rule 47/236: 'dconf_gnome_screensaver_user_locks'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_lock 'org/gnome/desktop/screensaver' 'lock-delay' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_user_locks'

###############################################################################
# The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces. (V-71893)
###############################################################################
(>&2 echo "Remediating rule 48/236: 'dconf_gnome_screensaver_idle_activation_enabled'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_settings 'org/gnome/desktop/screensaver' 'idle-activation-enabled' 'true' 'local.d' '00-security-settings'
dconf_lock 'org/gnome/desktop/screensaver' 'idle-activation-enabled' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_idle_activation_enabled'

###############################################################################
# The operating system must set the idle delay setting for all connection types. (V-71895)
###############################################################################
(>&2 echo "Remediating rule 49/236: 'dconf_gnome_screensaver_idle_delay'")

inactivity_timeout_value="900"
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_settings 'org/gnome/desktop/session' 'idle-delay' "uint32 ${inactivity_timeout_value}" 'local.d' '00-security-settings'
dconf_lock 'org/gnome/desktop/session' 'idle-delay' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_idle_delay'

###############################################################################
# BEGIN fix (50 / 236) for 'dconf_gnome_screensaver_lock_locked'
###############################################################################
(>&2 echo "Remediating rule 50/236: 'dconf_gnome_screensaver_lock_locked'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_lock 'org/gnome/desktop/screensaver' 'lock-enabled' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_lock_locked'

###############################################################################
# BEGIN fix (51 / 236) for 'dconf_gnome_screensaver_lock_enabled'
###############################################################################
(>&2 echo "Remediating rule 51/236: 'dconf_gnome_screensaver_lock_enabled'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_settings 'org/gnome/desktop/screensaver' 'lock-enabled' 'true' 'local.d' '00-security-settings'
dconf_lock 'org/gnome/desktop/screensaver' 'lock-enabled' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_lock_enabled'

###############################################################################
# BEGIN fix (52 / 236) for 'dconf_gnome_screensaver_idle_activation_locked'
###############################################################################
(>&2 echo "Remediating rule 52/236: 'dconf_gnome_screensaver_idle_activation_locked'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_lock 'org/gnome/desktop/screensaver' 'idle-activation-enabled' 'local.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_screensaver_idle_activation_locked'

###############################################################################
# BEGIN fix (53 / 236) for 'dconf_gnome_enable_smartcard_auth'
###############################################################################
(>&2 echo "Remediating rule 53/236: 'dconf_gnome_enable_smartcard_auth'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_settings 'org/gnome/login-screen' 'enable-smartcard-authentication' 'true' 'gdm.d' '00-security-settings'
dconf_lock 'org/gnome/login-screen' 'enable-smartcard-authentication' 'gdm.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_enable_smartcard_auth'

###############################################################################
# The operating system must not allow an unattended or automatic logon to the system via a graphical user interface. (V-71953)
###############################################################################
(>&2 echo "Remediating rule 54/236: 'gnome_gdm_disable_automatic_login'")

if rpm --quiet -q gdm
then
	if ! grep -q "^AutomaticLoginEnable=" /etc/gdm/custom.conf
	then
		sed -i "/^\[daemon\]/a \
		AutomaticLoginEnable=False" /etc/gdm/custom.conf
	else
		sed -i "s/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/g" /etc/gdm/custom.conf
	fi
fi
# END fix for 'gnome_gdm_disable_automatic_login'

###############################################################################
# BEGIN fix (55 / 236) for 'gnome_gdm_disable_guest_login'
###############################################################################
(>&2 echo "Remediating rule 55/236: 'gnome_gdm_disable_guest_login'")

if rpm --quiet -q gdm
then
	if ! grep -q "^TimedLoginEnable=" /etc/gdm/custom.conf
	then
		sed -i "/^\[daemon\]/a \
		TimedLoginEnable=False" /etc/gdm/custom.conf
	else
		sed -i "s/^TimedLoginEnable=.*/TimedLoginEnable=False/g" /etc/gdm/custom.conf
	fi
fi


(>&2 echo "Remediating rule 56/236: 'dconf_db_up_to_date'")

dconf update



###############################################################################
# BEGIN fix Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes. (V-71963)
###############################################################################
(>&2 echo "Remediating rule 60/236: 'grub2_enable_fips_mode'")


# prelink not installed
if test -e /etc/sysconfig/prelink -o -e /usr/sbin/prelink; then
    if grep -q ^PRELINKING /etc/sysconfig/prelink
    then
        sed -i 's/^PRELINKING[:blank:]*=[:blank:]*[:alpha:]*/PRELINKING=no/' /etc/sysconfig/prelink
    else
        printf '\n' >> /etc/sysconfig/prelink
        printf '%s\n' '# Set PRELINKING=no per security requirements' 'PRELINKING=no' >> /etc/sysconfig/prelink
    fi

    # Undo previous prelink changes to binaries if prelink is available.
    if test -x /usr/sbin/prelink; then
        /usr/sbin/prelink -ua
    fi
fi

if grep -q -m1 -o aes /proc/cpuinfo; then
	if ! rpm -q --quiet "dracut-fips-aesni" ; then
    yum install -y "dracut-fips-aesni"
fi
fi
if ! rpm -q --quiet "dracut-fips" ; then
    yum install -y "dracut-fips"
fi

dracut -f

# Correct the form of default kernel command line in  grub
if grep -q '^GRUB_CMDLINE_LINUX=.*fips=.*"'  /etc/default/grub; then
	# modify the GRUB command-line if a fips= arg already exists
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)fips=[^[:space:]]*\(.*"\)/\1 fips=1 \2/'  /etc/default/grub
else
	# no existing fips=arg is present, append it
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 fips=1"/'  /etc/default/grub
fi

# Get the UUID of the device mounted at /boot.
BOOT_UUID=$(findmnt --noheadings --output uuid --target /boot)

if grep -q '^GRUB_CMDLINE_LINUX=".*boot=.*"'  /etc/default/grub; then
	# modify the GRUB command-line if a boot= arg already exists
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)boot=[^[:space:]]*\(.*"\)/\1 boot=UUID='"${BOOT_UUID} \2/" /etc/default/ grub
else
	# no existing boot=arg is present, append it
	sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 boot=UUID='${BOOT_UUID}'"/'  /etc/default/grub
fi

# Correct the form of kernel command line for each installed kernel in the bootloader
/sbin/grubby --update-kernel=ALL --args="fips=1 boot=UUID=${BOOT_UUID}"
# END fix for 'grub2_enable_fips_mode'


###############################################################################
# The file permissions, ownership, and group membership of system files and commands must match the vendor values. (V-71849)
###############################################################################
(>&2 echo "Remediating rule 62/236: 'rpm_verify_permissions'")

# Declare array to hold set of RPM packages we need to correct permissions for
declare -A SETPERMS_RPM_DICT

# Create a list of files on the system having permissions different from what
# is expected by the RPM database
readarray -t FILES_WITH_INCORRECT_PERMS < <(rpm -Va --nofiledigest | awk '{ if (substr($0,2,1)=="M") print $NF }')

for FILE_PATH in "${FILES_WITH_INCORRECT_PERMS[@]}"
do
	RPM_PACKAGE=$(rpm -qf "$FILE_PATH")
	# Use an associative array to store packages as it's keys, not having to care about duplicates.
	SETPERMS_RPM_DICT["$RPM_PACKAGE"]=1
done

# For each of the RPM packages left in the list -- reset its permissions to the
# correct values
for RPM_PACKAGE in "${!SETPERMS_RPM_DICT[@]}"
do
	rpm --setperms "${RPM_PACKAGE}"
done
# END fix for 'rpm_verify_permissions'

###############################################################################
# The file permissions, ownership, and group membership of system files and commands must match the vendor values. (V-71849)
###############################################################################
(>&2 echo "Remediating rule 63/236: 'rpm_verify_ownership'")

# Declare array to hold set of RPM packages we need to correct permissions for
declare -A SETPERMS_RPM_DICT

# Create a list of files on the system having permissions different from what
# is expected by the RPM database
readarray -t FILES_WITH_INCORRECT_PERMS < <(rpm -Va --nofiledigest | awk '{ if (substr($0,6,1)=="U" || substr($0,7,1)=="G") print $NF }')

for FILE_PATH in "${FILES_WITH_INCORRECT_PERMS[@]}"
do
        RPM_PACKAGE=$(rpm -qf "$FILE_PATH")
	# Use an associative array to store packages as it's keys, not having to care about duplicates.
	SETPERMS_RPM_DICT["$RPM_PACKAGE"]=1
done

# For each of the RPM packages left in the list -- reset its permissions to the
# correct values
for RPM_PACKAGE in "${!SETPERMS_RPM_DICT[@]}"
do
        rpm --setugids "${RPM_PACKAGE}"
done

###############################################################################
# The cryptographic hash of system files and commands must match vendor values. (V-71855)
###############################################################################
(>&2 echo "Remediating rule 64/236: 'rpm_verify_hashes'")

# Find which files have incorrect hash (not in /etc, because there are all system related config. files) and then get files names
files_with_incorrect_hash="$(rpm -Va | grep -E '^..5.* /(bin|sbin|lib|lib64|usr)/' | awk '{print $NF}' )"
# From files names get package names and change newline to space, because rpm writes each package to new line
packages_to_reinstall="$(rpm -qf $files_with_incorrect_hash | tr '\n' ' ')"

yum reinstall -y $packages_to_reinstall
# END fix for 'rpm_verify_hashes'

###############################################################################
# A file integrity tool must verify the baseline operating system configuration at least weekly. (V-71973)
###############################################################################
(>&2 echo "Remediating rule 65/236: 'package_aide_installed'")

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi
# END fix for 'package_aide_installed'

###############################################################################
# Designated personnel must be notified if baseline configurations are changed in an unauthorized manner. (V-71975)
###############################################################################
(>&2 echo "Remediating rule 66/236: 'aide_verify_ext_attributes'")

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

aide_conf="/etc/aide.conf"

groups=$(LC_ALL=C grep "^[A-Z]\+" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)

for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *xattrs* ]]
	then
		if [[ -z $config ]]
		then
			config="xattrs"
		else
			config=$config"+xattrs"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done
# END fix for 'aide_verify_ext_attributes'

###############################################################################
# The file integrity tool must be configured to verify Access Control Lists (ACLs). (V-72069)
###############################################################################
(>&2 echo "Remediating rule 67/236: 'aide_verify_acls'")

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

aide_conf="/etc/aide.conf"

groups=$(LC_ALL=C grep "^[A-Z]\+" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)

for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *acl* ]]
	then
		if [[ -z $config ]]
		then
			config="acl"
		else
			config=$config"+acl"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done
# END fix for 'aide_verify_acls'

###############################################################################
# The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories. (V-72073)
###############################################################################
(>&2 echo "Remediating rule 68/236: 'aide_use_fips_hashes'")

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

aide_conf="/etc/aide.conf"
forbidden_hashes=(sha1 rmd160 
whirlpool tiger haval gost crc32)

groups=$(LC_ALL=C grep "^[A-Z]\+" $aide_conf | cut -f1 -d ' ' | tr -d ' ' | sort -u)

for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *sha512* ]]
	then
		config=$config"+sha512"
	fi

	for hash in ${forbidden_hashes[@]}
	do
		config=$(echo $config | sed "s/$hash//")
	done

	config=$(echo $config | sed "s/^\+*//")
	config=$(echo $config | sed "s/\+\++/+/")
	config=$(echo $config | sed "s/\+$//")

	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done
# END fix for 'aide_use_fips_hashes'

###############################################################################
# A file integrity tool must verify the baseline operating system configuration at least weekly. (V-71973)
###############################################################################
(>&2 echo "Remediating rule 69/236: 'aide_scan_notification'")

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

CRONTAB=/etc/crontab
CRONDIRS='/etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'

if [ -f /var/spool/cron/root ]; then
	VARSPOOL=/var/spool/cron/root
fi

if ! grep -qR '^.*\/usr\/sbin\/aide\s*\-\-check.*|.*\/bin\/mail\s*-s\s*".*"\s*root@.*$' $CRONTAB $VARSPOOL $CRONDIRS; then
	echo '0 5 * * * root /usr/sbin/aide  --check | /bin/mail -s "$(hostname) - AIDE Integrity Check" root@localhost' >> $CRONTAB
fi
# END fix for 'aide_scan_notification'

###############################################################################
# Designated personnel must be notified if baseline configurations are changed in an unauthorized manner. (V-71975)
###############################################################################
(>&2 echo "Remediating rule 70/236: 'aide_periodic_cron_checking'")

if ! rpm -q --quiet "aide" ; then
    yum install -y "aide"
fi

if ! grep -q "/usr/sbin/aide --check" /etc/crontab ; then
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
else
    sed -i '/^.*\/usr\/sbin\/aide --check.*$/d' /etc/crontab
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
fi
# END fix for 'aide_periodic_cron_checking'

###############################################################################
# BEGIN fix (71 / 236) for 'security_patches_up_to_date'
###############################################################################
(>&2 echo "Remediating rule 71/236: 'security_patches_up_to_date'")
yum -y update
# END fix for 'security_patches_up_to_date'

###############################################################################
# Vendor packaged system security patches and updates must be installed and up to date. (V-71999)
###############################################################################
(>&2 echo "Remediating rule 72/236: 'clean_components_post_updating'")

if grep --silent ^clean_requirements_on_remove /etc/yum.conf ; then
        sed -i "s/^clean_requirements_on_remove.*/clean_requirements_on_remove=1/g" /etc/yum.conf
else
        echo -e "\n# Set clean_requirements_on_remove to 1 per security requirements" >> /etc/yum.conf
        echo "clean_requirements_on_remove=1" >> /etc/yum.conf
fi
# END fix for 'clean_components_post_updating'

###############################################################################
# The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. (V-71979)
###############################################################################
(>&2 echo "Remediating rule 73/236: 'ensure_gpgcheck_globally_activated'")
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append "/etc/yum.conf" '^gpgcheck' '1' 'CCE-26989-4'
# END fix for 'ensure_gpgcheck_globally_activated'

###############################################################################
# Rule Title: The Red Hat Enterprise Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
###############################################################################
(>&2 echo "Remediating rule 74/236: 'ensure_gpgcheck_local_packages'")
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/yum.conf' '^localpkg_gpgcheck' '1' 'CCE-80347-8'
# END fix for 'ensure_gpgcheck_local_packages'


###############################################################################
# The system must send rsyslog output to a log aggregation server. (V-72209)
###############################################################################
(>&2 echo "Remediating rule 79/236: 'rsyslog_remote_loghost'")

rsyslog_remote_loghost_address="logcollector"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/rsyslog.conf' '^\*\.\*' "@@$rsyslog_remote_loghost_address" 'CCE-27343-3' '%s %s'
# END fix for 'rsyslog_remote_loghost'

###############################################################################
# Cron logging must be implemented. (V-72051)
###############################################################################
(>&2 echo "Remediating rule 80/236: 'rsyslog_cron_logging'")

if ! grep -s "^\s*cron\.\*\s*/var/log/cron$" /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
	mkdir -p /etc/rsyslog.d
	echo "cron.*	/var/log/cron" >> /etc/rsyslog.d/cron.conf
fi
# END fix for 'rsyslog_cron_logging'


###############################################################################
# The host must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments. (V-72219)
###############################################################################
(>&2 echo "Remediating rule 83/236: 'configure_firewalld_ports'")


if ! rpm -q --quiet "firewalld" ; then
    yum install -y "firewalld"
fi
firewalld_sshd_zone="public"

# This assumes that firewalld_sshd_zone is one of the pre-defined zones
if [ ! -f /etc/firewalld/zones/${firewalld_sshd_zone}.xml ]; then
    cp /usr/lib/firewalld/zones/${firewalld_sshd_zone}.xml /etc/firewalld/zones/${firewalld_sshd_zone}.xml
fi
if ! grep -q 'service name="ssh"' /etc/firewalld/zones/${firewalld_sshd_zone}.xml; then
    sed -i '/<\/description>/a \
  <service name="ssh"/>' /etc/firewalld/zones/${firewalld_sshd_zone}.xml
fi

# Check if any eth interface is bounded to the zone with SSH service enabled
nic_bound=false
eth_interface_list=$(ip link show up | cut -d ' ' -f2 | cut -d ':' -s -f1 | grep -E '^(en|eth)')
for interface in $eth_interface_list; do
    if grep -q "ZONE=$firewalld_sshd_zone" /etc/sysconfig/network-scripts/ifcfg-$interface; then
        nic_bound=true
        break;
    fi
done

if [ $nic_bound = false ];then
    # Add first NIC to SSH enabled zone

    if ! firewall-cmd --state -q; then
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
        replace_or_append "/etc/sysconfig/network-scripts/ifcfg-${eth_interface_list[0]}" '^ZONE=' "$firewalld_sshd_zone" 'CCE-80447-6' '%s=%s'
    else
        # If firewalld service is running, we need to do this step with firewall-cmd
        # Otherwise firewalld will comunicate with NetworkManage and will revert assigned zone
        # of NetworkManager managed interfaces upon reload
        firewall-cmd --zone=$firewalld_sshd_zone --add-interface=${eth_interface_list[0]}
        firewall-cmd --reload
    fi
fi
# END fix for 'configure_firewalld_ports'

###############################################################################
# BEGIN fix (84 / 236) for 'configure_firewalld_rate_limiting'
###############################################################################
(>&2 echo "Remediating rule 84/236: 'configure_firewalld_rate_limiting'")
(>&2 echo "FIX FOR THIS RULE 'configure_firewalld_rate_limiting' IS MISSING!")
# END fix for 'configure_firewalld_rate_limiting'

###############################################################################
# The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces. (V-72271)
###############################################################################
(>&2 echo "Remediating rule 85/236: 'service_firewalld_enabled'")

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" start 'firewalld.service'
"$SYSTEMCTL_EXEC" enable 'firewalld.service'
# END fix for 'service_firewalld_enabled'


###############################################################################
# The system must not forward IPv6 source-routed packets. (V-72319)
###############################################################################
(>&2 echo "Remediating rule 87/236: 'sysctl_net_ipv6_conf_all_accept_source_route'")

sysctl_net_ipv6_conf_all_accept_source_route_value="0"

#
# Set runtime for net.ipv6.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_source_route=$sysctl_net_ipv6_conf_all_accept_source_route_value

#
# If net.ipv6.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_source_route = value" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv6.conf.all.accept_source_route' "$sysctl_net_ipv6_conf_all_accept_source_route_value" 'CCE-80179-5'
# END fix for 'sysctl_net_ipv6_conf_all_accept_source_route'

###############################################################################
# The system must not forward Internet Protocol version 4 (IPv4) source-routed packets. (V-72283)
###############################################################################
(>&2 echo "Remediating rule 88/236: 'sysctl_net_ipv4_conf_default_accept_source_route'")

sysctl_net_ipv4_conf_default_accept_source_route_value="0"

#
# Set runtime for net.ipv4.conf.default.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_source_route=$sysctl_net_ipv4_conf_default_accept_source_route_value

#
# If net.ipv4.conf.default.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_source_route = value" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.accept_source_route' "$sysctl_net_ipv4_conf_default_accept_source_route_value" 'CCE-80162-1'
# END fix for 'sysctl_net_ipv4_conf_default_accept_source_route'

###############################################################################
# The system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address. (V-72287)
###############################################################################
(>&2 echo "Remediating rule 89/236: 'sysctl_net_ipv4_icmp_echo_ignore_broadcasts'")

sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value="1"

#
# Set runtime for net.ipv4.icmp_echo_ignore_broadcasts
#
/sbin/sysctl -q -n -w net.ipv4.icmp_echo_ignore_broadcasts=$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value

#
# If net.ipv4.icmp_echo_ignore_broadcasts present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_echo_ignore_broadcasts = value" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.icmp_echo_ignore_broadcasts' "$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value" 'CCE-80165-4'
# END fix for 'sysctl_net_ipv4_icmp_echo_ignore_broadcasts'

###############################################################################
# The system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted. (V-72289)
###############################################################################
(>&2 echo "Remediating rule 90/236: 'sysctl_net_ipv4_conf_all_accept_redirects'")

sysctl_net_ipv4_conf_all_accept_redirects_value="0"

#
# Set runtime for net.ipv4.conf.all.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_redirects=$sysctl_net_ipv4_conf_all_accept_redirects_value

#
# If net.ipv4.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_redirects = value" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.accept_redirects' "$sysctl_net_ipv4_conf_all_accept_redirects_value" 'CCE-80158-9'
# END fix for 'sysctl_net_ipv4_conf_all_accept_redirects'

###############################################################################
# The system must not forward IPv4 source-routed packets. (V-72319)
###############################################################################
(>&2 echo "Remediating rule 91/236: 'sysctl_net_ipv4_conf_all_accept_source_route'")

sysctl_net_ipv4_conf_all_accept_source_route_value="0"

#
# Set runtime for net.ipv4.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_source_route=$sysctl_net_ipv4_conf_all_accept_source_route_value

#
# If net.ipv4.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_source_route = value" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.accept_source_route' "$sysctl_net_ipv4_conf_all_accept_source_route_value" 'CCE-27434-0'
# END fix for 'sysctl_net_ipv4_conf_all_accept_source_route'

###############################################################################
# The system must not forward IPv6 source-routed packets. (V-72319
###############################################################################
(>&2 echo "Remediating rule 92/236: 'sysctl_net_ipv4_conf_default_accept_redirects'")

sysctl_net_ipv4_conf_default_accept_redirects_value="0"

#
# Set runtime for net.ipv4.conf.default.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_redirects=$sysctl_net_ipv4_conf_default_accept_redirects_value

#
# If net.ipv4.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_redirects = value" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.accept_redirects' "$sysctl_net_ipv4_conf_default_accept_redirects_value" 'CCE-80163-9'
# END fix for 'sysctl_net_ipv4_conf_default_accept_redirects'

###############################################################################
# The system must not forward Internet Protocol version 4 (IPv4) source-routed packets. (V-72283)
###############################################################################
(>&2 echo "Remediating rule 93/236: 'sysctl_net_ipv4_ip_forward'")


#
# Set runtime for net.ipv4.ip_forward
#
/sbin/sysctl -q -n -w net.ipv4.ip_forward=0

#
# If net.ipv4.ip_forward present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.ip_forward = 0" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.ip_forward' "0" 'CCE-80157-1'
# END fix for 'sysctl_net_ipv4_ip_forward'

###############################################################################
# The system must not forward Internet Protocol version 4 (IPv4) source-routed packets. (V-72283)
###############################################################################
(>&2 echo "Remediating rule 94/236: 'sysctl_net_ipv4_conf_all_send_redirects'")


#
# Set runtime for net.ipv4.conf.all.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.send_redirects=0

#
# If net.ipv4.conf.all.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.all.send_redirects = 0" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.send_redirects' "0" 'CCE-80156-3'
# END fix for 'sysctl_net_ipv4_conf_all_send_redirects'

###############################################################################
# The system must not forward Internet Protocol version 4 (IPv4) source-routed packets. (V-72283)
###############################################################################
(>&2 echo "Remediating rule 95/236: 'sysctl_net_ipv4_conf_default_send_redirects'")


#
# Set runtime for net.ipv4.conf.default.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.send_redirects=0

#
# If net.ipv4.conf.default.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.default.send_redirects = 0" to /etc/sysctl.conf
#
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.send_redirects' "0" 'CCE-80999-6'
# END fix for 'sysctl_net_ipv4_conf_default_send_redirects'

###############################################################################
# The Datagram Congestion Control Protocol (DCCP) kernel module must be disabled unless required. (V-77821)
###############################################################################
(>&2 echo "Remediating rule 96/236: 'kernel_module_dccp_disabled'")
if LC_ALL=C grep -q -m 1 "^install dccp" /etc/modprobe.d/dccp.conf ; then
	sed -i 's/^install dccp.*/install dccp /bin/true/g' /etc/modprobe.d/dccp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
fi
# END fix for 'kernel_module_dccp_disabled'





###############################################################################
#The Red Hat Enterprise Linux operating system must enable the SELinux targeted policy.
###############################################################################
(>&2 echo "Remediating rule 103/236: 'selinux_policytype'")

var_selinux_policy_name="targeted"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysconfig/selinux' '^SELINUXTYPE=' $var_selinux_policy_name 'CCE-27279-9' '%s=%s'
# END fix for 'selinux_policytype'




###############################################################################
# The Red Hat Enterprise Linux operating system must enable SELinux.
###############################################################################
(>&2 echo "Remediating rule 106/236: 'selinux_state'")

var_selinux_state="enforcing"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state 'CCE-27334-2' '%s=%s'

fixfiles onboot
fixfiles -f relabel
# END fix for 'selinux_state'

###############################################################################
# BEGIN fix (107 / 236) for 'account_disable_post_pw_expiration'
#  The Red Hat Enterprise Linux operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.
###############################################################################
(>&2 echo "Remediating rule 107/236: 'account_disable_post_pw_expiration'")

var_account_disable_post_pw_expiration="0"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/default/useradd' '^INACTIVE' "$var_account_disable_post_pw_expiration" 'CCE-27355-7' '%s=%s'
# END fix for 'account_disable_post_pw_expiration'

###############################################################################
# The root account must be the only account having unrestricted access to the system. (V-72005).
###############################################################################
(>&2 echo "Remediating rule 108/236: 'accounts_no_uid_except_zero'")
awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | xargs passwd -l
# END fix for 'accounts_no_uid_except_zero'



###############################################################################
#Passwords for new users must be restricted to a 60-day maximum lifetime. (V-71929)
###############################################################################
(>&2 echo "Remediating rule 110/236: 'accounts_maximum_age_login_defs'")

var_accounts_maximum_age_login_defs="60"

grep -q ^PASS_MAX_DAYS /etc/login.defs && \
  sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS     $var_accounts_maximum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MAX_DAYS      $var_accounts_maximum_age_login_defs" >> /etc/login.defs
fi
# END fix for 'accounts_maximum_age_login_defs'


###############################################################################
# The PAM system service must be configured to store only encrypted representations of passwords. (V-71919)
###############################################################################
(>&2 echo "Remediating rule 113/236: 'no_empty_passwords'")
sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/system-auth
sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/password-auth
# END fix for 'no_empty_passwords'


###############################################################################
# The shadow file must be configured to store only encrypted representations of passwords. (V-71921)
###############################################################################
(>&2 echo "Remediating rule 115/236: 'set_password_hashing_algorithm_logindefs'")
if grep --silent ^ENCRYPT_METHOD /etc/login.defs ; then
	sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' /etc/login.defs
else
	echo "" >> /etc/login.defs
	echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
fi
# END fix for 'set_password_hashing_algorithm_logindefs'

###############################################################################
# The system must not have accounts configured with blank or null passwords. (V-71937)
###############################################################################
(>&2 echo "Remediating rule 116/236: 'set_password_hashing_algorithm_systemauth'")

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do
	if ! grep -q "^password.*sufficient.*pam_unix.so.*sha512" $pamFile; then
		sed -i --follow-symlinks "/^password.*sufficient.*pam_unix.so/ s/$/ sha512/" $pamFile
	fi
done
# END fix for 'set_password_hashing_algorithm_systemauth'

###############################################################################
# User and group account administration utilities must be configured to store only encrypted representations of passwords. (V-71923)
###############################################################################
(>&2 echo "Remediating rule 117/236: 'set_password_hashing_algorithm_libuserconf'")

LIBUSER_CONF="/etc/libuser.conf"
CRYPT_STYLE_REGEX='[[:space:]]*\[defaults](.*(\n)+)+?[[:space:]]*crypt_style[[:space:]]*'

# Try find crypt_style in [defaults] section. If it is here, then change algorithm to sha512.
# If it isn't here, then add it to [defaults] section.
if grep -qzosP $CRYPT_STYLE_REGEX $LIBUSER_CONF ; then
        sed -i "s/\(crypt_style[[:space:]]*=[[:space:]]*\).*/\1sha512/g" $LIBUSER_CONF
elif grep -qs "\[defaults]" $LIBUSER_CONF ; then
        sed -i "/[[:space:]]*\[defaults]/a crypt_style = sha512" $LIBUSER_CONF
else
        echo -e "[defaults]\ncrypt_style = sha512" >> $LIBUSER_CONF
fi
# END fix for 'set_password_hashing_algorithm_libuserconf'

###############################################################################
# If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. (V-71945)
###############################################################################
(>&2 echo "Remediating rule 118/236: 'accounts_passwords_pam_faillock_deny_root'")

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

# This script fixes absence of pam_faillock.so in PAM stack or the
# absense of even_deny_root in pam_faillock.so arguments
# When inserting auth pam_faillock.so entries,
# the entry with preauth argument will be added before pam_unix.so module
# and entry with authfail argument will be added before pam_deny.so module.

# The placement of pam_faillock.so entries will not be changed
# if they are already present

for pamFile in "${AUTH_FILES[@]}"
do
	# if PAM file is missing, system is not using PAM or broken
	if [ ! -f $pamFile ]; then
		continue
	fi

	# is 'auth required' here?
	if grep -q "^auth.*required.*pam_faillock.so.*" $pamFile; then
		# has 'auth required' even_deny_root option?
		if ! grep -q "^auth.*required.*pam_faillock.so.*preauth.*even_deny_root" $pamFile; then
			# even_deny_root is not present
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*\).*/\1 even_deny_root/" $pamFile
		fi
	else
		# no 'auth required', add it
		sed -i --follow-symlinks "/^auth.*pam_unix.so.*/i auth required pam_faillock.so preauth silent even_deny_root" $pamFile
	fi

	# is 'auth [default=die]' here?
	if grep -q "^auth.*\[default=die\].*pam_faillock.so.*" $pamFile; then
		# has 'auth [default=die]' even_deny_root option?
		if ! grep -q "^auth.*\[default=die\].*pam_faillock.so.*authfail.*even_deny_root" $pamFile; then
			# even_deny_root is not present
			sed -i --follow-symlinks "s/\(^auth.*\[default=die\].*pam_faillock.so.*authfail.*\).*/\1 even_deny_root/" $pamFile
		fi
	else
		# no 'auth [default=die]', add it
		sed -i --follow-symlinks "/^auth.*pam_unix.so.*/a auth [default=die] pam_faillock.so authfail silent even_deny_root" $pamFile
	fi
done
# END fix for 'accounts_passwords_pam_faillock_deny_root'

###############################################################################
# Rule Title: The Red Hat Enterprise Linux operating system must be configured to lock accounts for a minimum of 15 minutes after three unsuccessful logon attempts within a 15-minute timeframe.
# Rule Title: The Red Hat Enterprise Linux operating system must lock the associated account after three unsuccessful root logon attempts are made within a 15-minute period.
###############################################################################
(>&2 echo "Remediating rule 119/236: 'accounts_passwords_pam_faillock_unlock_time'")

var_accounts_passwords_pam_faillock_unlock_time="never"
function include_set_faillock_option {
	:
}

function insert_preauth {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	# is auth required pam_faillock.so preauth present?
	if grep -qE "^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$" "$pam_file" ; then
		# is the option set?
		if grep -qE "^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$option=([0-9]*).*$" "$pam_file" ; then
			# just change the value of option to a correct value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\($option *= *\).*/\1\2$value/" "$pam_file"
		# the option is not set.
		else
			# append the option
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ $option=$value/" "$pam_file"
		fi
	# auth required pam_faillock.so preauth is not present, insert the whole line
	else
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent $option=$value" "$pam_file"
	fi
}

function insert_authfail {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	# is auth default pam_faillock.so authfail present?
	if grep -qE "^\s*auth\s+(\[default=die\])\s+pam_faillock\.so\s+authfail.*$" "$pam_file" ; then
		# is the option set?
		if grep -qE "^\s*auth\s+(\[default=die\])\s+pam_faillock\.so\s+authfail.*$option=([0-9]*).*$" "$pam_file" ; then
			# just change the value of option to a correct value
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\($option *= *\).*/\1\2$value/" "$pam_file"
		# the option is not set.
		else
			# append the option
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ $option=$value/" "$pam_file"
		fi
	# auth default pam_faillock.so authfail is not present, insert the whole line
	else
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail $option=$value" "$pam_file"
	fi
}

function insert_account {
	local pam_file="$1"
	if ! grep -qE "^\s*account\s+required\s+pam_faillock\.so.*$" "$pam_file" ; then
		sed -E -i --follow-symlinks "/^\s*account\s*required\s*pam_unix.so/i account     required      pam_faillock.so" "$pam_file"
	fi
}

function set_faillock_option {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	insert_preauth "$pam_file" "$option" "$value"
	insert_authfail "$pam_file" "$option" "$value"
	insert_account "$pam_file"
}
include_set_faillock_option

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pam_file in "${AUTH_FILES[@]}"
do
	set_faillock_option "$pam_file" "unlock_time" "$var_accounts_passwords_pam_faillock_unlock_time"
done
# END fix for 'accounts_passwords_pam_faillock_unlock_time'


###############################################################################
# If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. (V-71945)
###############################################################################
(>&2 echo "Remediating rule 121/236: 'accounts_passwords_pam_faillock_interval'")
function include_set_faillock_option {
	:
}

function insert_preauth {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	# is auth required pam_faillock.so preauth present?
	if grep -qE "^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$" "$pam_file" ; then
		# is the option set?
		if grep -qE "^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$option=([0-9]*).*$" "$pam_file" ; then
			# just change the value of option to a correct value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\($option *= *\).*/\1\2$value/" "$pam_file"
		# the option is not set.
		else
			# append the option
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ $option=$value/" "$pam_file"
		fi
	# auth required pam_faillock.so preauth is not present, insert the whole line
	else
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent $option=$value" "$pam_file"
	fi
}

function insert_authfail {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	# is auth default pam_faillock.so authfail present?
	if grep -qE "^\s*auth\s+(\[default=die\])\s+pam_faillock\.so\s+authfail.*$" "$pam_file" ; then
		# is the option set?
		if grep -qE "^\s*auth\s+(\[default=die\])\s+pam_faillock\.so\s+authfail.*$option=([0-9]*).*$" "$pam_file" ; then
			# just change the value of option to a correct value
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\($option *= *\).*/\1\2$value/" "$pam_file"
		# the option is not set.
		else
			# append the option
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ $option=$value/" "$pam_file"
		fi
	# auth default pam_faillock.so authfail is not present, insert the whole line
	else
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail $option=$value" "$pam_file"
	fi
}

function insert_account {
	local pam_file="$1"
	if ! grep -qE "^\s*account\s+required\s+pam_faillock\.so.*$" "$pam_file" ; then
		sed -E -i --follow-symlinks "/^\s*account\s*required\s*pam_unix.so/i account     required      pam_faillock.so" "$pam_file"
	fi
}

function set_faillock_option {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	insert_preauth "$pam_file" "$option" "$value"
	insert_authfail "$pam_file" "$option" "$value"
	insert_account "$pam_file"
}
include_set_faillock_option

var_accounts_passwords_pam_faillock_fail_interval="900"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pam_file in "${AUTH_FILES[@]}"
do
	set_faillock_option "$pam_file" "fail_interval" "$var_accounts_passwords_pam_faillock_fail_interval"
done
# END fix for 'accounts_passwords_pam_faillock_interval'

###############################################################################
# If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. (V-71945)
###############################################################################
(>&2 echo "Remediating rule 122/236: 'accounts_passwords_pam_faillock_deny'")

var_accounts_passwords_pam_faillock_deny="3"
function include_set_faillock_option {
	:
}

function insert_preauth {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	# is auth required pam_faillock.so preauth present?
	if grep -qE "^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$" "$pam_file" ; then
		# is the option set?
		if grep -qE "^\s*auth\s+required\s+pam_faillock\.so\s+preauth.*$option=([0-9]*).*$" "$pam_file" ; then
			# just change the value of option to a correct value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\($option *= *\).*/\1\2$value/" "$pam_file"
		# the option is not set.
		else
			# append the option
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ $option=$value/" "$pam_file"
		fi
	# auth required pam_faillock.so preauth is not present, insert the whole line
	else
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent $option=$value" "$pam_file"
	fi
}

function insert_authfail {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	# is auth default pam_faillock.so authfail present?
	if grep -qE "^\s*auth\s+(\[default=die\])\s+pam_faillock\.so\s+authfail.*$" "$pam_file" ; then
		# is the option set?
		if grep -qE "^\s*auth\s+(\[default=die\])\s+pam_faillock\.so\s+authfail.*$option=([0-9]*).*$" "$pam_file" ; then
			# just change the value of option to a correct value
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\($option *= *\).*/\1\2$value/" "$pam_file"
		# the option is not set.
		else
			# append the option
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ $option=$value/" "$pam_file"
		fi
	# auth default pam_faillock.so authfail is not present, insert the whole line
	else
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail $option=$value" "$pam_file"
	fi
}

function insert_account {
	local pam_file="$1"
	if ! grep -qE "^\s*account\s+required\s+pam_faillock\.so.*$" "$pam_file" ; then
		sed -E -i --follow-symlinks "/^\s*account\s*required\s*pam_unix.so/i account     required      pam_faillock.so" "$pam_file"
	fi
}

function set_faillock_option {
	local pam_file="$1"
	local option="$2"
	local value="$3"
	insert_preauth "$pam_file" "$option" "$value"
	insert_authfail "$pam_file" "$option" "$value"
	insert_account "$pam_file"
}
include_set_faillock_option

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pam_file in "${AUTH_FILES[@]}"
do
	set_faillock_option "$pam_file" "deny" "$var_accounts_passwords_pam_faillock_deny"
done
# END fix for 'accounts_passwords_pam_faillock_deny'

###############################################################################
# Passwords must be a minimum of 15 characters in length. (V-71935)
###############################################################################
(>&2 echo "Remediating rule 123/236: 'accounts_password_pam_minlen'")

var_password_pam_minlen="15"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^minlen' $var_password_pam_minlen 'CCE-27293-0' '%s = %s'
# END fix for 'accounts_password_pam_minlen'

###############################################################################
# When passwords are changed or new passwords are established, pwquality must be used. (V-73159)
###############################################################################
(>&2 echo "Remediating rule 124/236: 'accounts_password_pam_maxclassrepeat'")

var_password_pam_maxclassrepeat="4"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^maxclassrepeat' $var_password_pam_maxclassrepeat 'CCE-27512-3' '%s = %s'
# END fix for 'accounts_password_pam_maxclassrepeat'

###############################################################################
#  When passwords are changed or new passwords are established, pwquality must be used. (V-73159)
###############################################################################
(>&2 echo "Remediating rule 125/236: 'accounts_password_pam_maxrepeat'")

var_password_pam_maxrepeat="3"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^maxrepeat' $var_password_pam_maxrepeat 'CCE-82055-5' '%s = %s'
# END fix for 'accounts_password_pam_maxrepeat'

###############################################################################
# When passwords are changed or new passwords are assigned, the new password must contain at least one numeric character. (V-71907)
###############################################################################
(>&2 echo "Remediating rule 126/236: 'accounts_password_pam_dcredit'")

var_password_pam_dcredit="-1"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^dcredit' $var_password_pam_dcredit 'CCE-27214-6' '%s = %s'
# END fix for 'accounts_password_pam_dcredit'

###############################################################################
# When passwords are changed a minimum of four character classes must be changed. (V-71913)
###############################################################################
(>&2 echo "Remediating rule 127/236: 'accounts_password_pam_minclass'")

var_password_pam_minclass="4"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^minclass' $var_password_pam_minclass 'CCE-82045-6' '%s = %s'
# END fix for 'accounts_password_pam_minclass'

###############################################################################
# When passwords are changed a minimum of eight of the total number of characters must be changed. (V-71911)
###############################################################################
(>&2 echo "Remediating rule 128/236: 'accounts_password_pam_difok'")

var_password_pam_difok="8"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^difok' $var_password_pam_difok 'CCE-82020-9' '%s = %s'
# END fix for 'accounts_password_pam_difok'

###############################################################################
# When passwords are changed or new passwords are assigned, the new password must contain at least one special character. (V-71909)
###############################################################################
(>&2 echo "Remediating rule 129/236: 'accounts_password_pam_ocredit'")

var_password_pam_ocredit="-1"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^ocredit' $var_password_pam_ocredit 'CCE-27360-7' '%s = %s'
# END fix for 'accounts_password_pam_ocredit'

###############################################################################
#  When passwords are changed or new passwords are established, the new password must contain at least one lower-case character. (V-71905
###############################################################################
(>&2 echo "Remediating rule 130/236: 'accounts_password_pam_lcredit'")

var_password_pam_lcredit="-1"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^lcredit' $var_password_pam_lcredit 'CCE-27345-8' '%s = %s'
# END fix for 'accounts_password_pam_lcredit'

###############################################################################
# When passwords are changed or new passwords are established, the new password must contain at least one upper-case character. (V-71903)
###############################################################################
(>&2 echo "Remediating rule 131/236: 'accounts_password_pam_ucredit'")

var_password_pam_ucredit="-1"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/security/pwquality.conf' '^ucredit' $var_password_pam_ucredit 'CCE-27200-5' '%s = %s'
# END fix for 'accounts_password_pam_ucredit'

###############################################################################
# Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period. (V-71943)
###############################################################################
(>&2 echo "Remediating rule 132/236: 'accounts_password_pam_retry'")

var_password_pam_retry="3"

if grep -q "retry=" /etc/pam.d/system-auth ; then
	sed -i --follow-symlinks "s/\(retry *= *\).*/\1$var_password_pam_retry/" /etc/pam.d/system-auth
else
	sed -i --follow-symlinks "/pam_pwquality.so/ s/$/ retry=$var_password_pam_retry/" /etc/pam.d/system-auth
fi
# END fix for 'accounts_password_pam_retry'

###############################################################################
# Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period. (V-71943)
###############################################################################
(>&2 echo "Remediating rule 133/236: 'display_login_attempts'")
if grep -q "^session.*pam_lastlog.so" /etc/pam.d/postlogin; then
	sed -i --follow-symlinks "/pam_lastlog.so/d" /etc/pam.d/postlogin
fi

echo "session     [default=1]   pam_lastlog.so nowtmp showfailed" >> /etc/pam.d/postlogin
echo "session     optional      pam_lastlog.so silent noupdate showfailed" >> /etc/pam.d/postlogin
# END fix for 'display_login_attempts'

###############################################################################
# The operating system must have the screen package installed. (V-71897)
###############################################################################
(>&2 echo "Remediating rule 134/236: 'package_screen_installed'")

if ! rpm -q --quiet "screen" ; then
    yum install -y "screen"
fi
# END fix for 'package_screen_installed'

###############################################################################
# The operating system must have the required packages for multifactor authentication installed. (V-72417)
###############################################################################
(>&2 echo "Remediating rule 135/236: 'install_smartcard_packages'")

if ! rpm -q --quiet "esc" ; then
    yum install -y "esc"
fi
if ! rpm -q --quiet "pam_pkcs11" ; then
    yum install -y "pam_pkcs11"
fi
# END fix for 'install_smartcard_packages'

###############################################################################
# The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication. (V-71965)
###############################################################################
(>&2 echo "Remediating rule 136/236: 'smartcard_configure_cert_checking'")

# Install required packages
if ! rpm --quiet -q pam_pkcs11; then yum -y -d 1 install pam_pkcs11; fi

if grep "^\s*cert_policy" /etc/pam_pkcs11/pam_pkcs11.conf | grep -qv "ocsp_on"; then
	sed -i "/^\s*#/! s/cert_policy.*/cert_policy = ca, ocsp_on, signature;/g" /etc/pam_pkcs11/pam_pkcs11.conf
fi
# END fix for 'smartcard_configure_cert_checking'



# Enable pcscd.socket systemd activation socket
# Function to enable/disable and start/stop services on RHEL and Fedora systems.
#
# Example Call(s):
#
#     service_command enable bluetooth
#     service_command disable bluetooth.service
#
#     Using xinetd:
#     service_command disable rsh.socket xinetd=rsh
#
function service_command {

# Load function arguments into local variables
local service_state=$1
local service=$2
local xinetd

xinetd=$(echo $3 | cut -d = -f 2)

# Check sanity of the input
if [ $# -lt "2" ]
then
  echo "Usage: service_command 'enable/disable' 'service_name.service'"
  echo
  echo "To enable or disable xinetd services add \'xinetd=service_name\'"
  echo "as the last argument"  
  echo "Aborting."
  exit 1
fi

# If systemctl is installed, use systemctl command; otherwise, use the service/chkconfig commands
if [ -f "/usr/bin/systemctl" ] ; then
  service_util="/usr/bin/systemctl"
else
  service_util="/sbin/service"
  chkconfig_util="/sbin/chkconfig"
fi

# If disable is not specified in arg1, set variables to enable services.
# Otherwise, variables are to be set to disable services.
if [ "$service_state" != 'disable' ] ; then
  service_state="enable"
  service_operation="start"
  chkconfig_state="on"
else
  service_state="disable"
  service_operation="stop"
  chkconfig_state="off"
fi

# If chkconfig_util is not empty, use chkconfig/service commands.
if [ "x$chkconfig_util" != x ] ; then
  $service_util $service $service_operation
  $chkconfig_util --level 0123456 $service $chkconfig_state
else
  $service_util $service_operation $service
  $service_util $service_state $service
  # The service may not be running because it has been started and failed,
  # so let's reset the state so OVAL checks pass.
  # Service should be 'inactive', not 'failed' after reboot though.
  $service_util reset-failed $service
fi

# Test if local variable xinetd is empty using non-bashism.
# If empty, then xinetd is not being used.
if [ "x$xinetd" != x ] ; then
  grep -qi disable /etc/xinetd.d/$xinetd && \

  if [ "$service_operation" = 'disable' ] ; then
    sed -i "s/disable.*/disable         = no/gI" /etc/xinetd.d/$xinetd
  else
    sed -i "s/disable.*/disable         = yes/gI" /etc/xinetd.d/$xinetd
  fi
fi

}
service_command enable pcscd.socket

# Configure the expected /etc/pam.d/system-auth{,-ac} settings directly
#
# The code below will configure system authentication in the way smart card
# logins will be enabled, but also user login(s) via other method to be allowed
#
# NOTE: It is not possible to use the 'authconfig' command to perform the
#       remediation for us, because call of 'authconfig' would discard changes
#       for other remediations (see RH BZ#1357019 for details)
#
#	Therefore we need to configure the necessary settings directly.
#

# Define system-auth config location
SYSTEM_AUTH_CONF="/etc/pam.d/system-auth"
# Define expected 'pam_env.so' row in $SYSTEM_AUTH_CONF
PAM_ENV_SO="auth.*required.*pam_env.so"

# Define 'pam_succeed_if.so' row to be appended past $PAM_ENV_SO row into $SYSTEM_AUTH_CONF
SYSTEM_AUTH_PAM_SUCCEED="\
auth        [success=1 default=ignore] pam_succeed_if.so service notin \
login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver quiet use_uid"
# Define 'pam_pkcs11.so' row to be appended past $SYSTEM_AUTH_PAM_SUCCEED
# row into SYSTEM_AUTH_CONF file
SYSTEM_AUTH_PAM_PKCS11="\
auth        [success=done authinfo_unavail=ignore ignore=ignore default=die] \
pam_pkcs11.so nodebug"

# Define smartcard-auth config location
SMARTCARD_AUTH_CONF="/etc/pam.d/smartcard-auth"
# Define 'pam_pkcs11.so' auth section to be appended past $PAM_ENV_SO into $SMARTCARD_AUTH_CONF
SMARTCARD_AUTH_SECTION="\
auth        [success=done ignore=ignore default=die] pam_pkcs11.so nodebug wait_for_card"
# Define expected 'pam_permit.so' row in $SMARTCARD_AUTH_CONF
PAM_PERMIT_SO="account.*required.*pam_permit.so"
# Define 'pam_pkcs11.so' password section
SMARTCARD_PASSWORD_SECTION="\
password    required      pam_pkcs11.so"

# First Correct the SYSTEM_AUTH_CONF configuration
if ! grep -q 'pam_pkcs11.so' "$SYSTEM_AUTH_CONF"
then
	# Append (expected) pam_succeed_if.so row past the pam_env.so into SYSTEM_AUTH_CONF file
	# and append (expected) pam_pkcs11.so row right after the pam_succeed_if.so we just added
	# in SYSTEM_AUTH_CONF file
	# This will preserve any other already existing row equal to "$SYSTEM_AUTH_PAM_SUCCEED"
	echo "$(awk '/^'"$PAM_ENV_SO"'/{print $0 RS "'"$SYSTEM_AUTH_PAM_SUCCEED"'" RS "'"$SYSTEM_AUTH_PAM_PKCS11"'";next}1' "$SYSTEM_AUTH_CONF")" > "$SYSTEM_AUTH_CONF"
fi

# Then also correct the SMARTCARD_AUTH_CONF
if ! grep -q 'pam_pkcs11.so' "$SMARTCARD_AUTH_CONF"
then
	# Append (expected) SMARTCARD_AUTH_SECTION row past the pam_env.so into SMARTCARD_AUTH_CONF file
	sed -i --follow-symlinks -e '/^'"$PAM_ENV_SO"'/a '"$SMARTCARD_AUTH_SECTION" "$SMARTCARD_AUTH_CONF"
	# Append (expected) SMARTCARD_PASSWORD_SECTION row past the pam_permit.so into SMARTCARD_AUTH_CONF file
	sed -i --follow-symlinks -e '/^'"$PAM_PERMIT_SO"'/a '"$SMARTCARD_PASSWORD_SECTION" "$SMARTCARD_AUTH_CONF"
fi

# Perform /etc/pam_pkcs11/pam_pkcs11.conf settings below
# Define selected constants for later reuse
SP="[:space:]"
PAM_PKCS11_CONF="/etc/pam_pkcs11/pam_pkcs11.conf"

# Ensure OCSP is turned on in $PAM_PKCS11_CONF
# 1) First replace any occurrence of 'none' value of 'cert_policy' key setting with the correct configuration
sed -i "s/^[$SP]*cert_policy[$SP]\+=[$SP]\+none;/\t\tcert_policy = ca, ocsp_on, signature;/g" "$PAM_PKCS11_CONF"
# 2) Then append 'ocsp_on' value setting to each 'cert_policy' key in $PAM_PKCS11_CONF configuration line,
# which does not contain it yet
sed -i "/ocsp_on/! s/^[$SP]*cert_policy[$SP]\+=[$SP]\+\(.*\);/\t\tcert_policy = \1, ocsp_on;/" "$PAM_PKCS11_CONF"
# END fix for 'smartcard_auth'

###############################################################################
# The Red Hat Enterprise Linux operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.
###############################################################################
(>&2 echo "Remediating rule 138/236: 'disable_ctrlaltdel_reboot'")
# The process to disable ctrl+alt+del has changed in RHEL7. 
# Reference: https://access.redhat.com/solutions/1123873

systemctl mask ctrl-alt-del.target
# END fix for 'disable_ctrlaltdel_reboot'

###############################################################################
# The operating system must require authentication upon booting into single-user and maintenance modes. (V-77823)
###############################################################################
(>&2 echo "Remediating rule 139/236: 'require_singleuser_auth'")

service_file="/usr/lib/systemd/system/rescue.service"

sulogin="/sbin/sulogin"

if grep "^ExecStart=.*" "$service_file" ; then
    sed -i "s%^ExecStart=.*%ExecStart=-$sulogin rescue%" "$service_file"
else
    echo "ExecStart=-$sulogin rescue" >> "$service_file"
fi
# END fix for 'require_singleuser_auth'

###############################################################################
# The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
###############################################################################
(>&2 echo "Remediating rule 140/236: 'dconf_gnome_banner_enabled'")
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'gdm.d' '00-security-settings'
dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'gdm.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_banner_enabled'

###############################################################################
# The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
###############################################################################
(>&2 echo "Remediating rule 141/236: 'dconf_gnome_login_banner_text'")

login_banner_text="(^You[\s\n]+are[\s\n]+accessing[\s\n]+a[\s\n]+U.S.[\s\n]+Government[\s\n]+\(USG\)[\s\n]+Information[\s\n]+System[\s\n]+\(IS\)[\s\n]+that[\s\n]+is[\s\n]+provided[\s\n]+for[\s\n]+USG-authorized[\s\n]+use[\s\n]+only.[\s\n]*By[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+\(which[\s\n]+includes[\s\n]+any[\s\n]+device[\s\n]+attached[\s\n]+to[\s\n]+this[\s\n]+IS\),[\s\n]+you[\s\n]+consent[\s\n]+to[\s\n]+the[\s\n]+following[\s\n]+conditions\:(\\n)*(\n)*-[\s\n]*The[\s\n]+USG[\s\n]+routinely[\s\n]+intercepts[\s\n]+and[\s\n]+monitors[\s\n]+communications[\s\n]+on[\s\n]+this[\s\n]+IS[\s\n]+for[\s\n]+purposes[\s\n]+including,[\s\n]+but[\s\n]+not[\s\n]+limited[\s\n]+to,[\s\n]+penetration[\s\n]+testing,[\s\n]+COMSEC[\s\n]+monitoring,[\s\n]+network[\s\n]+operations[\s\n]+and[\s\n]+defense,[\s\n]+personnel[\s\n]+misconduct[\s\n]+\(PM\),[\s\n]+law[\s\n]+enforcement[\s\n]+\(LE\),[\s\n]+and[\s\n]+counterintelligence[\s\n]+\(CI\)[\s\n]+investigations.(\\n)*(\n)*-[\s\n]*At[\s\n]+any[\s\n]+time,[\s\n]+the[\s\n]+USG[\s\n]+may[\s\n]+inspect[\s\n]+and[\s\n]+seize[\s\n]+data[\s\n]+stored[\s\n]+on[\s\n]+this[\s\n]+IS.(\\n)*(\n)*-[\s\n]*Communications[\s\n]+using,[\s\n]+or[\s\n]+data[\s\n]+stored[\s\n]+on,[\s\n]+this[\s\n]+IS[\s\n]+are[\s\n]+not[\s\n]+private,[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+routine[\s\n]+monitoring,[\s\n]+interception,[\s\n]+and[\s\n]+search,[\s\n]+and[\s\n]+may[\s\n]+be[\s\n]+disclosed[\s\n]+or[\s\n]+used[\s\n]+for[\s\n]+any[\s\n]+USG-authorized[\s\n]+purpose.(\\n)*(\n)*-[\s\n]*This[\s\n]+IS[\s\n]+includes[\s\n]+security[\s\n]+measures[\s\n]+\(e.g.,[\s\n]+authentication[\s\n]+and[\s\n]+access[\s\n]+controls\)[\s\n]+to[\s\n]+protect[\s\n]+USG[\s\n]+interests--not[\s\n]+for[\s\n]+your[\s\n]+personal[\s\n]+benefit[\s\n]+or[\s\n]+privacy.(\\n)*(\n)*-[\s\n]*Notwithstanding[\s\n]+the[\s\n]+above,[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+does[\s\n]+not[\s\n]+constitute[\s\n]+consent[\s\n]+to[\s\n]+PM,[\s\n]+LE[\s\n]+or[\s\n]+CI[\s\n]+investigative[\s\n]+searching[\s\n]+or[\s\n]+monitoring[\s\n]+of[\s\n]+the[\s\n]+content[\s\n]+of[\s\n]+privileged[\s\n]+communications,[\s\n]+or[\s\n]+work[\s\n]+product,[\s\n]+related[\s\n]+to[\s\n]+personal[\s\n]+representation[\s\n]+or[\s\n]+services[\s\n]+by[\s\n]+attorneys,[\s\n]+psychotherapists,[\s\n]+or[\s\n]+clergy,[\s\n]+and[\s\n]+their[\s\n]+assistants.[\s\n]+Such[\s\n]+communications[\s\n]+and[\s\n]+work[\s\n]+product[\s\n]+are[\s\n]+private[\s\n]+and[\s\n]+confidential.[\s\n]+See[\s\n]+User[\s\n]+Agreement[\s\n]+for[\s\n]+details.$|^I\'ve[\s\n]+read[\s\n]+\&[\s\n]+consent[\s\n]+to[\s\n]+terms[\s\n]+in[\s\n]+IS[\s\n]+user[\s\n]+agreem\'t$)"
function include_dconf_settings {
	:
}

# Function to configure DConf settings for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_settings 'org/gnome/login-screen' 'banner-message-enable' 'true' 'local.d' '10-banner'
#
function dconf_settings {
	local _path=$1 _key=$2 _value=$3 _db=$4 _settingFile=$5

	# Check sanity of the input
	if [ $# -ne "5" ]
	then
		echo "Usage: dconf_settings 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_settingsfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	# If files contain ibus or distro, ignore them.
	# The assignment assumes that individual filenames don't contain :
	readarray -t SETTINGSFILES < <(grep -r "\\[${_path}\\]" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	DCONFFILE="/etc/dconf/db/${_db}/${_settingFile}"
	DBDIR="/etc/dconf/db/${_db}"

	mkdir -p "${DBDIR}"

	if [ ${#SETTINGSFILES[@]} -eq 0 ]
	then
		[ ! -z ${DCONFFILE} ] || echo "" >> ${DCONFFILE}
		printf '%s\n' "[${_path}]" >> ${DCONFFILE}
		printf '%s=%s\n' "${_key}" "${_value}" >> ${DCONFFILE}
	else
		escaped_value="$(sed -e 's/\\/\\\\/g' <<< "$_value")"
		if grep -q "^\\s*${_key}" "${SETTINGSFILES[@]}"
		then
			sed -i "s/\\s*${_key}\\s*=\\s*.*/${_key}=${escaped_value}/g" "${SETTINGSFILES[@]}"
		else
			sed -i "\\|\\[${_path}\\]|a\\${_key}=${escaped_value}" "${SETTINGSFILES[@]}"
		fi
	fi

	dconf update
}

# Function to configure DConf locks for RHEL and Fedora systems.
#
# Example Call(s):
#
#     dconf_lock 'org/gnome/login-screen' 'banner-message-enable' 'local.d' 'banner'
#
function dconf_lock {
	local _key=$1 _setting=$2 _db=$3 _lockFile=$4

	# Check sanity of the input
	if [ $# -ne "4" ]
	then
		echo "Usage: dconf_lock 'dconf_path' 'dconf_setting' 'dconf_db' 'dconf_lockfile'"
		echo "Aborting."
		exit 1
	fi

	# Check for setting in any of the DConf db directories
	LOCKFILES=$(grep -r "^/${_key}/${_setting}$" "/etc/dconf/db/" | grep -v "distro\\|ibus" | cut -d":" -f1)
	LOCKSFOLDER="/etc/dconf/db/${_db}/locks"

	mkdir -p "${LOCKSFOLDER}"

	if [[ -z "${LOCKFILES}" ]]
	then
		echo "/${_key}/${_setting}" >> "/etc/dconf/db/${_db}/locks/${_lockFile}"
	fi

	dconf update
}
include_dconf_settings

expanded=$(echo "$login_banner_text" | sed 's/(\\\\\x27)\*/\\\x27/g;s/(\\\x27)\*//g;s/(\\\\\x27)/tamere/g;s/(\^\(.*\)\$|.*$/\1/g;s/\[\\s\\n\][+*]/ /g;s/\\//g;s/(n)\*/\\n/g;s/\x27/\\\x27/g;')

dconf_settings 'org/gnome/login-screen' 'banner-message-text' "'${expanded}'" 'gdm.d' '00-security-settings'
dconf_lock 'org/gnome/login-screen' 'banner-message-text' 'gdm.d' '00-security-settings-lock'
# END fix for 'dconf_gnome_login_banner_text'

###############################################################################
# The Red Hat Enterprise Linux operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
###############################################################################
(>&2 echo "Remediating rule 142/236: 'banner_etc_issue'")

login_banner_text="(^You[\s\n]+are[\s\n]+accessing[\s\n]+a[\s\n]+U.S.[\s\n]+Government[\s\n]+\(USG\)[\s\n]+Information[\s\n]+System[\s\n]+\(IS\)[\s\n]+that[\s\n]+is[\s\n]+provided[\s\n]+for[\s\n]+USG-authorized[\s\n]+use[\s\n]+only.[\s\n]*By[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+\(which[\s\n]+includes[\s\n]+any[\s\n]+device[\s\n]+attached[\s\n]+to[\s\n]+this[\s\n]+IS\),[\s\n]+you[\s\n]+consent[\s\n]+to[\s\n]+the[\s\n]+following[\s\n]+conditions\:(\\n)*(\n)*-[\s\n]*The[\s\n]+USG[\s\n]+routinely[\s\n]+intercepts[\s\n]+and[\s\n]+monitors[\s\n]+communications[\s\n]+on[\s\n]+this[\s\n]+IS[\s\n]+for[\s\n]+purposes[\s\n]+including,[\s\n]+but[\s\n]+not[\s\n]+limited[\s\n]+to,[\s\n]+penetration[\s\n]+testing,[\s\n]+COMSEC[\s\n]+monitoring,[\s\n]+network[\s\n]+operations[\s\n]+and[\s\n]+defense,[\s\n]+personnel[\s\n]+misconduct[\s\n]+\(PM\),[\s\n]+law[\s\n]+enforcement[\s\n]+\(LE\),[\s\n]+and[\s\n]+counterintelligence[\s\n]+\(CI\)[\s\n]+investigations.(\\n)*(\n)*-[\s\n]*At[\s\n]+any[\s\n]+time,[\s\n]+the[\s\n]+USG[\s\n]+may[\s\n]+inspect[\s\n]+and[\s\n]+seize[\s\n]+data[\s\n]+stored[\s\n]+on[\s\n]+this[\s\n]+IS.(\\n)*(\n)*-[\s\n]*Communications[\s\n]+using,[\s\n]+or[\s\n]+data[\s\n]+stored[\s\n]+on,[\s\n]+this[\s\n]+IS[\s\n]+are[\s\n]+not[\s\n]+private,[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+routine[\s\n]+monitoring,[\s\n]+interception,[\s\n]+and[\s\n]+search,[\s\n]+and[\s\n]+may[\s\n]+be[\s\n]+disclosed[\s\n]+or[\s\n]+used[\s\n]+for[\s\n]+any[\s\n]+USG-authorized[\s\n]+purpose.(\\n)*(\n)*-[\s\n]*This[\s\n]+IS[\s\n]+includes[\s\n]+security[\s\n]+measures[\s\n]+\(e.g.,[\s\n]+authentication[\s\n]+and[\s\n]+access[\s\n]+controls\)[\s\n]+to[\s\n]+protect[\s\n]+USG[\s\n]+interests--not[\s\n]+for[\s\n]+your[\s\n]+personal[\s\n]+benefit[\s\n]+or[\s\n]+privacy.(\\n)*(\n)*-[\s\n]*Notwithstanding[\s\n]+the[\s\n]+above,[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+does[\s\n]+not[\s\n]+constitute[\s\n]+consent[\s\n]+to[\s\n]+PM,[\s\n]+LE[\s\n]+or[\s\n]+CI[\s\n]+investigative[\s\n]+searching[\s\n]+or[\s\n]+monitoring[\s\n]+of[\s\n]+the[\s\n]+content[\s\n]+of[\s\n]+privileged[\s\n]+communications,[\s\n]+or[\s\n]+work[\s\n]+product,[\s\n]+related[\s\n]+to[\s\n]+personal[\s\n]+representation[\s\n]+or[\s\n]+services[\s\n]+by[\s\n]+attorneys,[\s\n]+psychotherapists,[\s\n]+or[\s\n]+clergy,[\s\n]+and[\s\n]+their[\s\n]+assistants.[\s\n]+Such[\s\n]+communications[\s\n]+and[\s\n]+work[\s\n]+product[\s\n]+are[\s\n]+private[\s\n]+and[\s\n]+confidential.[\s\n]+See[\s\n]+User[\s\n]+Agreement[\s\n]+for[\s\n]+details.$|^I\'ve[\s\n]+read[\s\n]+\&[\s\n]+consent[\s\n]+to[\s\n]+terms[\s\n]+in[\s\n]+IS[\s\n]+user[\s\n]+agreem\'t$)"

# There was a regular-expression matching various banners, needs to be expanded
expanded=$(echo "$login_banner_text" | sed 's/(\\\\\x27)\*/\\\x27/g;s/(\\\x27)\*//g;s/(\^\(.*\)\$|.*$/\1/g;s/\[\\s\\n\][+*]/ /g;s/\\//g;s/[^-]- /\n\n-/g;s/(n)\**//g')
formatted=$(echo "$expanded" | fold -sw 80)

cat <<EOF >/etc/issue
$formatted
EOF

printf "\n" >> /etc/issue


###############################################################################
# The Red Hat Enterprise Linux operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.
###############################################################################
(>&2 echo "Remediating rule 144/236: 'accounts_umask_etc_login_defs'")

var_accounts_user_umask="077"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/login.defs' '^UMASK' "$var_accounts_user_umask" 'CCE-80205-8' '%s %s'
# END fix for 'accounts_umask_etc_login_defs'


###############################################################################
# The Red Hat Enterprise Linux operating system must be configured so that all local interactive user accounts, upon creation, are assigned a home directory.
###############################################################################
(>&2 echo "Remediating rule 149/236: 'accounts_have_homedir_login_defs'")

if ! grep -q ^CREATE_HOME /etc/login.defs; then
	echo "CREATE_HOME     yes" >> /etc/login.defs
else
	sed -i "s/^\(CREATE_HOME\).*/\1 yes/g" /etc/login.defs
fi
# END fix for 'accounts_have_homedir_login_defs'

###############################################################################
# BEGIN fix (150 / 236) for 'accounts_user_dot_group_ownership'
###############################################################################
(>&2 echo "Remediating rule 150/236: 'accounts_user_dot_group_ownership'")
(>&2 echo "FIX FOR THIS RULE 'accounts_user_dot_group_ownership' Must Be Created Manually")
# END fix for 'accounts_user_dot_group_ownership'

###############################################################################
# Rule Title: The Red Hat Enterprise Linux operating system must be configured so that the delay between logon prompts following a failed console logon attempt is at least four seconds.
###############################################################################
(>&2 echo "Remediating rule 151/236: 'accounts_logon_fail_delay'")


# Set variables
var_accounts_fail_delay="4"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append '/etc/login.defs' '^FAIL_DELAY' "$var_accounts_fail_delay" 'CCE-80352-8' '%s %s'
# END fix for 'accounts_logon_fail_delay'


###############################################################################
# The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types. (V-72217)
###############################################################################
(>&2 echo "Remediating rule 155/236: 'accounts_max_concurrent_login_sessions'")

var_accounts_max_concurrent_login_sessions="10"

if grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.d/*.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.d/*.conf
elif grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.conf
else
	echo "*	hard	maxlogins	$var_accounts_max_concurrent_login_sessions" >> /etc/security/limits.conf
fi
# END fix for 'accounts_max_concurrent_login_sessions'


###############################################################################
# These audit records must also identify individual identities of group account users. (V-72079)
###############################################################################
(>&2 echo "Remediating rule 162/236: 'auditd_audispd_encrypt_sent_records'")



AUDISP_REMOTE_CONFIG="/etc/audisp/audisp-remote.conf"
option="^enable_krb5"
value="yes"
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append $AUDISP_REMOTE_CONFIG "$option" "$value" "CCE-80540-8"
# END fix for 'auditd_audispd_encrypt_sent_records'

###############################################################################
# The operating system must off-load audit records onto a different system or media from the system being audited. (V-72083)
###############################################################################
(>&2 echo "Remediating rule 163/236: 'auditd_audispd_configure_remote_server'")

var_audispd_remote_server="myhost.mydomain.com"


AUDITCONFIG=/etc/audisp/audisp-remote.conf
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append $AUDITCONFIG '^remote_server' "$var_audispd_remote_server" "CCE-80541-6"
# END fix for 'auditd_audispd_configure_remote_server'


###############################################################################
# The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) 
# when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity. (V-72089)
###############################################################################
(>&2 echo "Remediating rule 165/236: 'auditd_data_retention_space_left'")

var_auditd_space_left="100"

grep -q "^space_left[[:space:]]*=.*$" /etc/audit/auditd.conf && \
  sed -i "s/^space_left[[:space:]]*=.*$/space_left = $var_auditd_space_left/g" /etc/audit/auditd.conf || \
  echo "space_left = $var_auditd_space_left" >> /etc/audit/auditd.conf
# END fix for 'auditd_data_retention_space_left'

###############################################################################
# The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when 
# the threshold for the repository maximum audit record storage capacity is reached. (V-72093)
###############################################################################
(>&2 echo "Remediating rule 166/236: 'auditd_data_retention_action_mail_acct'")

var_auditd_action_mail_acct="root"

AUDITCONFIG=/etc/audit/auditd.conf
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached. (V-72093)
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append $AUDITCONFIG '^action_mail_acct' "$var_auditd_action_mail_acct" "CCE-27394-6"
# END fix for 'auditd_data_retention_action_mail_acct'

###############################################################################
# The audit system must take appropriate action when the audit storage volume is full. (V-72087)
###############################################################################
(>&2 echo "Remediating rule 168/236: 'auditd_data_retention_space_left_action'")

var_auditd_space_left_action="email"

#
# If space_left_action present in /etc/audit/auditd.conf, change value
# to var_auditd_space_left_action, else
# add "space_left_action = $var_auditd_space_left_action" to /etc/audit/auditd.conf
#

AUDITCONFIG=/etc/audit/auditd.conf
# Function to replace configuration setting in config file or add the configuration setting if
# it does not exist.
#
# Expects arguments:
#
# config_file:		Configuration file that will be modified
# key:			Configuration option to change
# value:		Value of the configuration option to change
# cce:			The CCE identifier or '@CCENUM@' if no CCE identifier exists
# format:		The printf-like format string that will be given stripped key and value as arguments,
#			so e.g. '%s=%s' will result in key=value subsitution (i.e. without spaces around =)
#
# Optional arugments:
#
# format:		Optional argument to specify the format of how key/value should be
# 			modified/appended in the configuration file. The default is key = value.
#
# Example Call(s):
#
#     With default format of 'key = value':
#     replace_or_append '/etc/sysctl.conf' '^kernel.randomize_va_space' '2' '@CCENUM@'
#
#     With custom key/value format:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' 'disabled' '@CCENUM@' '%s=%s'
#
#     With a variable:
#     replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state '@CCENUM@' '%s=%s'
#
function replace_or_append {
  local default_format='%s = %s' case_insensitive_mode=yes sed_case_insensitive_option='' grep_case_insensitive_option=''
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  if [ "$case_insensitive_mode" = yes ]; then
    sed_case_insensitive_option="i"
    grep_case_insensitive_option="-i"
  fi
  [ -n "$format" ] || format="$default_format"
  # Check sanity of the input
  [ $# -ge "3" ] || { echo "Usage: replace_or_append <config_file_location> <key_to_search> <new_value> [<CCE number or literal '@CCENUM@' if unknown>] [printf-like format, default is '$default_format']" >&2; exit 1; }

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  sed_command=('sed' '-i')
  if test -L "$config_file"; then
    sed_command+=('--follow-symlinks')
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if [ -n "$cce" ] && [ "$cce" != '@CCENUM@' ]; then
    cce="${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "$key")

  # shellcheck disable=SC2059
  printf -v formatted_output "$format" "$stripped_key" "$value"

  # If the key exists, change it. Otherwise, add it to the config_file.
  # We search for the key string followed by a word boundary (matched by \>),
  # so if we search for 'setting', 'setting2' won't match.
  if LC_ALL=C grep -q -m 1 $grep_case_insensitive_option -e "${key}\\>" "$config_file"; then
    "${sed_command[@]}" "s/${key}\\>.*/$formatted_output/g$sed_case_insensitive_option" "$config_file"
  else
    # \n is precaution for case where file ends without trailing newline
    printf '\n# Per %s: Set %s in %s\n' "$cce" "$formatted_output" "$config_file" >> "$config_file"
    printf '%s\n' "$formatted_output" >> "$config_file"
  fi
}
replace_or_append $AUDITCONFIG '^space_left_action' "$var_auditd_space_left_action" "CCE-27375-5"
# END fix for 'auditd_data_retention_space_left_action'

###############################################################################
# The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure. (V-72081)
###############################################################################
(>&2 echo "Remediating rule 169/236: 'audit_rules_kernel_module_loading_finit'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S finit_module \(-F key=\|-k \).*"
	GROUP="modules"
	FULL_RULE="-a always,exit -F arch=$ARCH -S finit_module -k modules"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_kernel_module_loading_finit'

###############################################################################
# The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure. (V-72081)
###############################################################################
(>&2 echo "Remediating rule 170/236: 'audit_rules_kernel_module_loading_init'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S init_module \(-F key=\|-k \).*"
	GROUP="modules"
	FULL_RULE="-a always,exit -F arch=$ARCH -S init_module -k modules"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_kernel_module_loading_init'

###############################################################################
# The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure. (V-72081)
###############################################################################
(>&2 echo "Remediating rule 171/236: 'audit_rules_kernel_module_loading_delete'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit and 64-bit kernel syscall numbers not always line up =>
#       it's required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule.
#       (See `man 7 audit.rules` for details )
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S delete_module \(-F key=\|-k \).*"
	GROUP="modules"
	FULL_RULE="-a always,exit -F arch=$ARCH -S delete_module -k modules"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_kernel_module_loading_delete'

###############################################################################
# The system must display the date and time of the last successful account logon upon logon. (V-72275)
###############################################################################
(>&2 echo "Remediating rule 172/236: 'audit_rules_login_events_lastlog'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/var/log/lastlog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/lastlog" "wa" "logins"
# END fix for 'audit_rules_login_events_lastlog'

###############################################################################
# BEGIN fix (173 / 236) If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. (V-71945)
###############################################################################
(>&2 echo "Remediating rule 173/236: 'audit_rules_login_events_faillock'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/var/run/faillock" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/run/faillock" "wa" "logins"
# END fix for 'audit_rules_login_events_faillock'

###############################################################################
# BEGIN fix (174 / 236) for 'audit_rules_login_events_tallylog'
###############################################################################
(>&2 echo "Remediating rule 174/236: 'audit_rules_login_events_tallylog'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/var/log/tallylog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/tallylog" "wa" "logins"
# END fix for 'audit_rules_login_events_tallylog'

###############################################################################
# All uses of the fchown command must be audited. (V-72099)
###############################################################################
(>&2 echo "Remediating rule 175/236: 'audit_rules_dac_modification_fchown'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S fchown.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S fchown -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_fchown'

###############################################################################
# All uses of the setxattr command must be audited. (V-72111)
###############################################################################
(>&2 echo "Remediating rule 176/236: 'audit_rules_dac_modification_setxattr'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S setxattr.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S setxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_setxattr'

###############################################################################
# All uses of the chown command must be audited. (V-72097)
###############################################################################
(>&2 echo "Remediating rule 177/236: 'audit_rules_dac_modification_chown'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S chown.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chown -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_chown'

###############################################################################
# All uses of the fchownat command must be audited. (V-72103)
###############################################################################
(>&2 echo "Remediating rule 178/236: 'audit_rules_dac_modification_fchownat'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S fchownat.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_fchownat'

###############################################################################
# All uses of the chmod command must be audited. (V-72105)
###############################################################################
(>&2 echo "Remediating rule 179/236: 'audit_rules_dac_modification_chmod'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S chmod.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_chmod'


###############################################################################
# All uses of the removexattr command must be audited. (V-72117)
###############################################################################
(>&2 echo "Remediating rule 181/236: 'audit_rules_dac_modification_removexattr'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S removexattr.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S removexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_removexattr'

###############################################################################
# All uses of the fremovexattr command must be audited. (V-72119)
###############################################################################
(>&2 echo "Remediating rule 182/236: 'audit_rules_dac_modification_fremovexattr'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S fremovexattr.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_fremovexattr'

###############################################################################
# All uses of the lsetxattr command must be audited. (V-72115)
###############################################################################
(>&2 echo "Remediating rule 183/236: 'audit_rules_dac_modification_lsetxattr'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S lsetxattr.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S lsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_lsetxattr'

###############################################################################
# All uses of the fchmod command must be audited. (V-72107)
###############################################################################
(>&2 echo "Remediating rule 184/236: 'audit_rules_dac_modification_fchmod'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S fchmod.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S fchmod -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_fchmod'

###############################################################################
# All uses of the lchown command must be audited. (V-72101)
###############################################################################
(>&2 echo "Remediating rule 185/236: 'audit_rules_dac_modification_lchown'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S lchown.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S lchown -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_lchown'

###############################################################################
# All uses of the fsetxattr command must be audited. (V-72113)
###############################################################################
(>&2 echo "Remediating rule 186/236: 'audit_rules_dac_modification_fsetxattr'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S fsetxattr.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S fsetxattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_fsetxattr'

###############################################################################
# All uses of the lremovexattr command must be audited. (V-72121)
###############################################################################
(>&2 echo "Remediating rule 187/236: 'audit_rules_dac_modification_lremovexattr'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S lremovexattr.*"
	GROUP="perm_mod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S lremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_dac_modification_lremovexattr'

###############################################################################
# All uses of the truncate command must be audited. (V-72131)
###############################################################################
(>&2 echo "Remediating rule 188/236: 'audit_rules_unsuccessful_file_modification_truncate'")
function create_audit_remediation_unsuccessful_file_modification_detailed {
	mkdir -p "$(dirname "$1")"
	# The - option to mark a here document limit string (<<-EOF) suppresses leading tabs (but not spaces) in the output.
	cat <<-EOF > "$1"
		## This content is a section of an Audit config snapshot recommended for RHEL8 sytems that target OSPP compliance.
		## The following content has been retreived on 2019-03-11 from: https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules

		## The purpose of these rules is to meet the requirements for Operating
		## System Protection Profile (OSPP)v4.2. These rules depends on having
		## 10-base-config.rules, 11-loginuid.rules, and 43-module-load.rules installed.

		## Unsuccessful file creation (open with O_CREAT)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create

		## Unsuccessful file modifications (open for write or truncate)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification

		## Unsuccessful file access (any other opens) This has to go last.
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
	EOF
}
create_audit_remediation_unsuccessful_file_modification_detailed /etc/audit/rules.d/30-ospp-v42-remediation.rules
# END fix for 'audit_rules_unsuccessful_file_modification_truncate'

###############################################################################
# All uses of the creat command must be audited. (V-72123)
###############################################################################
(>&2 echo "Remediating rule 189/236: 'audit_rules_unsuccessful_file_modification_creat'")
function create_audit_remediation_unsuccessful_file_modification_detailed {
	mkdir -p "$(dirname "$1")"
	# The - option to mark a here document limit string (<<-EOF) suppresses leading tabs (but not spaces) in the output.
	cat <<-EOF > "$1"
		## This content is a section of an Audit config snapshot recommended for RHEL8 sytems that target OSPP compliance.
		## The following content has been retreived on 2019-03-11 from: https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules

		## The purpose of these rules is to meet the requirements for Operating
		## System Protection Profile (OSPP)v4.2. These rules depends on having
		## 10-base-config.rules, 11-loginuid.rules, and 43-module-load.rules installed.

		## Unsuccessful file creation (open with O_CREAT)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create

		## Unsuccessful file modifications (open for write or truncate)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification

		## Unsuccessful file access (any other opens) This has to go last.
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
	EOF
}
create_audit_remediation_unsuccessful_file_modification_detailed /etc/audit/rules.d/30-ospp-v42-remediation.rules
# END fix for 'audit_rules_unsuccessful_file_modification_creat'

###############################################################################
# All uses of the open command must be audited. (V-72125)
###############################################################################
(>&2 echo "Remediating rule 190/236: 'audit_rules_unsuccessful_file_modification_open'")
function create_audit_remediation_unsuccessful_file_modification_detailed {
	mkdir -p "$(dirname "$1")"
	# The - option to mark a here document limit string (<<-EOF) suppresses leading tabs (but not spaces) in the output.
	cat <<-EOF > "$1"
		## This content is a section of an Audit config snapshot recommended for RHEL8 sytems that target OSPP compliance.
		## The following content has been retreived on 2019-03-11 from: https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules

		## The purpose of these rules is to meet the requirements for Operating
		## System Protection Profile (OSPP)v4.2. These rules depends on having
		## 10-base-config.rules, 11-loginuid.rules, and 43-module-load.rules installed.

		## Unsuccessful file creation (open with O_CREAT)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create

		## Unsuccessful file modifications (open for write or truncate)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification

		## Unsuccessful file access (any other opens) This has to go last.
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
	EOF
}
create_audit_remediation_unsuccessful_file_modification_detailed /etc/audit/rules.d/30-ospp-v42-remediation.rules
# END fix for 'audit_rules_unsuccessful_file_modification_open'

###############################################################################
# All uses of the open_by_handle_at command must be audited. (V-72129)
###############################################################################
(>&2 echo "Remediating rule 191/236: 'audit_rules_unsuccessful_file_modification_open_by_handle_at'")
function create_audit_remediation_unsuccessful_file_modification_detailed {
	mkdir -p "$(dirname "$1")"
	# The - option to mark a here document limit string (<<-EOF) suppresses leading tabs (but not spaces) in the output.
	cat <<-EOF > "$1"
		## This content is a section of an Audit config snapshot recommended for RHEL8 sytems that target OSPP compliance.
		## The following content has been retreived on 2019-03-11 from: https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules

		## The purpose of these rules is to meet the requirements for Operating
		## System Protection Profile (OSPP)v4.2. These rules depends on having
		## 10-base-config.rules, 11-loginuid.rules, and 43-module-load.rules installed.

		## Unsuccessful file creation (open with O_CREAT)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create

		## Unsuccessful file modifications (open for write or truncate)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification

		## Unsuccessful file access (any other opens) This has to go last.
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
	EOF
}
create_audit_remediation_unsuccessful_file_modification_detailed /etc/audit/rules.d/30-ospp-v42-remediation.rules
# END fix for 'audit_rules_unsuccessful_file_modification_open_by_handle_at'

###############################################################################
# All uses of the ftruncate command must be audited. (V-72133)
###############################################################################
(>&2 echo "Remediating rule 192/236: 'audit_rules_unsuccessful_file_modification_ftruncate'")
function create_audit_remediation_unsuccessful_file_modification_detailed {
	mkdir -p "$(dirname "$1")"
	# The - option to mark a here document limit string (<<-EOF) suppresses leading tabs (but not spaces) in the output.
	cat <<-EOF > "$1"
		## This content is a section of an Audit config snapshot recommended for RHEL8 sytems that target OSPP compliance.
		## The following content has been retreived on 2019-03-11 from: https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules

		## The purpose of these rules is to meet the requirements for Operating
		## System Protection Profile (OSPP)v4.2. These rules depends on having
		## 10-base-config.rules, 11-loginuid.rules, and 43-module-load.rules installed.

		## Unsuccessful file creation (open with O_CREAT)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create

		## Unsuccessful file modifications (open for write or truncate)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification

		## Unsuccessful file access (any other opens) This has to go last.
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
	EOF
}
create_audit_remediation_unsuccessful_file_modification_detailed /etc/audit/rules.d/30-ospp-v42-remediation.rules
# END fix for 'audit_rules_unsuccessful_file_modification_ftruncate'

###############################################################################
# All uses of the openat command must be audited. (V-72127)
###############################################################################
(>&2 echo "Remediating rule 193/236: 'audit_rules_unsuccessful_file_modification_openat'")
function create_audit_remediation_unsuccessful_file_modification_detailed {
	mkdir -p "$(dirname "$1")"
	# The - option to mark a here document limit string (<<-EOF) suppresses leading tabs (but not spaces) in the output.
	cat <<-EOF > "$1"
		## This content is a section of an Audit config snapshot recommended for RHEL8 sytems that target OSPP compliance.
		## The following content has been retreived on 2019-03-11 from: https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules

		## The purpose of these rules is to meet the requirements for Operating
		## System Protection Profile (OSPP)v4.2. These rules depends on having
		## 10-base-config.rules, 11-loginuid.rules, and 43-module-load.rules installed.

		## Unsuccessful file creation (open with O_CREAT)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S open -F a1&0100 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create
		-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-create

		## Unsuccessful file modifications (open for write or truncate)
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S openat,open_by_handle_at -F a2&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S open -F a1&01003 -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b32 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification
		-a always,exit -F arch=b64 -S truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-modification

		## Unsuccessful file access (any other opens) This has to go last.
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
		-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=unsuccesful-access
	EOF
}
create_audit_remediation_unsuccessful_file_modification_detailed /etc/audit/rules.d/30-ospp-v42-remediation.rules
# END fix for 'audit_rules_unsuccessful_file_modification_openat'

###############################################################################
# All uses of the setfiles command must be audited. (V-72141)
###############################################################################
(>&2 echo "Remediating rule 194/236: 'audit_rules_execution_setfiles'")


PATTERN="-a always,exit -F path=/usr/sbin/setfiles\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_execution_setfiles'

###############################################################################
# All uses of the setsebool command must be audited. (V-72137)
###############################################################################
(>&2 echo "Remediating rule 195/236: 'audit_rules_execution_setsebool'")


PATTERN="-a always,exit -F path=/usr/sbin/setsebool\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_execution_setsebool'

###############################################################################
# The Red Hat Enterprise Linux operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
###############################################################################
(>&2 echo "Remediating rule 196/236: 'audit_rules_execution_semanage'")


PATTERN="-a always,exit -F path=/usr/sbin/semanage\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_execution_semanage'

###############################################################################
# All uses of the chcon command must be audited. (V-72139)
###############################################################################
(>&2 echo "Remediating rule 197/236: 'audit_rules_execution_chcon'")


PATTERN="-a always,exit -F path=/usr/bin/chcon\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_execution_chcon'

###############################################################################
# All uses of the rmdir command must be audited. (V-72203)
###############################################################################
(>&2 echo "Remediating rule 198/236: 'audit_rules_file_deletion_events_rmdir'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S rmdir.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rmdir -F auid>=1000 -F auid!=unset -F key=delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_file_deletion_events_rmdir'

###############################################################################
# All uses of the unlink command must be audited. (V-72205)
###############################################################################
(>&2 echo "Remediating rule 199/236: 'audit_rules_file_deletion_events_unlinkat'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S unlinkat.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S unlinkat -F auid>=1000 -F auid!=unset -F key=delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_file_deletion_events_unlinkat'

###############################################################################
# All uses of the rename command must be audited. (V-72199)
###############################################################################
(>&2 echo "Remediating rule 200/236: 'audit_rules_file_deletion_events_rename'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S rename.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rename -F auid>=1000 -F auid!=unset -F key=delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_file_deletion_events_rename'

###############################################################################
# All uses of the renameat command must be audited. (V-72201)
###############################################################################
(>&2 echo "Remediating rule 201/236: 'audit_rules_file_deletion_events_renameat'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S renameat.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S renameat -F auid>=1000 -F auid!=unset -F key=delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_file_deletion_events_renameat'

###############################################################################
# All uses of the unlink command must be audited. (V-72205)
###############################################################################
(>&2 echo "Remediating rule 202/236: 'audit_rules_file_deletion_events_unlink'")


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S unlink.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S unlink -F auid>=1000 -F auid!=unset -F key=delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done
# END fix for 'audit_rules_file_deletion_events_unlink'

###############################################################################
# All uses of the gpasswd command must be audited. (V-72153)
###############################################################################
(>&2 echo "Remediating rule 203/236: 'audit_rules_privileged_commands_gpasswd'")


PATTERN="-a always,exit -F path=/usr/bin/gpasswd\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_gpasswd'

###############################################################################
# All uses of the gpasswd command must be audited. (V-72153)
###############################################################################
(>&2 echo "Remediating rule 204/236: 'audit_rules_privileged_commands_passwd'")


PATTERN="-a always,exit -F path=/usr/bin/passwd\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_passwd'

###############################################################################
# All uses of the sudo command must be audited. (V-72161)
###############################################################################
(>&2 echo "Remediating rule 205/236: 'audit_rules_privileged_commands_sudo'")


PATTERN="-a always,exit -F path=/usr/bin/sudo\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_sudo'

###############################################################################
# All uses of the postdrop command must be audited. (V-72175)
###############################################################################
(>&2 echo "Remediating rule 206/236: 'audit_rules_privileged_commands_postdrop'")


PATTERN="-a always,exit -F path=/usr/sbin/postdrop\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_postdrop'

###############################################################################
# All uses of the chsh command must be audited. (V-72167)
###############################################################################
(>&2 echo "Remediating rule 207/236: 'audit_rules_privileged_commands_chsh'")


PATTERN="-a always,exit -F path=/usr/bin/chsh\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_chsh'

###############################################################################
# All uses of the postqueue command must be audited. (V-72177)BEGIN fix (208 / 236) for 'audit_rules_privileged_commands_postqueue'
###############################################################################
(>&2 echo "Remediating rule 208/236: 'audit_rules_privileged_commands_postqueue'")


PATTERN="-a always,exit -F path=/usr/sbin/postqueue\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_postqueue'

###############################################################################
# The Red Hat Enterprise Linux operating system must be configured so that passwords are restricted to a 24 hours/1 day minimum lifetime.
###############################################################################
(>&2 echo "Remediating rule 209/236: 'audit_rules_privileged_commands_chage'")


PATTERN="-a always,exit -F path=/usr/bin/chage\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_chage'

###############################################################################
# All uses of the userhelper command must be audited. (V-72157)
###############################################################################
(>&2 echo "Remediating rule 210/236: 'audit_rules_privileged_commands_userhelper'")


PATTERN="-a always,exit -F path=/usr/sbin/userhelper\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_userhelper'

###############################################################################
# All uses of the pam_timestamp_check command must be audited. (V-72185)
###############################################################################
(>&2 echo "Remediating rule 211/236: 'audit_rules_privileged_commands_pam_timestamp_check'")


PATTERN="-a always,exit -F path=/usr/sbin/pam_timestamp_check\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_pam_timestamp_check'

###############################################################################
# All uses of the crontab command must be audited. (V-72183)
###############################################################################
(>&2 echo "Remediating rule 212/236: 'audit_rules_privileged_commands_crontab'")


PATTERN="-a always,exit -F path=/usr/bin/crontab\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_crontab'

###############################################################################
# All uses of the umount command must be audited. (V-72173)
###############################################################################
(>&2 echo "Remediating rule 213/236: 'audit_rules_privileged_commands_umount'")


PATTERN="-a always,exit -F path=/usr/bin/umount\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_umount'

###############################################################################
# All uses of the unix_chkpwd command must be audited. (V-72151)
###############################################################################
(>&2 echo "Remediating rule 214/236: 'audit_rules_privileged_commands_unix_chkpwd'")


PATTERN="-a always,exit -F path=/usr/sbin/unix_chkpwd\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_unix_chkpwd'

###############################################################################
# All uses of the ssh-keysign command must be audited. (V-72179)
###############################################################################
(>&2 echo "Remediating rule 215/236: 'audit_rules_privileged_commands_ssh_keysign'")


PATTERN="-a always,exit -F path=/usr/libexec/openssh/ssh-keysign\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_ssh_keysign'

###############################################################################
# All uses of the sudoedit command must be audited. (V-72169)
###############################################################################
(>&2 echo "Remediating rule 216/236: 'audit_rules_privileged_commands_sudoedit'")


PATTERN="-a always,exit -F path=/usr/bin/sudoedit\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_sudoedit'

###############################################################################
# All uses of the mount command must be audited. (V-72171)
###############################################################################
(>&2 echo "Remediating rule 217/236: 'audit_rules_privileged_commands'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to perform remediation for 'audit_rules_privileged_commands' rule
#
# Expects two arguments:
#
# audit_tool		tool used to load audit rules
# 			One of 'auditctl' or 'augenrules'
#
# min_auid		Minimum original ID the user logged in with
# 			'500' for RHEL-6 and before, '1000' for RHEL-7 and after.
#
# Example Call(s):
#
#      perform_audit_rules_privileged_commands_remediation "auditctl" "500"
#      perform_audit_rules_privileged_commands_remediation "augenrules"	"1000"
#
function perform_audit_rules_privileged_commands_remediation {
#
# Load function arguments into local variables
local tool="$1"
local min_auid="$2"

# Check sanity of the input
if [ $# -ne "2" ]
then
	echo "Usage: perform_audit_rules_privileged_commands_remediation 'auditctl | augenrules' '500 | 1000'"
	echo "Aborting."
	exit 1
fi

declare -a files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then:
# * add '/etc/audit/audit.rules'to the list of files to be inspected,
# * specify '/etc/audit/audit.rules' as the output audit file, where
#   missing rules should be inserted
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect=("/etc/audit/audit.rules")
	output_audit_file="/etc/audit/audit.rules"
#
# If the audit tool is 'augenrules', then:
# * add '/etc/audit/rules.d/*.rules' to the list of files to be inspected
#   (split by newline),
# * specify /etc/audit/rules.d/privileged.rules' as the output file, where
#   missing rules should be inserted
elif [ "$tool" == 'augenrules' ]
then
	readarray -t files_to_inspect < <(find /etc/audit/rules.d -maxdepth 1 -type f -name '*.rules' -print)
	output_audit_file="/etc/audit/rules.d/privileged.rules"
fi

# Obtain the list of SUID/SGID binaries on the particular system (split by newline)
# into privileged_binaries array
readarray -t privileged_binaries < <(find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null)

# Keep list of SUID/SGID binaries that have been already handled within some previous iteration
declare -a sbinaries_to_skip=()

# For each found sbinary in privileged_binaries list
for sbinary in "${privileged_binaries[@]}"
do

	# Check if this sbinary wasn't already handled in some of the previous sbinary iterations
	# Return match only if whole sbinary definition matched (not in the case just prefix matched!!!)
	if [[ $(sed -ne "\|${sbinary}|p" <<< "${sbinaries_to_skip[*]}") ]]
	then
		# If so, don't process it second time & go to process next sbinary
		continue
	fi

	# Reset the counter of inspected files when starting to check
	# presence of existing audit rule for new sbinary
	local count_of_inspected_files=0

	# Define expected rule form for this binary
	expected_rule="-a always,exit -F path=${sbinary} -F perm=x -F auid>=${min_auid} -F auid!=unset -k privileged"

	# If list of audit rules files to be inspected is empty, just add new rule and move on to next binary
	if [[ ${#files_to_inspect[@]} -eq 0 ]]; then
		echo "$expected_rule" >> "$output_audit_file"
		continue
	fi

	# Replace possible slash '/' character in sbinary definition so we could use it in sed expressions below
	sbinary_esc=${sbinary//$'/'/$'\/'}

	# For each audit rules file from the list of files to be inspected
	for afile in "${files_to_inspect[@]}"
	do

		# Search current audit rules file's content for match. Match criteria:
		# * existing rule is for the same SUID/SGID binary we are currently processing (but
		#   can contain multiple -F path= elements covering multiple SUID/SGID binaries)
		# * existing rule contains all arguments from expected rule form (though can contain
		#   them in arbitrary order)
	
		base_search=$(sed -e '/-a always,exit/!d' -e '/-F path='"${sbinary_esc}"'/!d'		\
				-e '/-F path=[^[:space:]]\+/!d'   -e '/-F perm=.*/!d'						\
				-e '/-F auid>='"${min_auid}"'/!d' -e '/-F auid!=\(4294967295\|unset\)/!d'	\
				-e '/-k \|-F key=/!d' "$afile")

		# Increase the count of inspected files for this sbinary
		count_of_inspected_files=$((count_of_inspected_files + 1))

		# Require execute access type to be set for existing audit rule
		exec_access='x'

		# Search current audit rules file's content for presence of rule pattern for this sbinary
		if [[ $base_search ]]
		then

			# Current audit rules file already contains rule for this binary =>
			# Store the exact form of found rule for this binary for further processing
			concrete_rule=$base_search

			# Select all other SUID/SGID binaries possibly also present in the found rule

			readarray -t handled_sbinaries < <(grep -o -e "-F path=[^[:space:]]\+" <<< "$concrete_rule")
			handled_sbinaries=("${handled_sbinaries[@]//-F path=/}")

			# Merge the list of such SUID/SGID binaries found in this iteration with global list ignoring duplicates
			readarray -t sbinaries_to_skip < <(for i in "${sbinaries_to_skip[@]}" "${handled_sbinaries[@]}"; do echo "$i"; done | sort -du)

			# Separate concrete_rule into three sections using hash '#'
			# sign as a delimiter around rule's permission section borders
			concrete_rule="$(echo "$concrete_rule" | sed -n "s/\(.*\)\+\(-F perm=[rwax]\+\)\+/\1#\2#/p")"

			# Split concrete_rule into head, perm, and tail sections using hash '#' delimiter

			rule_head=$(cut -d '#' -f 1 <<< "$concrete_rule")
			rule_perm=$(cut -d '#' -f 2 <<< "$concrete_rule")
			rule_tail=$(cut -d '#' -f 3 <<< "$concrete_rule")

			# Extract already present exact access type [r|w|x|a] from rule's permission section
			access_type=${rule_perm//-F perm=/}

			# Verify current permission access type(s) for rule contain 'x' (execute) permission
			if ! grep -q "$exec_access" <<< "$access_type"
			then

				# If not, append the 'x' (execute) permission to the existing access type bits
				access_type="$access_type$exec_access"
				# Reconstruct the permissions section for the rule
				new_rule_perm="-F perm=$access_type"
				# Update existing rule in current audit rules file with the new permission section
				sed -i "s#${rule_head}\(.*\)${rule_tail}#${rule_head}${new_rule_perm}${rule_tail}#" "$afile"

			fi

		# If the required audit rule for particular sbinary wasn't found yet, insert it under following conditions:
		#
		# * in the "auditctl" mode of operation insert particular rule each time
		#   (because in this mode there's only one file -- /etc/audit/audit.rules to be inspected for presence of this rule),
		#
		# * in the "augenrules" mode of operation insert particular rule only once and only in case we have already
		#   searched all of the files from /etc/audit/rules.d/*.rules location (since that audit rule can be defined
		#   in any of those files and if not, we want it to be inserted only once into /etc/audit/rules.d/privileged.rules file)
		#
		elif [ "$tool" == "auditctl" ] || [[ "$tool" == "augenrules" && $count_of_inspected_files -eq "${#files_to_inspect[@]}" ]]
		then

			# Check if this sbinary wasn't already handled in some of the previous afile iterations
			# Return match only if whole sbinary definition matched (not in the case just prefix matched!!!)
			if [[ ! $(sed -ne "\|${sbinary}|p" <<< "${sbinaries_to_skip[*]}") ]]
			then
				# Current audit rules file's content doesn't contain expected rule for this
				# SUID/SGID binary yet => append it
				echo "$expected_rule" >> "$output_audit_file"
			fi

			continue
		fi

	done

done
}
perform_audit_rules_privileged_commands_remediation "auditctl" "1000"
perform_audit_rules_privileged_commands_remediation "augenrules" "1000"
# END fix for 'audit_rules_privileged_commands'

###############################################################################
# All uses of the su command must be audited. (V-72159)
###############################################################################
(>&2 echo "Remediating rule 218/236: 'audit_rules_privileged_commands_su'")


PATTERN="-a always,exit -F path=/usr/bin/su\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_su'

###############################################################################
# All uses of the newgrp command must be audited. (V-72165)
###############################################################################
(>&2 echo "Remediating rule 219/236: 'audit_rules_privileged_commands_newgrp'")


PATTERN="-a always,exit -F path=/usr/bin/newgrp\\s\\+.*"
GROUP="privileged"
# Although the fix doesn't use ARCH, we reset it because it could have been set by some other remediation
ARCH=""
FULL_RULE="-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -F key=privileged"
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix syscall audit rule for given system call. It is
# based on example audit syscall rule definitions as outlined in
# /usr/share/doc/audit-2.3.7/stig.rules file provided with the audit
# package. It will combine multiple system calls belonging to the same
# syscall group into one audit rule (rather than to create audit rule per
# different system call) to avoid audit infrastructure performance penalty
# in the case of 'one-audit-rule-definition-per-one-system-call'. See:
#
#   https://www.redhat.com/archives/linux-audit/2014-November/msg00009.html
#
# for further details.
#
# Expects five arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules
# * audit rules' pattern		audit rule skeleton for same syscall
# * syscall group			greatest common string this rule shares
# 					with other rules from the same group
# * architecture			architecture this rule is intended for
# * full form of new rule to add	expected full form of audit rule as to be
# 					added into audit.rules file
#
# Note: The 2-th up to 4-th arguments are used to determine how many existing
# audit rules will be inspected for resemblance with the new audit rule
# (5-th argument) the function is going to add. The rule's similarity check
# is performed to optimize audit.rules definition (merge syscalls of the same
# group into one rule) to avoid the "single-syscall-per-audit-rule" performance
# penalty.
#
# Example call:
#
#	See e.g. 'audit_rules_file_deletion_events.sh' remediation script
#
function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
	echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

retval=0

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	return 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
	# Extract audit $key from audit rule so we can use it later
	key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)' '|' "$full_rule" : '.*-F[[:space:]]key=\([^[:space:]]\+\)')
	readarray -t matches < <(sed -s -n -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules)
	if [ $? -ne 0 ]
	then
		retval=1
	fi
	for match in "${matches[@]}"
	do
		files_to_inspect+=("${match}")
	done
	# Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
	if [ ${#files_to_inspect[@]} -eq "0" ]
	then
		file_to_inspect="/etc/audit/rules.d/$key.rules"
		files_to_inspect=("$file_to_inspect")
		if [ ! -e "$file_to_inspect" ]
		then
			touch "$file_to_inspect"
			chmod 0640 "$file_to_inspect"
		fi
	fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do
	# Filter existing $audit_file rules' definitions to select those that:
	# * follow the rule pattern, and
	# * meet the hardware architecture requirement, and
	# * are current syscall group specific
	readarray -t existing_rules < <(sed -e "\;${pattern};!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file")
	if [ $? -ne 0 ]
	then
		retval=1
	fi

	# Process rules found case-by-case
	for rule in "${existing_rules[@]}"
	do
		# Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
		if [ "${rule}" != "${full_rule}" ]
		then
			# If so, isolate just '(-S \w)+' substring of that rule
			rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
			# Check if list of '-S syscall' arguments of that rule is subset
			# of '-S syscall' list of expected $full_rule
			if grep -q -- "$rule_syscalls" <<< "$full_rule"
			then
				# Rule is covered (i.e. the list of -S syscalls for this rule is
				# subset of -S syscalls of $full_rule => existing rule can be deleted
				# Thus delete the rule from audit.rules & our array
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi
				existing_rules=("${existing_rules[@]//$rule/}")
			else
				# Rule isn't covered by $full_rule - it besides -S syscall arguments
				# for this group contains also -S syscall arguments for other syscall
				# group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
				# since 'lchown' & 'fchownat' share 'chown' substring
				# Therefore:
				# * 1) delete the original rule from audit.rules
				# (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
				# * 2) delete the -S syscall arguments for this syscall group, but
				# keep those not belonging to this syscall group
				# (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
				# * 3) append the modified (filtered) rule again into audit.rules
				# if the same rule not already present
				#
				# 1) Delete the original rule
				sed -i -e "\;${rule};d" "$audit_file"
				if [ $? -ne 0 ]
				then
					retval=1
				fi

				# 2) Delete syscalls for this group, but keep those from other groups
				# Convert current rule syscall's string into array splitting by '-S' delimiter
				IFS_BKP="$IFS"
				IFS=$'-S'
				read -a rule_syscalls_as_array <<< "$rule_syscalls"
				# Reset IFS back to default
				IFS="$IFS_BKP"
				# Splitting by "-S" can't be replaced by the readarray functionality easily

				# Declare new empty string to hold '-S syscall' arguments from other groups
				new_syscalls_for_rule=''
				# Walk through existing '-S syscall' arguments
				for syscall_arg in "${rule_syscalls_as_array[@]}"
				do
					# Skip empty $syscall_arg values
					if [ "$syscall_arg" == '' ]
					then
						continue
					fi
					# If the '-S syscall' doesn't belong to current group add it to the new list
					# (together with adding '-S' delimiter back for each of such item found)
					if grep -q -v -- "$group" <<< "$syscall_arg"
					then
						new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
					fi
				done
				# Replace original '-S syscall' list with the new one for this rule
				updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
				# Squeeze repeated whitespace characters in rule definition (if any) into one
				updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
				# 3) Append the modified / filtered rule again into audit.rules
				#    (but only in case it's not present yet to prevent duplicate definitions)
				if ! grep -q -- "$updated_rule" "$audit_file"
				then
					echo "$updated_rule" >> "$audit_file"
				fi
			fi
		else
			# $audit_file already contains the expected rule form for this
			# architecture & key => don't insert it second time
			append_expected_rule=1
		fi
	done

	# We deleted all rules that were subset of the expected one for this arch & key.
	# Also isolated rules containing system calls not from this system calls group.
	# Now append the expected rule if it's not present in $audit_file yet
	if [[ ${append_expected_rule} -eq "0" ]]
	then
		echo "$full_rule" >> "$audit_file"
	fi
done

return $retval

}
fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
# END fix for 'audit_rules_privileged_commands_newgrp'

###############################################################################
# The Red Hat Enterprise Linux operating system must be configured so that users must provide a password for privilege escalation.
###############################################################################
(>&2 echo "Remediating rule 220/236: 'audit_rules_sysadmin_actions'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/sudoers" "wa" "actions"
fix_audit_watch_rule "augenrules" "/etc/sudoers" "wa" "actions"
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/sudoers.d" "wa" "actions"
fix_audit_watch_rule "augenrules" "/etc/sudoers.d" "wa" "actions"
# END fix for 'audit_rules_sysadmin_actions'



###############################################################################
# The shadow file must be configured to store only encrypted representations of passwords. (V-71921)
###############################################################################
(>&2 echo "Remediating rule 222/236: 'audit_rules_usergroup_modification_shadow'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/shadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/shadow" "wa" "audit_rules_usergroup_modification"
# END fix for 'audit_rules_usergroup_modification_shadow'

###############################################################################
# The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd. (V-73173)
###############################################################################
(>&2 echo "Remediating rule 223/236: 'audit_rules_usergroup_modification_opasswd'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"
# END fix for 'audit_rules_usergroup_modification_opasswd'

###############################################################################
# BEGIN fix (224 / 236) for 'audit_rules_system_shutdown'
###############################################################################
(>&2 echo "Remediating rule 224/236: 'audit_rules_system_shutdown'")

# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
#
# files to check if '-f .*' setting is present in that '*.rules' file already.
# If found, delete such occurrence since auditctl(8) manual page instructs the
# '-f 2' rule should be placed as the last rule in the configuration
find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name '*.rules' -exec sed -i '/-e[[:space:]]\+.*/d' {} ';'

# Append '-f 2' requirement at the end of both:
# * /etc/audit/audit.rules file 		(for auditctl case)
# * /etc/audit/rules.d/immutable.rules		(for augenrules case)

for AUDIT_FILE in "/etc/audit/audit.rules" "/etc/audit/rules.d/immutable.rules"
do
	echo '' >> $AUDIT_FILE
	echo '# Set the audit.rules configuration to halt system upon audit failure per security requirements' >> $AUDIT_FILE
	echo '-f 2' >> $AUDIT_FILE
done
# END fix for 'audit_rules_system_shutdown'

###############################################################################
# The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow. (V-73167)
###############################################################################
(>&2 echo "Remediating rule 225/236: 'audit_rules_usergroup_modification_gshadow'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"
# END fix for 'audit_rules_usergroup_modification_gshadow'

###############################################################################
# The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd. (V-73173)
###############################################################################
(>&2 echo "Remediating rule 226/236: 'audit_rules_usergroup_modification_passwd'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/passwd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/passwd" "wa" "audit_rules_usergroup_modification"
# END fix for 'audit_rules_usergroup_modification_passwd'

###############################################################################
# The Red Hat Enterprise Linux operating system must be configured so that all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file.
###############################################################################
(>&2 echo "Remediating rule 227/236: 'audit_rules_usergroup_modification_group'")


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
# Function to fix audit file system object watch rule for given path:
# * if rule exists, also verifies the -w bits match the requirements
# * if rule doesn't exist yet, appends expected rule form to $files_to_inspect
#   audit rules file, depending on the tool which was used to load audit rules
#
# Expects four arguments (each of them is required) in the form of:
# * audit tool				tool used to load audit rules,
# 					either 'auditctl', or 'augenrules'
# * path                        	value of -w audit rule's argument
# * required access bits        	value of -p audit rule's argument
# * key                         	value of -k audit rule's argument
#
# Example call:
#
#       fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
#
function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
	echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
	echo "Aborting."
	exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules	| Rule already defined	|  Audit rules file to inspect	  |
# -----------------------------------------------------------------------------------------
#	auditctl		|     Doesn't matter	|  /etc/audit/audit.rules	  |
# -----------------------------------------------------------------------------------------
# 	augenrules		|          Yes		|  /etc/audit/rules.d/*.rules	  |
# 	augenrules		|          No		|  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect
files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
	echo "Unknown audit rules loading tool: $1. Aborting."
	echo "Use either 'auditctl' or 'augenrules'!"
	exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
	files_to_inspect+=('/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
	readarray -t matches < <(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules)

	# For each of the matched entries
	for match in "${matches[@]}"
	do
		# Extract filepath from the match
		rulesd_audit_file=$(echo $match | cut -f1 -d ':')
		# Append that path into list of files for inspection
		files_to_inspect+=("$rulesd_audit_file")
	done
	# Case when particular audit rule isn't defined yet
	if [ "${#files_to_inspect[@]}" -eq "0" ]
	then
		# Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
		local key_rule_file="/etc/audit/rules.d/$key.rules"
		# If the $key.rules file doesn't exist yet, create it with correct permissions
		if [ ! -e "$key_rule_file" ]
		then
			touch "$key_rule_file"
			chmod 0640 "$key_rule_file"
		fi

		files_to_inspect+=("$key_rule_file")
	fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

	# Check if audit watch file system object rule for given path already present
	if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
	then
		# Rule is found => verify yet if existing rule definition contains
		# all of the required access type bits

		# Escape slashes in path for use in sed pattern below
		local esc_path=${path//$'/'/$'\/'}
		# Define BRE whitespace class shortcut
		local sp="[[:space:]]"
		# Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
		current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
		# Split required access bits string into characters array
		# (to check bit's presence for one bit at a time)
		for access_bit in $(echo "$required_access_bits" | grep -o .)
		do
			# For each from the required access bits (e.g. 'w', 'a') check
			# if they are already present in current access bits for rule.
			# If not, append that bit at the end
			if ! grep -q "$access_bit" <<< "$current_access_bits"
			then
				# Concatenate the existing mask with the missing bit
				current_access_bits="$current_access_bits$access_bit"
			fi
		done
		# Propagate the updated rule's access bits (original + the required
		# ones) back into the /etc/audit/audit.rules file for that rule
		sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
	else
		# Rule isn't present yet. Append it at the end of $audit_rules_file file
		# with proper key

		echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
	fi
done
}
fix_audit_watch_rule "auditctl" "/etc/group" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/group" "wa" "audit_rules_usergroup_modification"
# END fix for 'audit_rules_usergroup_modification_group'

###############################################################################
# Auditd must be downloaded and enabled (V-38632)
###############################################################################
(>&2 echo "Remediating rule 228/236: 'service_auditd_enabled'")

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" start 'auditd.service'
"$SYSTEMCTL_EXEC" enable 'auditd.service'
# END fix for 'service_auditd_enabled'



###############################################################################
# The Red Hat Enterprise Linux operating system must be configured to disable USB mass storage.
###############################################################################
(>&2 echo "Remediating rule 232/236: 'kernel_module_usb-storage_disabled'")
if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	sed -i 's/^install usb-storage.*/install usb-storage /bin/true/g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
fi
# END fix for 'kernel_module_usb-storage_disabled'

###############################################################################
# The Red Hat Enterprise Linux operating system must disable the file system automounter unless required.
###############################################################################
(>&2 echo "Remediating rule 233/236: 'service_autofs_disabled'")


SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'autofs.service'
"$SYSTEMCTL_EXEC" disable 'autofs.service'
"$SYSTEMCTL_EXEC" mask 'autofs.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" list-unit-files | grep -q '^autofs.socket'; then
    "$SYSTEMCTL_EXEC" stop 'autofs.socket'
    "$SYSTEMCTL_EXEC" disable 'autofs.socket'
    "$SYSTEMCTL_EXEC" mask 'autofs.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'autofs.service' || true
# END fix for 'service_autofs_disabled'


###############################################################################
# File systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed. (V-72041)
###############################################################################
(>&2 echo "Remediating rule 235/236: 'mount_option_home_nosuid'")
function include_mount_options_functions {
	:
}

# $1: type of filesystem
# $2: new mount point option
# $3: filesystem of new mount point (used when adding new entry in fstab)
# $4: mount type of new mount point (used when adding new entry in fstab)
function ensure_mount_option_for_vfstype {
        local _vfstype="$1" _new_opt="$2" _filesystem=$3 _type=$4 _vfstype_points=()
        readarray -t _vfstype_points < <(grep -E "[[:space:]]${_vfstype}[[:space:]]" /etc/fstab | awk '{print $2}')

        for _vfstype_point in "${_vfstype_points[@]}"
        do
                ensure_mount_option_in_fstab "$_vfstype_point" "$_new_opt" "$_filesystem" "$_type"
        done
}

# $1: mount point
# $2: new mount point option
# $3: device or virtual string (used when adding new entry in fstab)
# $4: mount type of mount point (used when adding new entry in fstab)
function ensure_mount_option_in_fstab {
	local _mount_point="$1" _new_opt="$2" _device=$3 _type=$4
	local _mount_point_match_regexp="" _previous_mount_opts=""
	_mount_point_match_regexp="$(get_mount_point_regexp "$_mount_point")"

	if [ "$(grep -c "$_mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
		# runtime opts without some automatic kernel/userspace-added defaults
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
					| sed -E "s/(rw|defaults|seclabel|${_new_opt})(,|$)//g;s/,$//")
		[ "$_previous_mount_opts" ] && _previous_mount_opts+=","
		echo "${_device} ${_mount_point} ${_type} defaults,${_previous_mount_opts}${_new_opt} 0 0" >> /etc/fstab
	elif [ "$(grep "$_mount_point_match_regexp" /etc/fstab | grep -c "$_new_opt")" -eq 0 ]; then
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/fstab | awk '{print $4}')
		sed -i "s|\(${_mount_point_match_regexp}.*${_previous_mount_opts}\)|\1,${_new_opt}|" /etc/fstab
	fi
}

# $1: mount point
function get_mount_point_regexp {
		printf "[[:space:]]%s[[:space:]]" "$1"
}

# $1: mount point
function assert_mount_point_in_fstab {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	grep "$_mount_point_match_regexp" -q /etc/fstab \
		|| { echo "The mount point '$1' is not even in /etc/fstab, so we can't set up mount options" >&2; return 1; }
}

# $1: mount point
function remove_defaults_from_fstab_if_overriden {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	if grep "$_mount_point_match_regexp" /etc/fstab | grep -q "defaults,"
	then
		sed -i "s|\(${_mount_point_match_regexp}.*\)defaults,|\1|" /etc/fstab
	fi
}

# $1: mount point
function ensure_partition_is_mounted {
	local _mount_point="$1"
	mkdir -p "$_mount_point" || return 1
	if mountpoint -q "$_mount_point"; then
		mount -o remount --target "$_mount_point"
	else
		mount --target "$_mount_point"
	fi
}
include_mount_options_functions

function perform_remediation {
	# test "$mount_has_to_exist" = 'yes'
	if test "yes" = 'yes'; then
		assert_mount_point_in_fstab /home || { echo "Not remediating, because there is no record of /home in /etc/fstab" >&2; return 1; }
	fi

	ensure_mount_option_in_fstab "/home" "nosuid" "" ""

	ensure_partition_is_mounted "/home"
}

perform_remediation
# END fix for 'mount_option_home_nosuid'

###############################################################################
# File systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed. (V-72043)
###############################################################################
(>&2 echo "Remediating rule 236/236: 'mount_option_nosuid_removable_partitions'")

var_removable_partition="/dev/cdrom"
function include_mount_options_functions {
	:
}

# $1: type of filesystem
# $2: new mount point option
# $3: filesystem of new mount point (used when adding new entry in fstab)
# $4: mount type of new mount point (used when adding new entry in fstab)
function ensure_mount_option_for_vfstype {
        local _vfstype="$1" _new_opt="$2" _filesystem=$3 _type=$4 _vfstype_points=()
        readarray -t _vfstype_points < <(grep -E "[[:space:]]${_vfstype}[[:space:]]" /etc/fstab | awk '{print $2}')

        for _vfstype_point in "${_vfstype_points[@]}"
        do
                ensure_mount_option_in_fstab "$_vfstype_point" "$_new_opt" "$_filesystem" "$_type"
        done
}

# $1: mount point
# $2: new mount point option
# $3: device or virtual string (used when adding new entry in fstab)
# $4: mount type of mount point (used when adding new entry in fstab)
function ensure_mount_option_in_fstab {
	local _mount_point="$1" _new_opt="$2" _device=$3 _type=$4
	local _mount_point_match_regexp="" _previous_mount_opts=""
	_mount_point_match_regexp="$(get_mount_point_regexp "$_mount_point")"

	if [ "$(grep -c "$_mount_point_match_regexp" /etc/fstab)" -eq 0 ]; then
		# runtime opts without some automatic kernel/userspace-added defaults
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
					| sed -E "s/(rw|defaults|seclabel|${_new_opt})(,|$)//g;s/,$//")
		[ "$_previous_mount_opts" ] && _previous_mount_opts+=","
		echo "${_device} ${_mount_point} ${_type} defaults,${_previous_mount_opts}${_new_opt} 0 0" >> /etc/fstab
	elif [ "$(grep "$_mount_point_match_regexp" /etc/fstab | grep -c "$_new_opt")" -eq 0 ]; then
		_previous_mount_opts=$(grep "$_mount_point_match_regexp" /etc/fstab | awk '{print $4}')
		sed -i "s|\(${_mount_point_match_regexp}.*${_previous_mount_opts}\)|\1,${_new_opt}|" /etc/fstab
	fi
}

# $1: mount point
function get_mount_point_regexp {
		printf "[[:space:]]%s[[:space:]]" "$1"
}

# $1: mount point
function assert_mount_point_in_fstab {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	grep "$_mount_point_match_regexp" -q /etc/fstab \
		|| { echo "The mount point '$1' is not even in /etc/fstab, so we can't set up mount options" >&2; return 1; }
}

# $1: mount point
function remove_defaults_from_fstab_if_overriden {
	local _mount_point_match_regexp
	_mount_point_match_regexp="$(get_mount_point_regexp "$1")"
	if grep "$_mount_point_match_regexp" /etc/fstab | grep -q "defaults,"
	then
		sed -i "s|\(${_mount_point_match_regexp}.*\)defaults,|\1|" /etc/fstab
	fi
}

# $1: mount point
function ensure_partition_is_mounted {
	local _mount_point="$1"
	mkdir -p "$_mount_point" || return 1
	if mountpoint -q "$_mount_point"; then
		mount -o remount --target "$_mount_point"
	else
		mount --target "$_mount_point"
	fi
}
include_mount_options_functions

function perform_remediation {
	# test "$mount_has_to_exist" = 'yes'
	if test "yes" = 'yes'; then
		assert_mount_point_in_fstab "$var_removable_partition" || { echo "Not remediating, because there is no record of $var_removable_partition in /etc/fstab" >&2; return 1; }
	fi

	ensure_mount_option_in_fstab "$var_removable_partition" "nosuid" "" ""

	ensure_partition_is_mounted "$var_removable_partition"
}

perform_remediation
# END fix for 'mount_option_nosuid_removable_partitions'


###############################################################################
#The Red Hat Enterprise Linux operating system must have the screen package installed.
###############################################################################

# Install Screen package 
yum install -y tmux && yum install -y screen
