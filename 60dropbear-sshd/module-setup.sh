#!/bin/bash

## Based on code, examples and ideas from:
## 	https://bugzilla.redhat.com/show_bug.cgi?id=524727
## 	http://roosbertl.blogspot.de/2012/12/centos6-disk-encryption-with-remote.html
## 	https://bitbucket.org/bmearns/dracut-crypt-wait
##	https://github.com/mk-fg/dracut-crypt-sshd
##
## Start dropbear sshd to be able to send password to waiting cryptsetup
## (from "crypt" module) remotely, or for any other kind of net-debug of dracut.
##
## Options (E.g., dropbear_port, dropbear_rsa_key, and dropbear_acl) can be added to /etc/dracut.conf [Tested with dracut 029-2.fc19]
## Dropbear sshd will be started at boot with:
## 	port: ${dropbear_port} or 2222
## 	Dropbear formatted host key: ${dropbear_rsa_key} or generated (fingerprint echoed)
##	Note: The dropbear host key must be of the name dropbear_host_{RSA,DSS,ECDSA}_key. Check manpage for details
## 	authorized client key(s): ${dropbear_acl} or /root/.ssh/authorized_keys
## 	root user only, no password auth, no port forwarding
##
## In dropbear shell:
##   
## 	## See what's on the console ("cat /dev/vcs1" should work too)
## 	console_peek
## 	## Read and send password to console
## 	console_auth
##
## N.B.: Style based on Google's "Shell Style Guide" [Revision 1.26]. Available from:
##       	http://google-styleguide.googlecode.com/svn/trunk/shell.xml

## Add to Readme
## For an explanation of dracut modules and their format please see:
## 	https://www.kernel.org/pub/linux/utils/boot/dracut/dracut.html
check() {
  return 0
}

depends() {
  echo network
  return 0
}

install() {
  
  ## Check for dracut.conf parameters
  [[ -z "${dropbear_port}" ]] && {
    dinfo "dropbear_port not set in dracut.conf, using default (2222)"
    dropbear_port=2222
  }
  
  [[ -z "${dropbear_rsa_key}" ]] && {
    
    ## I assume ssh-keygen does a better job of producing good RSA keys than
    ## dropbearkey, so use that one. It's interactive-only, hence some hacks.
    dinfo "dropbear_rsa_key not set in dracut.conf, using default (${moddir}/dropbear_rsa_host_key)"
    dropbear_rsa_key="${moddir}/dropbear_rsa_host_key"
    
  }
  
  [[ -z "${dropbear_acl}" ]] && {
    dinfo "dropbear_acl not set in dracut.conf, using default location (/root/.ssh/authorized_keys)"
    dropbear_acl="${moddir}/authorized_keys"
  }

  ## Find and set temporary directory for install files
  local tmp=$(mktemp -d --tmpdir dracut-crypt-sshd.XXXX)
  dinfo "Temporary directory will be: ${tmp}"
  
  ## Use dracut_install to abort if source is missing
  dracut_install pkill
  dracut_install setterm
  dracut_install /lib64/libnss_files.so.2
  dracut_install netstat  #For checking dropbear is working on the correct port
  
  ## Copy/Install dropbear and console_peek into the initramfs image
  ## Modules directory variable should point to /lib/dracut/modules.d/60dropbear-sshd
  dinfo "Modules will be installed from: ${moddir}"
  inst $(which dropbear) /sbin/dropbear
  inst "$moddir"/console_peek.sh /bin/console_peek
  
  ## Don't bother with a Digital Signature Algorithm (DSA) key because the algorithm is weaker than RSA.
  ## Check if the dropbear_rsa_key variable has been set, otherwise create a new key pair using ssh-keygen and 
  ## convert to the format dropbear uses
  [[ -f "${dropbear_rsa_key}" ]] || {
    dfatal "Failed to generate ad-hoc rsa key"
    return 255
  }
  
  dinfo "Dropbear boot key parameters:"
  dinfo "  Port: ${dropbear_port}"
  local key_fp=$(dropbearkey -y -f ${dropbear_rsa_key} | grep "Fingerprint: ")
  dinfo "  ${key_fp}"
  inst "${dropbear_rsa_key}" /etc/dropbear/dropbear_rsa_host_key
  
  inst "${dropbear_acl}" /root/.ssh/authorized_keys
  
  ## glibc needs only /etc/passwd with "root" entry (no group or shadow), which
  ## should be provided by 99base; /bin/sh will be run regardless of /etc/shells presence.
  ## It can do without nsswitch.conf, resolv.conf or whatever other stuff it usually has.
  
  ## Helper to safely send password to cryptsetup on /dev/console without echoing it.
  ## Yeah, dracut modules shouldn't compile stuff, but I'm not packaging that separately.
  gcc -std=gnu99 -O2 -Wall "$moddir"/auth.c -o "$tmp"/auth
  inst "$tmp"/auth /bin/console_auth
    
  ## Generate hooks right here, with parameters baked-in
  ## The first hook checks if dropbear is running, prints dropbear parameters, and then starts dropbear
  cat > "$tmp"/sshd_run.sh << EOF
#!/bin/sh

[ -f /tmp/dropbear.pid ] || {
  
  info '[Dropbear-sshd] Starting Dropbear'
  info '[Dropbear-sshd] sshd port: ${dropbear_port}'
  info '[Dropbear-sshd] sshd key fingerprint: ${key_fp}'
  info '[Dropbear-sshd] Creating /var/log/lastlog'
  mkdir -p /var/log > /var/log/lastlog

  ## Removed "-d -" option as it is not available in dropbear v2013.62
  ## If present it sets a null dss key. It is no longer shown in the dropbear manpage
  # Tried and get error "Failed loading -"
  /sbin/dropbear -E -m -s -j -k -p ${dropbear_port} -r /etc/dropbear/dropbear_rsa_host_key -P /tmp/dropbear.pid
  [ \$? -gt 0 ] && info 'Dropbear sshd failed to start'
}
EOF

  ## Create the kill hook
  cat >"$tmp"/sshd_kill.sh << EOF
#!/bin/sh
[ -f /tmp/dropbear.pid ] || exit 0
read main_pid </tmp/dropbear.pid
kill -STOP \${main_pid} 2>/dev/null
pkill -P \${main_pid}
kill \${main_pid} 2>/dev/null
kill -CONT \${main_pid} 2>/dev/null
EOF
  
  ## Add the run script to initqueue (priority 20) and kill script to cleanup (priority 05)
  chmod +x "$tmp"/sshd_{run,kill}.sh
  inst_hook initqueue 20 "$tmp"/sshd_run.sh
  inst_hook cleanup 05 "$tmp"/sshd_kill.sh
  
  rm -rf "$tmp"
  return 0
	
}
