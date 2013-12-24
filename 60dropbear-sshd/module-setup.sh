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
  
  ## Find and set temporary directory for install files
  local tmp=$(mktemp -d --tmpdir dracut-crypt-sshd.XXXX)
  dinfo "Temporary directory will be: ${tmp}"
  
  ## Use dracut_install to abort if source is missing
  dracut_install pkill
  dracut_install setterm
  dracut_install /lib64/libnss_files.so.2
  dracut_install netstat
  
  ## Copy/Install dropbear and console_peek into the initramfs image
  dinfo "Modules will be installed from: ${moddir}"
  inst $(which dropbear) /sbin/dropbear
  inst "$moddir"/console_peek.sh /bin/console_peek
  
  ## Don't bother with a Digital Signature Algorithm (DSA) key because the algorithm is weaker than RSA.
  ## Check if the dropbear_rsa_key variable has been set, otherwise create a new key pair using ssh-keygen and 
  ## convert to the format dropbear uses
  [[ -z "${dropbear_rsa_key}" ]] && {
    
    ## I assume ssh-keygen does a better job of producing good RSA keys than
    ## dropbearkey, so use that one. It's interactive-only, hence some hacks.
    dinfo "Variable dropbear_rsa_key not set in dracut.conf."
    dinfo "Generating an ad-hoc RSA key for dropbear sshd in initramfs"
#    dropbear_rsa_key="$tmp"/key
    dropbear_rsa_key="dropbear_rsa_host_key"
    ## Remove temp key if it already exists
#    rm -f "${dropbear_rsa_key}"
#    mkfifo "$tmp"/keygen.fifo
#    script -q -c "ssh-keygen -q -t rsa -f '${dropbear_rsa_key}'; echo >'${tmp}/keygen.fifo'" /dev/null </dev/null >"$tmp"/keygen.log 2>&1
#    : <"$tmp"/keygen.fifo
#    script -q -c "dropbearkey -t rsa -s 4096 -f '${dropbear_rsa_key}.db' > authorized_keys"
#    dropbearkey -y -f id_rsa | grep "^ssh-rsa " >> authorized_keys
#    [[ -f "${dropbear_rsa_key}" && -f "${dropbear_rsa_key}".pub ]] || {
    [[ -f "$moddir/${dropbear_rsa_key}" ]] || {
      dfatal "Failed to generate ad-hoc rsa key"
      return 255
    }
    
    ## Oh, wow, another tool that doesn't have "batch mode" in the same script.
    ## It's deeply concerning that security people don't seem to grasp such basic concepts.
#    mv "${dropbear_rsa_key}"{,.tmp}
#    dropbearconvert openssh dropbear "${dropbear_rsa_key}"{.tmp,} >/dev/null 2>&1 || { 
#      dfatal "dropbearconvert failed"; rm -rf "$tmp"; return 255; }
  }
  
  local key_fp=$(dropbearkey -y -f ${moddir}/dropbear_rsa_host_key | grep "Fingerprint: ")
#  local key_bb=$(ssh-keygen -B -f /etc/ssh/ssh_host_rsa_key.pub)
  dinfo "Dropbear boot key parameters:"
  dinfo "  Port: ${dropbear_port}"
  dinfo "  ${key_fp}"
#  dinfo "  bubblebabble: ${key_bb}"
#  inst ""$moddir"/dropbear_dss_host_key" /etc/dropbear/dropbear_dss_host_key
  inst ""$moddir"/dropbear_rsa_host_key" /etc/dropbear/dropbear_rsa_host_key
#  inst ""$moddir"/dropbear_ecdsa_host_key" /etc/dropbear/dropbear_ecdsa_host_key
  
#  [[ -z "${dropbear_acl}" ]] && dropbear_acl="${moddir}"/authorized_keys
  inst "$moddir"/authorized_keys /root/.ssh/authorized_keys
  
  ## glibc needs only /etc/passwd with "root" entry (no group or shadow), which
  ## should be provided by 99base; /bin/sh will be run regardless of /etc/shells presence.
  ## It can do without nsswitch.conf, resolv.conf or whatever other stuff it usually has.
  
  ## Helper to safely send password to cryptsetup on /dev/console without echoing it.
  ## Yeah, dracut modules shouldn't compile stuff, but I'm not packaging that separately.
  gcc -std=gnu99 -O2 -Wall "$moddir"/auth.c -o "$tmp"/auth
  inst "$tmp"/auth /bin/console_auth
  
  ## Set dropbear_port if key generated manually
  [[ -z "${dropbear_port}" ]] && dropbear_port=2222
  
  ## Generate hooks right here, with parameters baked-in
  ## The first hook checks if dropbear is running, prints dropbear parameters, and then starts dropbear
  cat > "$tmp"/sshd_run.sh << EOF
#!/bin/sh

#[ -f /tmp/dropbear.pid ] && kill 0 \$(cat /tmp/dropbear.pid) 2>/dev/null || {
[ -f /tmp/dropbear.pid ] || {
  
  info '[Dropbear-sshd] Starting Dropbear'
  info '[Dropbear-sshd] sshd port: ${dropbear_port}'
  info '[Dropbear-sshd] sshd key fingerprint: ${key_fp}'
#  info 'sshd key bubblebabble: ${key_bb}'
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
