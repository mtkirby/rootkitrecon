# rootkitrecon


Rootkitrecon is a script that runs on an rpm/dpk system that reports suspicious activity.

Output files are:



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.libkitcheck

This report shows results from examining the ld library cache and check each library file to make sure it belongs to a known installed package.  Next, it will examine the loaded libraries for each process and again check to make sure it belongs to a known installed package as well as alert for any process that was executed with LD_PRELOAD.
What admins should look for:  Anything in this report is highly suspicious and likely a library rootkit.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.localusers

This report shows local users and if they have a password set, have an ssh key, and lists their .ssh directory and any history files in their home.
What admins should look for:  Look for unknown accounts.  Examine authorized_keys for unknown keys.  Look at history files for suspicious activity.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.modpkgcheck

Shows active kernel modules that do not belong to an rpm or dpkg package.
What admins should look for:  Any kernel module that is not part of an rpm or dpkg package could be a rootkit.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.nonpkgcheck

Finds all the directories that were created by packages and then searches those directories for files that do not belong to a package.
What admins should look for:  There will be false positives.  Look for mystery executables.


/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.patchinfo

Shows a count of missing security patches.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.pkgcheck

Performs rpm and dpkg integrity checks and only report on files that do not match the package contents.  This is more useful than a traditional FIM as it continually alerts on file integrity mismatches.  Traditional FIM often has false positives resulting from system patching.
What admins should look for:  Any checksum mismatch could be a sign of a rootkit.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.procpkgcheck

Examines running processes and only report on executables that do not belong to a known rpm or dpkg.  It will ignore any processes in a docker and/or lxc container.
What admins should look for:  Any process that does not belong to a known rpm or dpkg could be from a rootkit



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.socketlist

Shows what programs, and users, that have listening sockets and established connections.
What admins should look for:  Unknown listeners and outbound connections that may be a reverse shell.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.getlast

Grab last logins and reboots



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.procinfo

Information on all running processes



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.ausession

Shows audit logs for all running sessions.



/tmp/rootkitrecon.$HOSTNAME/rkrecon-$HOSTNAME.aureports

Shows audit reports.
