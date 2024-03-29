#!/bin/bash
# 20240219 Kirby


umask 077
export COLUMNS=5000

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]
then
    echo "FAILURE: Bash is too old for $0"
    exit 1
fi

if [[ "$LOGNAME" != "root" ]]
then
    echo "FAILURE: Must run as root"
    exit 1
fi

unset PYTHONPATH
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH
export LD_LIBRARY_PATH=/lib64:/usr/lib64:/lib:/usr/lib:/usr/lib32:/lib32:$LD_LIBRARY_PATH
export HOSTNAME=$(uname -n)
export LINEBANNER="--------------------------------------------------------------------------------"
export BANNER="################################################################################"

##################################################
function MAIN()
{
    local func
    local logdir="/tmp/rootkitrecon.$HOSTNAME"
    declare -A functions

    functions['pkgcheck']="Performs rpm and dpkg integrity checks and only report on files that do not match the package contents. This is more useful than a traditional FIM as it continually alerts on file integrity mismatches. Traditional FIM often has false positives resulting from system patching. What admins should look for: Any checksum mismatch could be a sign of a rootkit."
    functions['procpkgcheck']="Examines running processes and only report on executables that do not belong to a known rpm or dpkg. It will ignore any processes in a docker and/or lxc container. What admins should look for: Any process that does not belong to a known rpm or dpkg could be from a rootkit"
    functions['patchinfo']="Shows a count of missing security patches and last patch dates."
    functions['libkitcheck']="This report shows results from examining the ld library cache and check each library file to make sure it belongs to a known installed package. Next, it will examine the loaded libraries for each process and again check to make sure it belongs to a known installed package as well as alert for any process that was executed with LD_PRELOAD. What admins should look for: Anything in this report is highly suspicious and likely a library rootkit."
    functions['modpkgcheck']="Shows active kernel modules that do not belong to an rpm or dpkg package. What admins should look for: Any kernel module that is not part of an rpm or dpkg package could be a rootkit."
    functions['localusersecurity']="This report shows local users and if they have a password set, have an ssh key, and lists their .ssh directory and any history files in their home. What admins should look for: Look for unknown accounts. Examine authorized_keys for unknown keys. Look at history files for suspicious activity."
    functions['socketlist']="Shows what programs, and users, that have listening sockets and established connections. What admins should look for: Unknown listeners and outbound connections that may be a reverse shell."
    functions['nonpkgcheck']="Finds all the directories that were created by packages and then searches those directories for files that do not belong to a package. What admins should look for: There will be false positives. Look for mystery executables."
    functions['procinfo']="Information on all running processes"
    functions['ausession']="Shows audit logs for all running sessions."
    functions['aureports']="Shows audit reports."
    functions['getlast']="Grab last logins and reboots."
    functions['sctimers']="Show systemd timers"

    mkdir "$logdir" >/dev/null 2>&1

    echo "This will take a few minutes.  Output files are in ${logdir}"
    for func in ${!functions[@]}
    do
        echo "$LINEBANNER"
        echo "Running $func -- ${functions[$func]}"
        $func > ${logdir}/rkrecon-$HOSTNAME.$func.txt 2>&1
        echo "Log file is ${logdir}/rkrecon-$HOSTNAME.$func.txt"
        echo ''
    done
    ps -efwww --cols 5000 --cumulative > ${logdir}/rkrecon-$HOSTNAME.ps-efwww.txt 2>&1
    ps -efwww --forest --cols 5000 --cumulative > ${logdir}/rkrecon-$HOSTNAME.ps-efwww-forest.txt 2>&1
    pstree -clapSunGs > ${logdir}/rkrecon-$HOSTNAME.pstree-clapSunGs.txt 2>&1
    ip netns list |egrep -q . && ip netns list > ${logdir}/rkrecon-$HOSTNAME.ip-netns-list.txt 2>&1
    docker ps 2>/dev/null |egrep -q . && docker ps > ${logdir}/rkrecon-$HOSTNAME.docker-ps.txt 2>&1
    lsof -Pni > ${logdir}/rkrecon-$HOSTNAME.lsof-Pni.txt 2>&1
    lsof > ${logdir}/rkrecon-$HOSTNAME.lsof.txt 2>&1

    echo ''
    echo "tarball of logs is /tmp/rootkitrecon.$HOSTNAME.tgz"
    rm -f /tmp/rootkitrecon.$HOSTNAME.tgz 2>/dev/null
    cd /tmp
    tar cfz /tmp/rootkitrecon.$HOSTNAME.tgz ${logdir##*/} >/dev/null 2>&1
    echo "$BANNER"
    echo "Other tools to run:"
    echo "    prochunter: https://gitlab.com/nowayout/prochunter"
    echo "    rkhunter: https://sourceforge.net/projects/rkhunter/files/rkhunter/"
    echo "    chkrootkit: http://www.chkrootkit.org/"
    echo "    lynis: https://github.com/CISOfy/lynis"
    echo "$BANNER"
    echo "done"
}

##################################################
function join_by 
{
    local IFS="$1"
    shift
    echo "$*"
}

##################################################
function printfileinfo() 
{
    local file=$1
    local checkowner=$2
    local checkownerdesc=$3
    local extrainfo=$4
    local alert=()
    local alarm
    local octmode
    local filemode
    local fileowner
    local otherperm
    local groupperm
    local mountpoint
    local fstype
    local sha1sum
    file=$(readlink -f "$file")
    octmode=$(stat -c "%a" "$file")
    filemode=$(stat -c "%A" "$file")
    fileowner=$(stat -c "%U" "$file")
    filesize=$(stat -c "%s" "$file")
    otherperm=${octmode:$((${#octmode}-1)):1}
    groupperm=${octmode:$((${#octmode}-2)):1}
    mountpoint=$(stat -c "%m" "$file")
    fstype=$(stat --file-system -c "%T" "$file")

    if [[ "$file" =~ ^/proc/ ]] \
    || [[ "$file" =~ ^/sys/ ]] \
    || [[ "$file" =~ ^/dev/ ]] 
    then
        return 1
    fi

    if [[ "$checkowner" != "$fileowner" ]] \
    && [[ "$fileowner" != "root" ]] \
    && [[ -n "$checkowner" ]]
    then
        alert+=("$checkownerdesc and file owner mismatch.")
    fi
    if [[ "$otherperm" == '2' ]] \
    || [[ "$otherperm" == '3' ]] \
    || [[ "$otherperm" == '6' ]] \
    || [[ "$otherperm" == '7' ]]
    then
        alert+=("Permissions allow world write.")
    fi
    if [[ "$groupperm" == '2' ]] \
    || [[ "$groupperm" == '3' ]] \
    || [[ "$groupperm" == '6' ]] \
    || [[ "$groupperm" == '7' ]]
    then
        alert+=("Permissions allow group write.")
    fi

    if [[ ${#alert} -ge 1 ]]
    then
        alarm="ALARM=\"$(join_by ' ' "${alert[@]}")\""
    fi

    sha1sum="unknown"
    if [[ -f "$file" ]] \
    && [[ "$filesize" -lt 1000000000 ]]
    then
        if which sha1sum >/dev/null 2>&1; then
            sha1sum=$(sha1sum "$file" |awk '{print $1}')
        elif which openssl >/dev/null 2>&1; then
            sha1sum=$(openssl sha1 "$file" |awk '{print $2}')
        fi  
    fi

    #echo "file=\"$file\" fileowner=\"$fileowner\" filemode=\"$filemode\" octmode=\"$octmode\" mountpoint=\"$mountpoint\" fstype=\"$fstype\" checkowner=\"$checkowner\" checkownerdesc=\"$checkownerdesc\" sha1sum=\"$sha1sum\" $extrainfo $alarm"
    echo "FILE=$file"
    echo "FILEOWNER=$fileowner  FILEMODE=$filemode OCTMODE=$octmode  MOUNTPOINT=$mountpoint FSTYPE=$fstype"
    echo "CHECKOWNER=$checkowner CHECKOWNERDESC=$checkownerdesc"
    echo "SHA1SUM=$sha1sum"
    echo "$extrainfo $alarm"
}


##################################################
function rpmcheck() 
{
    local pkg=$1
    local comments=()
    local filemode=''
    local filegroup=''
    local pkgmode=''
    local pkguser=''
    local pkggroup=''
    local file=""
    local attr=""
    local flatcomments=""

    # Check to see if package still exists.
    # Ignore package if this system is in the middle of patching
    if ! rpm -q "$pkg" >/dev/null 2>&1
    then
        return 1
    fi

    local IFS=$'\n'
    for line in $(rpm -V --nodeps --nomtime "$pkg")
    do
        file="${line##* }"
        attr="${line%% *}"
        comments=()

        if [[ "x$file" != "x" ]]
        then
            [[ "$attr" == "missing" ]] && comments+=("file is missing.")
            [[ "${attr:0:1}" == "S" ]] && comments+=("file size differs.")
            if [[ "${attr:1:1}" == "M" ]]
            then
                pkgmode=$(rpm -qil --dump "$pkg" |egrep "^$file " |head -1 |awk '{print $5}' |sed -e 's/.*\(....\)/\1/')
                filemode=$(stat -c "%a" "$file")
                comments+=("mode differs: was $pkgmode and is now $filemode.")
            fi
            [[ "${attr:2:1}" == "5" ]] && comments+=("digest differs.")
            [[ "${attr:3:1}" == "D" ]] && comments+=("device major/minor mismatch.")
            [[ "${attr:4:1}" == "L" ]] && comments+=("readlink path mismatch.")
            if [[ "${attr:5:1}" == "U" ]]
            then
                pkguser=$(rpm -qil --dump "$pkg" |egrep "^$file " |head -1 |awk '{print $6}')
                fileuser=$(stat -c "%U" "$file")
                comments+=("user ownership differs: was $pkguser, is now $fileuser.")
                fi
            if [[ "${attr:6:1}" == "G" ]]
            then
                pkggroup=$(rpm -qil --dump "$pkg" |egrep "^$file " |head -1 |awk '{print $7}')
                filegroup=$(stat -c "%G" "$file")
                comments+=("group ownership differs: was $pkggroup, is now $filegroup.")
            fi
            [[ "${attr:7:1}" == "T" ]] && comments+=("mtime differs. ")
            [[ "${attr:8:1}" == "P" ]] && comments+=("capabilities differ. ")
            flatcomments=$(join_by '  ' "${comments[@]}")
            echo "$LINEBANNER"
            echo "FILE $file"
            echo "PKG $pkg"
            echo "ATTR $attr $flatcomments"
        fi
    done
}

##################################################
function dpkgcheck() 
{
    local pkg=$1
    local comments=()
    local file=""
    local attr=""
    local flatcomments=""

    # Check to see if package still exists.
    # Ignore package if this system is in the middle of patching
    if ! dpkg -s "$pkg" >/dev/null 2>&1
    then
        echo "ignoring $pkg"
        return 1
    fi

    local IFS=$'\n'
    for line in $(dpkg -V "$pkg")
    do
        file="${line##* }"
        attr="${line%% *}"
        comments=()
        # dpkg doesn't have all the features that rpm has
        if [[ "x$file" != "x" ]]
        then
            [[ "$attr" == "missing" ]] && comments+=("file is missing.")
            [[ "${attr:2:1}" == "5" ]] && comments+=("digest differs.")
            flatcomments=$(join_by '  ' "${comments[@]}")
            echo "$LINEBANNER"
            echo "FILE $file"
            echo "PKG $pkg"
            echo "ATTR $attr $flatcomments"
        fi
    done

}


##################################################
function pkgcheck()
{
    totalcount=0
    local pkg
    local rpms=()
    local pkgcount
    local IFS=$'\n'

    if which rpm >/dev/null 2>&1
    then
        declare -a rpms
        # ignore kernel packages on the first run.  
        for pkg in $(rpm -qa)
        do
            rpms+=("$pkg")
        done
        # add kernel packages only for revision we are running
        for pkg in $(rpm -qa kernel-* |grep "$(uname -r)" |egrep -v '\-devel\-|\-headers\-')
        do
            rpms+=("$pkg")
        done
        pkgcount=${#rpms[@]}
        if [[ $pkgcount -ge 1 ]] \
        || [[ $pkgcount =~ ^[[:digit:]]+$ ]]
        then
            for pkg in ${rpms[*]}
            do
                rpmcheck "$pkg"
            done
        else
            echo "pkgcount for rpm failed"
        fi
    fi
    
    
    if which dpkg >/dev/null 2>&1
    then
        declare -a dpkgs
        # ignore kernel packages on the first run.  
        for pkg in $(dpkg -l |awk '/^ii / {print $2}')
        do
            dpkgs+=("$pkg")
        done
        # add kernel packages only for revision we are running
        for pkg in $(dpkg -l linux-image*  |awk '/^ii / {print $2}' |grep "$(uname -r)")
        do
            dpkgs+=("$pkg")
        done
        # add kernel packages only for revision we are running
        pkgcount=${#dpkgs[@]}
        if [[ $pkgcount -ge 1 ]] \
        || [[ $pkgcount =~ ^[[:digit:]]+$ ]]
        then
            for pkg in ${dpkgs[*]}
            do
                dpkgcheck "$pkg"
            done
        else
            echo "pkgcount for dpkg failed"
        fi
    fi
}



##################################################
function procpkgcheck()
{
    declare -A seen
    local totalproccount=$(cat /proc/[0-9]*/cpuset 2>/dev/null |egrep -c '^/$')
    local proccount=0
    local chrootcount=0
    local pid
    local piddir
    local file
    local procowner
    local procuid
    local loginuid

    for piddir in /proc/[0-9]*
    do
        pid=${piddir##*/}
        ((proccount++))
    
        # Check to see if exe file exists.
        # Sometimes a program will create a temporary script and delete it while running.
        file=$(stat -c '%N' "$piddir/exe" 2>/dev/null |grep ' -> '|sed -e "s/.*-> .\(\/.*\).$/\1/")
        file=$(readlink -f "$file")
        if [[ ! -f "$file" ]]
        then
            continue
        fi
    
        #
        # Ignore process if it is within a container or chroot
        #   
        if ! egrep -q '^/$' "$piddir"/cpuset >/dev/null 2>&1
        then
            ((chrootcount++))
            continue
        fi
            
        if [[ ${seen["$file"]} == 1 ]]
        then
            continue
        else
            seen["$file"]=1
        fi 
    
        if ! rpm -qf "$file" >/dev/null 2>&1 \
        && ! dpkg-query -S "$file" >/dev/null 2>&1
        then
            procowner=$(stat -c '%U' "$piddir")
            procuid=$(stat -c '%u' "$piddir")
            loginuid=$(cat "$piddir"/loginuid)
            printfileinfo "$file" "$procowner" "Process owner" "pid=\"$pid\" procowner=\"$procowner\" procuid=\"$procuid\" loginuid=\"$loginuid\""   
            ps -fwwwp $pid
            echo "$LINEBANNER"
            echo ''
        fi
    done
}

##################################################
function patchinfo()
{
    local yum
    local num
    local type
    local patches
    local aptlastpatch
    local lastpatch
    local alarm

    # yum/dnf uses python, which can conflict with Splunk's python
    unset PYTHONPATH
    
    declare -a notices
    
    local IFS=$'\n'
    if which dnf >/dev/null 2>&1 || which yum >/dev/null 2>&1
    then
        if which dnf >/dev/null 2>&1
        then
            yum=dnf
        else
            yum=yum
        fi
        num=0
        for line in $($yum updateinfo|egrep -a 'notice\(s\)$')
        do
            num=$(echo "$line" |awk '{print $1}')
            type=$(echo "$line" |sed -e 's/.* [0-9]* \(.*\) notice.*/\1/'|sed -e 's/ /_/g')
            notices+=($type=$num)
        done
        alarm="$(join_by ' ' "${notices[@]}")"
        if [[ -z ${notices[@]} ]]
        then
            echo "No missing security patches"
        fi

        lastpatch=$($yum history |grep -i '| update ' |sed -e 's/.* \([0-9]*-[0-9]*-[0-9]*\) [0-9]*:[0-9]* .*/\1/' |head -1)
        echo "updater=\"$yum\" lastpatchdate=\"$lastpatch\" $alarm"
        echo '';echo ''
        $yum history 
    fi
    
    if which apt-get >/dev/null 2>&1
    then
        apt-get update >/dev/null 2>&1
        apt-get -q -s upgrade
        patches=$(apt-get -q -s upgrade|egrep -a  '^[0-9]+ upgraded' |sed -e 's/\([0-9]*\) upgraded.*/\1/')
        echo "updater=\"apt\" patches=$patches"
    fi
    
    
    if egrep -q '^Start-Date:' /var/log/apt/history.log >/dev/null 2>&1
    then
        aptlastpatch=$(egrep -a '^Start-Date:' /var/log/apt/history.log |tail -1 |awk '{print $2" "$3}')
        echo "updater=\"apt\" lastpatchdate=\"$aptlastpatch\""
    fi
}



##################################################
function libkitcheck()
{
    local chrootcount
    local dupskip
    local ldcount
    local libfile
    local libtotalcount
    local loginuid
    local pid
    local piddir
    local preload
    local proclibcount
    local procowner
    local procuid
    declare -A libseen
    
    ldcount=$(ldconfig -p |grep -c ' => ')
    proclibcount=$(awk '/ r-xp .* fd:/ {print $6}' /proc/[0-9]*/maps 2>/dev/null|sort|uniq |wc -l)
    libtotalcount=$((ldcount + proclibcount))
    dupskip=0
    chrootcount=0
    for libfile in $(ldconfig -p|grep ' => ' |sed -e 's/.* => \(\/*\)/\1/' )
    do 
        libfile=$(readlink -f "$libfile")
        if ! rpm -qf "$libfile" >/dev/null 2>&1 \
        && ! dpkg -S "$libfile" >/dev/null 2>&1
        then
            printfileinfo "$libfile" "root" "ld cache" "ALARM=\"ALERT $libfile found in ld cache does not belong to a package\""
        else
            libseen["$libfile"]=1
        fi
    done
    
    for piddir in /proc/[0-9]*
    do
        pid=${piddir##*/}
        # Check to see if exe file exists.
        # Sometimes a program will create a temporary script and delete it while running.
        file=$(stat -c '%N' "$piddir/exe" 2>/dev/null |grep ' -> '|sed -e "s/.*-> .\(\/.*\).$/\1/")
        if [[ ! -f "$file" ]]
        then
            continue
        fi
    
        # Ignore process if it is within a container or chroot
        if ! egrep -q '^/$' "$piddir"/cpuset >/dev/null 2>&1
        then
            ((chrootcount++))
            continue
        fi
    
        if preload=$(tr '\0' '\n' < "$piddir"/environ |egrep '^LD_PRELOAD=' 2>&1)
        then
            procowner=$(stat -c '%U' "$piddir")
            procuid=$(stat -c '%u' "$piddir")
            loginuid=$(cat "$piddir"/loginuid)
            printfileinfo "$file" "" "" "ALARM=\"LD_PRELOAD DETECTED\" preload=\"$preload\" process=\"$file\" pid=\"$pid\" procowner=\"$procowner\" procuid=\"$procuid\" loginuid=\"$loginuid\""
            ps -fwwwp $pid
            echo "$LINEBANNER"
            echo ''
        fi
    
        for libfile in $(awk '/ r-xp .* fd:/ {print $6}' "$piddir"/maps 2>/dev/null)
        do
            libfile=$(readlink -f "$libfile")
            if [[ ${libseen["$libfile"]} == 1 ]]
            then
                ((dupskip++))
                continue
            fi
            if [[ -f "$libfile" ]] \
            && ! rpm -qf "$libfile" >/dev/null 2>&1 \
            && ! dpkg -S "$libfile" >/dev/null 2>&1 
            then
                procowner=$(stat -c '%U' "$piddir")
                procuid=$(stat -c '%u' "$piddir")
                loginuid=$(cat "$piddir"/loginuid)
                printfileinfo "$libfile" "" "" "ALARM=\"ALERT $libfile is not a package library\" process=\"$file\" pid=\"$pid\" procowner=\"$procowner\" procuid=\"$procuid\" loginuid=\"$loginuid\""
                ps -fwwwp $pid
                echo "$LINEBANNER"
                echo ''
            else
                libseen["$libfile"]=1
            fi
        done
    done
}




##################################################
function modpkgcheck()
{
    local module
    local filename

    if ! which rpm >/dev/null 2>&1 \
    && ! which dpkg dpkg-query >/dev/null 2>&1
    then
        echo "Unable to do modpkgcheck.  No rpm/dpkg"
        return 1
    fi
    
    for module in $(lsmod |awk '{print $1}')
    do 
        if [[ "$module" == 'Module' ]]
        then
            continue
        fi
        filename=$(modinfo "$module" 2>/dev/null |awk '/^filename:/ {print $2}')
        filename=$(readlink -f "$filename")
    
        if ! rpm -qf "$filename" >/dev/null 2>&1 \
        && ! dpkg-query -S "$filename" >/dev/null 2>&1
        then
            echo "ALERT=\"No package for module=$module filename=$filename\""
        else
            echo "module $module is good"
        fi
    done
}


##################################################
function nonpkgcheck()
{
    local IFS=$'\n'
    declare -A dirs
    declare -A pkgfiles
    local pkgcount=()
    local totalpkgcount
    local pkg
    local dir
    local file
    local filecount
    local dircount

    if which rpm >/dev/null 2>&1
    then
        totalpkgcount=$(rpm -qa|wc -l)
        for pkg in $(rpm -qa 2>/dev/null)
        do 
            ((pkgcount++))
            for file in $(rpm -qil "$pkg" |egrep '^/')
            do
                pkgfiles["$file"]=1
                pkgfiles["$file"]=1
                dir="${file%/*}"
                if [[ "$dir" =~ ^$ ]] \
                || [[ "$dir" =~ /log ]] \
                || [[ "$dir" =~ /cache ]] \
                || [[ "$dir" =~ /tmp ]] \
                || [[ "$dir" =~ /root ]] \
                || [[ "$dir" =~ /lock ]] \
                || [[ "$dir" =~ /run ]] \
                || [[ -h "$dir" ]]
                then
                    continue
                fi
                dirs["$dir"]=1
            done
        done
    fi
    
    if which dpkg >/dev/null 2>&1
    then
        totalpkgcount=$(dpkg -l |awk '/^[phuri]/ {print $2}' 2>/dev/null |wc -l)
        for pkg in $(dpkg -l |awk '/^[phuri]/ {print $2}' 2>/dev/null)
        do 
        ((pkgcount++))
            for file in $(dpkg -L "$pkg" |egrep '^/')
            do
                pkgfiles["$file"]=1
                pkgfiles["$file"]=1
                dir="${file%/*}"
                if [[ "$dir" =~ ^$ ]] \
                || [[ "$dir" =~ ^\.$ ]] \
                || [[ "$dir" =~ /log ]] \
                || [[ "$dir" =~ /cache ]] \
                || [[ "$dir" =~ /tmp ]] \
                || [[ "$dir" =~ /root ]] \
                || [[ "$dir" =~ /lock ]] \
                || [[ "$dir" =~ /run ]] \
                || [[ -h "$dir" ]]
                then
                    continue
                fi
                dirs["$dir"]=1
            done
        done
    fi
    
    totaldircount=${#dirs[@]}    
    dircount=0
    filecount=0
    checkcount=0
    for dir in "${!dirs[@]}"
    do
        ((dircount++))
        for file in "$dir"/*
        do
            ((filecount++))
            if [[ -f "$file" ]] \
            && [[ ! "$file" =~ \.pyc$ ]] \
            && [[ ! "$file" =~ \.cache$ ]] \
            && [[ ! "$file" =~ \.log$ ]] \
            && [[ ! "$file" =~ \.solv$ ]] \
            && [[ ! "$file" =~ \.solvx$ ]] \
            && [[ ! "$file" =~ \.dat$ ]] \
            && [[ ! "$file" =~ \.reg$ ]] \
            && [[ ! "$file" =~ \.rpmnew$ ]] \
            && [[ ! -h "$file" ]] \
            && [[ -z ${pkgfiles["$file"]} ]] \
            && ! rpm -qif "$file" >/dev/null 2>&1 \
            && ! dpkg -S "$file" >/dev/null 2>&1
            then
                ((checkcount++))
                echo "$LINEBANNER"
                printfileinfo "$file" "" "" ""
            fi
        done
    done
}


##################################################
function localusersecurity()
{
    local username
    local home
    local hassshkey
    local shell
    local shadowline
    local haspw
    local pwage
    local pwageepoch
    local pwagedate
    local pwexpire
    local pwexpireepoch
    local pwexpiredate

    local IFS=$'\n'
    usercount=0
    for line in $(cat /etc/passwd)
    do 
        #IFS=':' passwd=($line)
        IFS=':' read -ra passwd <<< "$line"
        IFS=$'\n'
        username=${passwd[0]}
        home=${passwd[5]}
        if [[ -f "$home/.ssh/authorized_keys" ]]
        then
            hassshkey="yes"
        else
            hassshkey="no"
        fi
        shell=${passwd[6]}
        if [[ "$shell" == "/sbin/nologin" ]] \
        || [[ "$shell" == "/usr/sbin/nologin" ]] \
        || [[ "$shell" == "/bin/false" ]] \
        || [[ "$shell" == "/sbin/shutdown" ]] \
        || [[ "$shell" == "/sbin/halt" ]] \
        || [[ "$shell" == "/bin/sync" ]]
        then
            continue
        fi
    
        # DES is 13 chars, so match at least 13
        shadowline="$(egrep "^$username:" /etc/shadow)"
        #IFS=':' shadow=($shadowline)
        IFS=':' read -ra shadow <<< "$shadowline"
        IFS=$'\n'
        if [[ "${#shadow[1]}" -ge 13 ]]
        then 
            haspw="yes"
        else
            haspw="no"
        fi
    
        # probably a service account
        if [[ "$haspw" == "no" ]] \
        && [[ "$hassshkey" == "no" ]]
        then
            continue
        fi
        pwage=${shadow[2]}
        if [[ "x$pwage" == "x" ]]
        then
            pwage=0
        fi
        pwageepoch=$(( pwage * 86400 ))
        pwagedate=$(date --date="@$pwageepoch")
    
        pwexpire=${shadow[4]}
        if [[ "x$pwexpire" != "x" ]]
        then
            pwexpireepoch=$(( pwexpire * 86400 ))
            pwexpiredate=$(date --date="@$pwexpireepoch")
        else
            pwexpiredate=""
        fi
    
        echo "$LINEBANNER"
        echo "$username shell=$shell lastpasswd=\"$pwagedate\" haspw=\"$haspw\" hassshkey=\"$hassshkey\""
        ls -l $home/.ssh/* 2>/dev/null
        ls -l $home/*history 2>/dev/null
    done
}

##################################################
function getlast()
{
    last -wx
}

##################################################
function ausession()
{
    local session
    local file

    if ! which ausearch >/dev/null 2>&1
    then
        return 0
    fi

    for session in $(sort -u /proc/*/sessionid)
    do
        if [[ $session == 4294967295 ]]
        then
            continue
        fi

        echo "$BANNER"
        echo "session $session"
        ausearch -i --session $session
        echo "$BANNER"
    done
}

##################################################
function aureports()
{
    if ! which aureport >/dev/null 2>&1
    then
        return 0
    fi

    echo "$BANNER"
    echo "aureport -i -au"
    aureport -i -au
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -l"
    aureport -i -l
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i --tty"
    aureport -i --tty
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i --summary"
    aureport -i --summary
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -f |egrep -v ' execve | open '"
    aureport -i -f |egrep -v ' execve | open '
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i --integrity"
    aureport -i --integrity
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -n"
    aureport -i -n
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -r"
    aureport -i -r
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -m"
    aureport -i -m
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -ma"
    aureport -i -ma
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -c -nc"
    aureport -i -c -nc
    echo "$BANNER"

    echo "$BANNER"
    echo "aureport -i -a"
    aureport -i -a
    echo "$BANNER"
}

##################################################
function procinfo()
{
    local pid

    for pid in /proc/[0-9]*
    do
        echo "$BANNER"
        echo "$LINEBANNER"
        echo "$pid exe"
        ls -l $pid/exe
        echo "$LINEBANNER"
        echo "$pid cwd"
        ls -l $pid/cwd
        echo "$LINEBANNER"
        echo "$pid cmdline"
        cat $pid/cmdline |tr '\0' '\n' |uniq
        echo "$LINEBANNER"
        echo "$pid environ"
        cat $pid/environ |tr '\0' '\n' |uniq
        echo "$LINEBANNER"
        echo "$pid fd"
        ls -l $pid/fd/
        echo "$LINEBANNER"
        echo "$pid ns"
        ls -l $pid/ns/
        echo "$LINEBANNER"
        echo "$pid root"
        ls -l $pid/root
        echo "$LINEBANNER"
        echo "$pid sessionid"
        sort $pid/sessionid 
        echo "$LINEBANNER"
        echo "$pid loginuid"
        sort $pid/loginuid 
        echo "$BANNER"
    done
}


##################################################
function sctimers()
{
    echo "$LINEBANNER"
    systemctl list-timers --all
    echo "$LINEBANNER"
    ls -lah /run/systemd/transient/ /run/user/*/systemd/transient/
}

##################################################
function socketlist()
{
    local socket
    local pid
    local chroot
    local cmdline
    local user
    local line
    local state
    declare -a socket
    
    if which netstat >/dev/null 2>&1
    then
        local IFS=$'\n'
        for line in $(netstat -peanut|sort -rk 6| awk '{ if ($6 == "LISTEN" || $6 == "ESTABLISHED") print }' |sed -e 's/[[:space:]][[:space:]]*/ /g')
        do
            local IFS=' '
            #socket=($line)
            read -ra socket <<< "$line"
            pid=${socket[8]%/*}
            state=${socket[5]}
            chroot=$(cat /proc/"$pid"/cpuset)
            cmdline=$(tr '\0' ' ' < /proc/"$pid"/cmdline)
            user=$(id -nu "${socket[6]}")
            echo "$LINEBANNER"
            echo "$state ${socket[0]} LOCAL=${socket[3]} REMOTE=${socket[4]}"
            echo "UID=${socket[6]} USER=$user CHROOT=$chroot PID=$pid"
            echo "CMD=${cmdline}"
            printfileinfo "/proc/$pid/exe" "$user" "Process owner" ""
            ps -fwwwp $pid
            echo ''
        done
    elif which ss >/dev/null 2>&1
    then
        local IFS=$'\n'
        for line in $(ss -n -l -p -ut|awk '{ if ($2 == "LISTEN" || $2 == "UNCONN") print }' |sed -e 's/[[:space:]][[:space:]]*/ /g')
        do
            local IFS=' '
            #socket=($line)
            read -ra socket <<< "$line"
            pid=$(echo "${socket[6]}" |sed -e 's/.*,pid=\([[:digit:]]*\),.*/\1/')
            chroot=$(cat /proc/"$pid"/cpuset)
            cmdline=$(tr '\0' ' ' < /proc/"$pid"/cmdline)
            uid=$(stat -c '%u' /proc/"$pid")
            user=$(id -nu "$uid")
            echo "$LINEBANNER"
            echo "$state ${socket[1]} LOCAL=${socket[4]} REMOTE=${socket[5]}"
            echo "UID=$uid USER=$user CHROOT=$chroot PID=$pid"
            echo "CMD=${cmdline}"
            printfileinfo "/proc/$pid/exe" "$user" "Process owner" ""
            ps -fwwwp $pid
        done
    fi
    
}



MAIN
