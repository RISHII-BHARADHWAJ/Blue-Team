#!/bin/bash

> fulllogs.log

CURRENT_DATE=$(date "+%b %d")

# Function to get random timestamp
get_time() {
    printf "%02d:%02d:%02d" $((RANDOM%24)) $((RANDOM%60)) $((RANDOM%60))
}

# 1. PROCESS LINUX (Mix of Info, Low, High) - Multiply 5x
if [ -f temp_linux.log ]; then
    for i in {1..5}; do
        awk -v d="$CURRENT_DATE" 'BEGIN{
            srand();
            hosts[0]="web-01"; hosts[1]="web-02"; hosts[2]="db-01"; hosts[3]="app-srv-01"; hosts[4]="mail-01";
            len=5;
        } {
            h=int(rand()*24); m=int(rand()*60); s=int(rand()*60);
            t=sprintf("%02d:%02d:%02d", h, m, s);
            
            # Pick random host
            host_idx = int(rand()*len);
            host = hosts[host_idx];

            # Inject diversity
            r=rand();
            if (r < 0.1) line = "warning: disk space low on /var/log";
            else if (r < 0.3) line = "session opened for user root"; 
            else line = $0;

            print d " " t " " host " systemd: " line;
        }' temp_linux.log | sed 's/  / /g' >> fulllogs.log
    done
fi

# 2. PROCESS SSH (High Volume Auth Failures) - Multiply 5x
if [ -f temp_openssh.log ]; then
    for i in {1..5}; do
        awk -v d="$CURRENT_DATE" 'BEGIN{
            srand();
            hosts[0]="gateway-01"; hosts[1]="bastion-01"; hosts[2]="web-01"; hosts[3]="db-02";
            len=4;
        } {
            h=int(rand()*24); m=int(rand()*60); s=int(rand()*60);
            t=sprintf("%02d:%02d:%02d", h, m, s);
            
            # Pick random host
            host_idx = int(rand()*len);
            host = hosts[host_idx];
            
            # Extract process/pid from original if possible, or just append
            print d " " t " " host " sshd[1234]: " $0;
        }' temp_openssh.log | sed 's/  / /g' >> fulllogs.log
    done
fi

# 3. PROCESS APACHE (Web Traffic & Errors) - Multiply 5x
if [ -f temp_apache.log ]; then
    for i in {1..5}; do
        awk -v d="$CURRENT_DATE" 'BEGIN{
            srand();
            hosts[0]="web-01"; hosts[1]="web-02"; hosts[2]="web-03"; hosts[3]="api-gateway";
            len=4;
        } {
            h=int(rand()*24); m=int(rand()*60); s=int(rand()*60);
            t=sprintf("%02d:%02d:%02d", h, m, s);
            
            # Pick random host
            host_idx = int(rand()*len);
            host = hosts[host_idx];

            # Inject [error] explicitly sometimes
            r=rand();
            if (r < 0.2) level = "[error]";
            else level = "[notice]";
            
            msg = "";
            for (i=7; i<=NF; i++) msg = msg " " $i;
            
            print d " " t " " host " httpd" level ": " msg;
        }' temp_apache.log | sed 's/  / /g' >> fulllogs.log
    done
fi

# 4. SYNTHETIC ATTACKS (Critical/High)
# Generate 1000 random attack logs for more volume
HOSTS=("firewall-01" "firewall-02" "waf-01" "ids-01" "web-01" "web-LB")
for i in {1..1000}; do
    T=$(get_time)
    
    # Pick random host
    RAND_HOST=${HOSTS[$RANDOM % ${#HOSTS[@]}]}
    
    R=$((RANDOM%6))
    case $R in
        0) MSG="CMD injection detected: cmd.exe /c dir in GET request from 203.0.113.$((RANDOM%255))" ;;
        1) MSG="SQL Injection attempt: UNION SELECT * FROM users from 198.51.100.$((RANDOM%255))" ;;
        2) MSG="XSS Payload detected: <script>alert(1)</script> in POST body from 192.0.2.$((RANDOM%255))" ;;
        3) MSG="RCE Attempt: uname -a executed by www-data" ;;
        4) MSG="SSTI Attempt: {{7*7}} payload found in template parameter" ;;
        5) MSG="LFI Detected: GET /vulnerable.php?page=../../../../etc/passwd" ;;
    esac
    echo "$CURRENT_DATE $T $RAND_HOST waf: ALERT $MSG" >> fulllogs.log
done

# Shuffle
shuf fulllogs.log -o fulllogs.log
echo "Enriched logs generated with diverse hosts."
