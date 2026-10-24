#!/system/bin/sh

# Logging control
LOG=false
LOG_FILE=/data/adb/tether_unblock/log.txt

log_msg() {
    [ "$LOG" = "true" ] && echo "$1" >> "$LOG_FILE"
}

# shellcheck disable=SC2034
MODDIR=${0%/*}

# 1. Disable tethering detection properties
resetprop tether_dun_required 0
resetprop net.tethering.noprovisioning true
resetprop tether_entitlement_check_state 0

# 2. Wait for boot
until [ "$(getprop sys.boot_completed)" = 1 ]; do
    sleep 1
done

# 3. Grace period so upstream (rmnet/wlan) is up
sleep 5

HAS_IPTABLES=false
HAS_IP6TABLES=false
HAS_IP=false
[ -x "$(command -v iptables)" ] && HAS_IPTABLES=true
[ -x "$(command -v ip6tables)" ] && HAS_IP6TABLES=true
[ -x "$(command -v ip)" ] && HAS_IP=true

log_msg "start $(date)"

# 4. Candidate interfaces (broad list)
# Includes upstream names (wlan0, ccmni*) — they will be filtered out below.
IFACES="ap0 ap1 ap2 softap0 swlan0 rndis0 wlan0 wlan1 wlan2 wlan3 \
rndis1 usb0 usb1 ncm0 ncm1 ncm2 ncm3 eth0 eth1 bt-pan bnep0 bnep1 ccmni-lan"

# ============================================================
# 5. Detect upstream interfaces dynamically
# ============================================================
detect_upstream() {
    UL=""

    # IPv4 default route
    U4=$(ip route get 8.8.8.8 2>/dev/null \
        | grep -o "dev [^ ]*" | cut -d' ' -f2 | head -n 1)
    [ -n "$U4" ] && UL="$UL $U4"

    # IPv6 default route
    U6=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null \
        | grep -o "dev [^ ]*" | cut -d' ' -f2 | head -n 1)
    [ -n "$U6" ] && UL="$UL $U6"

    # All default routes across all tables (Android per-network tables)
    UALL=$(ip route show table all 2>/dev/null \
        | awk '/^default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' \
        | sort -u)
    for u in $UALL; do UL="$UL $u"; done

    # Cellular interfaces that are UP (MediaTek/Qualcomm) — glob instead of ls|grep
    for path in /sys/class/net/ccmni* /sys/class/net/rmnet*; do
        [ -e "$path" ] || continue
        i=${path##*/}
        st=$(cat "/sys/class/net/$i/operstate" 2>/dev/null)
        case "$st" in
            up|unknown) UL="$UL $i" ;;
        esac
    done

    # Deduplicate
    echo "$UL" | tr ' ' '\n' | sort -u | tr '\n' ' '
}

if $HAS_IP; then
    UPSTREAM=$(detect_upstream)
    log_msg "upstream: $UPSTREAM"

    # Retry once if nothing found (network may not be ready yet)
    if [ -z "$(echo "$UPSTREAM" | tr -d ' ')" ]; then
        sleep 30
        UPSTREAM=$(detect_upstream)
        log_msg "upstream (retry): $UPSTREAM"
    fi
else
    UPSTREAM=""
fi

# ============================================================
# 6. Filter IFACES: drop anything that is upstream
# ============================================================
FILTERED=""
for i in $IFACES; do
    case " $UPSTREAM " in
        *" $i "*)
            log_msg "skip upstream: $i"
            continue
            ;;
    esac
    FILTERED="$FILTERED $i"
done
IFACES="${FILTERED# }"

# If no upstream detected, restrict to confirmed-safe interfaces
if [ -z "$(echo "$UPSTREAM" | tr -d ' ')" ]; then
    IFACES="ap0 rndis0"
    log_msg "no upstream — fallback IFACES: $IFACES"
fi
log_msg "final IFACES: $IFACES"

# ============================================================
# 7. TTL/HL fix (masks hop count difference)
#    Idempotent: check rule exists before adding.
# ============================================================
for IFACE in $IFACES; do
    if $HAS_IPTABLES; then
        iptables -t mangle -C PREROUTING -i "$IFACE" -j TTL --ttl-inc 1 2>/dev/null \
            || iptables -t mangle -A PREROUTING -i "$IFACE" -j TTL --ttl-inc 1 2>/dev/null
        iptables -t mangle -C POSTROUTING -o "$IFACE" -j TTL --ttl-inc 1 2>/dev/null \
            || iptables -t mangle -I POSTROUTING -o "$IFACE" -j TTL --ttl-inc 1 2>/dev/null
    fi

    if $HAS_IP6TABLES; then
        ip6tables -t mangle -C PREROUTING ! -p icmpv6 -i "$IFACE" -j HL --hl-inc 1 2>/dev/null \
            || ip6tables -t mangle -A PREROUTING ! -p icmpv6 -i "$IFACE" -j HL --hl-inc 1 2>/dev/null
        ip6tables -t mangle -C POSTROUTING ! -p icmpv6 -o "$IFACE" -j HL --hl-inc 1 2>/dev/null \
            || ip6tables -t mangle -I POSTROUTING ! -p icmpv6 -o "$IFACE" -j HL --hl-inc 1 2>/dev/null
    fi
done

# Fallback if kernel lacks TTL/HL targets
if $HAS_IPTABLES && ! iptables -j TTL -h >/dev/null 2>&1; then
    echo 64 > /proc/sys/net/ipv4/ip_default_ttl 2>/dev/null
    log_msg "fallback: ip_default_ttl=64"
fi
if $HAS_IP6TABLES && ! ip6tables -j HL -h >/dev/null 2>&1; then
    echo 64 > /proc/sys/net/ipv6/conf/all/hop_limit 2>/dev/null
    log_msg "fallback: hop_limit=64"
fi

# ============================================================
# 8. Policy routing bypass (priority 5000), IPv4 + IPv6
# ============================================================
if $HAS_IP; then
    # IPv4
    ROUTE4=$(ip route get 8.8.8.8 2>/dev/null)
    UP4=$(echo "$ROUTE4" | grep -o "dev [^ ]*" | cut -d' ' -f2 | head -n 1)
    T4=$(echo "$ROUTE4" | grep -o "table [^ ]*" | cut -d' ' -f2 | head -n 1)
    [ -z "$T4" ] && T4="$UP4"

    if [ -n "$UP4" ] && [ -n "$T4" ]; then
        log_msg "IPv4 upstream: dev=$UP4 table=$T4"
        for IFACE in $IFACES; do
            ip rule del from all iif "$IFACE" lookup "$T4" priority 5000 2>/dev/null
            ip rule add from all iif "$IFACE" lookup "$T4" priority 5000 2>/dev/null \
                && log_msg "rule4 add ok: $IFACE -> $T4" \
                || log_msg "rule4 add FAIL: $IFACE -> $T4"
        done
    fi

    # IPv6
    ROUTE6=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null)
    UP6=$(echo "$ROUTE6" | grep -o "dev [^ ]*" | cut -d' ' -f2 | head -n 1)
    T6=$(echo "$ROUTE6" | grep -o "table [^ ]*" | cut -d' ' -f2 | head -n 1)
    [ -z "$T6" ] && T6="$UP6"

    if [ -n "$UP6" ] && [ -n "$T6" ]; then
        log_msg "IPv6 upstream: dev=$UP6 table=$T6"
        for IFACE in $IFACES; do
            ip -6 rule del from all iif "$IFACE" lookup "$T6" priority 5000 2>/dev/null
            ip -6 rule add from all iif "$IFACE" lookup "$T6" priority 5000 2>/dev/null \
                && log_msg "rule6 add ok: $IFACE -> $T6" \
                || log_msg "rule6 add FAIL: $IFACE -> $T6"
        done
    fi
fi

log_msg "done $(date)"
