#!/bin/bash
# ============================================================
#  CIS + Cyber Essentials + CE+ + NCSC + MDM + UK MoD DCC
#  macOS Workstation Security Auditor
#  Author: Peter Bassill | OTY Heavy Industries
# ------------------------------------------------------------
#  macOS counterpart to audit.ps1 (Windows Workstation Audit).
#  Performs a comprehensive local macOS security audit covering:
#    - CIS Apple macOS Benchmark Level 1 & Level 2 (aligned)
#    - Cyber Essentials (CE) controls
#    - Cyber Essentials Plus (CE+) additional controls
#    - NCSC alignment recommendations
#    - MDM / Device Management posture (Jamf, Intune, Kandji, etc.)
#    - UK MoD Defence Cyber Certification Level 2 & 3
#
#  The script is MDM-aware. When a device is detected as MDM
#  enrolled, controls natively managed by the MDM (e.g. password
#  policy, FileVault escrow, configuration profiles) are noted so
#  that cloud-managed controls do not generate false FAILs against
#  local policy baselines.
#
#  Zero external dependencies: uses only tools shipped with macOS
#  (defaults, fdesetup, spctl, csrutil, socketfilterfw, pmset,
#   system_profiler, sw_vers, scutil, dscl, pwpolicy, profiles,
#   softwareupdate, launchctl, sysctl, tmutil, nvram).
#
#  Outputs: colour console summary + .txt, .csv, .json, .html
#  reports and a CycloneDX .json SBOM, written next to the script.
#
#  USAGE:
#    sudo ./audit-macos.sh [--audit <scope>] [--previous-report <file.json>]
#
#    --audit scope : all (default) | ce | cis1 | cis2 | ncsc | mdm | dcc2 | dcc3
#    --previous-report <file> : prior JSON export for delta/trend comparison
#
#  Run with sudo for full coverage; many checks require root.
# ============================================================

set -u

ScriptVersion="7.0.0"

# ------------------------------------------------------------
#  ARGUMENT PARSING
# ------------------------------------------------------------
AuditScope="all"
PreviousReport=""

while [ $# -gt 0 ]; do
    case "$1" in
        --audit)
            AuditScope="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
            shift 2 ;;
        --audit=*)
            AuditScope="$(printf '%s' "${1#*=}" | tr '[:upper:]' '[:lower:]')"
            shift ;;
        --previous-report)
            PreviousReport="$2"; shift 2 ;;
        --previous-report=*)
            PreviousReport="${1#*=}"; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,40p'
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Use --help for usage." >&2
            exit 2 ;;
    esac
done

case "$AuditScope" in
    all|ce|cis1|cis2|ncsc|mdm|dcc2|dcc3) ;;
    *) echo "Invalid --audit value: $AuditScope" >&2; exit 2 ;;
esac

# Map audit scope to the framework tag that must match (empty = all)
FrameworkFilter=""
AuditLabel="Full audit (all frameworks)"
case "$AuditScope" in
    ce)    FrameworkFilter="CE+";    AuditLabel="Cyber Essentials / CE+ only" ;;
    cis1)  FrameworkFilter="CIS";    AuditLabel="CIS Level 1 only" ;;
    cis2)  FrameworkFilter="CIS-L2"; AuditLabel="CIS Level 2 only" ;;
    ncsc)  FrameworkFilter="NCSC";   AuditLabel="NCSC alignment only" ;;
    mdm)   FrameworkFilter="MDM";    AuditLabel="MDM / Device Management only" ;;
    dcc2)  FrameworkFilter="DCC-L2"; AuditLabel="UK MoD DCC Level 2 only" ;;
    dcc3)  FrameworkFilter="DCC-L3"; AuditLabel="UK MoD DCC Level 3 only" ;;
esac

# ------------------------------------------------------------
#  INITIALISATION
# ------------------------------------------------------------
Timestamp="$(date +%Y-%m-%d_%H-%M-%S)"
MachineName="$(scutil --get ComputerName 2>/dev/null || hostname -s)"
SafeName="$(printf '%s' "$MachineName" | tr ' /:' '___')"
ScriptDir="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
ReportPath="$ScriptDir/${SafeName}_Audit_$Timestamp.txt"
CsvPath="$ScriptDir/${SafeName}_Audit_$Timestamp.csv"
JsonPath="$ScriptDir/${SafeName}_Audit_$Timestamp.json"
HtmlPath="$ScriptDir/${SafeName}_Audit_$Timestamp.html"
SbomPath="$ScriptDir/${SafeName}_SBOM_$Timestamp.json"
AuditStartEpoch="$(date +%s)"

# Console colours (only when stdout is a terminal)
if [ -t 1 ]; then
    C_RESET="$(printf '\033[0m')"; C_RED="$(printf '\033[31m')"
    C_GREEN="$(printf '\033[32m')"; C_YELLOW="$(printf '\033[33m')"
    C_CYAN="$(printf '\033[36m')"; C_WHITE="$(printf '\033[37m')"
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_WHITE=""
fi

# Parallel result arrays (bash 3.2 compatible - no associative arrays)
R_ID=(); R_DESC=(); R_STATUS=(); R_DETAIL=(); R_FW=(); R_SEV=(); R_REM=()

IsRoot=0
[ "$(id -u)" -eq 0 ] && IsRoot=1

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

# Severity weighting for the weighted compliance score
severity_weight() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        critical) echo 3 ;;
        high)     echo 2 ;;
        *)        echo 1 ;;
    esac
}

# JSON string escaper
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s///\\t}"
    # carriage returns / newlines
    s="$(printf '%s' "$s" | awk 'BEGIN{ORS=""} {gsub(/\r/,""); print}')"
    printf '%s' "$s"
}

# HTML string escaper
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}

# CSV field escaper (always quote, double embedded quotes)
csv_escape() {
    local s="$1"
    s="${s//\"/\"\"}"
    printf '"%s"' "$s"
}

# Render a textual progress bar of a percentage (0-100), width 20
progress_bar() {
    local pct="$1" width=20 i filled empty out=""
    [ -z "$pct" ] && pct=0
    filled=$(( pct * width / 100 ))
    [ "$filled" -gt "$width" ] && filled=$width
    [ "$filled" -lt 0 ] && filled=0
    empty=$(( width - filled ))
    i=0; while [ "$i" -lt "$filled" ]; do out="$out#"; i=$((i+1)); done
    i=0; while [ "$i" -lt "$empty" ];  do out="$out-"; i=$((i+1)); done
    printf '[%s]' "$out"
}

# Map an integer score (0-100) to a risk rating word
risk_rating() {
    local s="$1"
    if   [ "$s" -ge 90 ]; then echo "LOW"
    elif [ "$s" -ge 75 ]; then echo "MODERATE"
    elif [ "$s" -ge 50 ]; then echo "HIGH"
    else echo "CRITICAL"; fi
}

# Integer percentage helper: pct numerator denominator
pct() {
    local n="$1" d="$2"
    [ "$d" -le 0 ] && { echo 0; return; }
    echo $(( n * 100 / d ))
}

# Read a defaults value, returning empty string if missing.
# usage: read_default <domain> <key>  OR  read_default -app <path> <key>
read_default() {
    defaults read "$@" 2>/dev/null
}

# Read a defaults value from a specific plist host file as root if possible
read_default_host() {
    # $1 = plist path, $2 = key
    if [ -f "$1" ]; then
        defaults read "$1" "$2" 2>/dev/null
    fi
}

# Append a line to the text report and (if tty) print coloured to console
emit() {
    printf '%s\n' "$1" >> "$ReportPath"
    printf '%s\n' "$1"
}

# Section header
section() {
    local title="$1"
    {
        printf '\n'
        printf '============================================================\n'
        printf '  %s\n' "$title"
        printf '============================================================\n'
    } >> "$ReportPath"
    printf '\n%s============================================================%s\n' "$C_CYAN" "$C_RESET"
    printf '%s  %s%s\n' "$C_CYAN" "$title" "$C_RESET"
    printf '%s============================================================%s\n' "$C_CYAN" "$C_RESET"
}

# Determine whether a framework tag is in scope for this run
in_scope() {
    [ -z "$FrameworkFilter" ] && return 0
    case " $1 " in
        *" $FrameworkFilter "*) return 0 ;;
        *) return 1 ;;
    esac
}

# Record a result.
# add_result <id> <description> <status> <detail> <frameworks> <severity> <remediation>
#   status: PASS | FAIL | WARN | INFO
#   frameworks: space separated list of tags (CIS CIS-L2 CE+ NCSC MDM DCC-L2 DCC-L3)
add_result() {
    local id="$1" desc="$2" status="$3" detail="$4" fw="$5" sev="${6:-Medium}" rem="${7:-}"

    # Scope filter: skip results that have no framework in the selected scope.
    if [ -n "$FrameworkFilter" ]; then
        in_scope "$fw" || return 0
    fi

    R_ID+=("$id"); R_DESC+=("$desc"); R_STATUS+=("$status")
    R_DETAIL+=("$detail"); R_FW+=("$fw"); R_SEV+=("$sev"); R_REM+=("$rem")

    local colour="$C_WHITE" tag="$status"
    case "$status" in
        PASS) colour="$C_GREEN" ;;
        FAIL) colour="$C_RED" ;;
        WARN) colour="$C_YELLOW" ;;
        INFO) colour="$C_CYAN" ;;
    esac

    printf '[%s] %s - %s\n' "$status" "$id" "$desc" >> "$ReportPath"
    [ -n "$detail" ] && printf '        %s\n' "$detail" >> "$ReportPath"
    printf '%s[%s]%s %s - %s\n' "$colour" "$tag" "$C_RESET" "$id" "$desc"
    [ -n "$detail" ] && printf '        %s%s%s\n' "$C_WHITE" "$detail" "$C_RESET"
}

# ============================================================
#  BANNER & DEVICE CONTEXT
# ============================================================
: > "$ReportPath"

print_banner() {
    local line
    {
        printf '############################################################\n'
        printf '#  macOS Workstation Security Auditor v%s\n' "$ScriptVersion"
        printf '#  CIS / Cyber Essentials / CE+ / NCSC / MDM / UK MoD DCC\n'
        printf '#  OTY Heavy Industries\n'
        printf '############################################################\n'
    } >> "$ReportPath"
    printf '%s############################################################%s\n' "$C_CYAN" "$C_RESET"
    printf '%s#  macOS Workstation Security Auditor v%s%s\n' "$C_CYAN" "$ScriptVersion" "$C_RESET"
    printf '%s#  CIS / Cyber Essentials / CE+ / NCSC / MDM / UK MoD DCC%s\n' "$C_CYAN" "$C_RESET"
    printf '%s#  OTY Heavy Industries%s\n' "$C_CYAN" "$C_RESET"
    printf '%s############################################################%s\n' "$C_CYAN" "$C_RESET"
    line="Scope: $AuditLabel"
    emit "$line"
    if [ "$IsRoot" -ne 1 ]; then
        emit "WARNING: Not running as root. Some checks will be limited. Re-run with sudo for full coverage."
    fi
}
print_banner

# Gather device context up front
OS_NAME="$(sw_vers -productName 2>/dev/null)"
OS_VER="$(sw_vers -productVersion 2>/dev/null)"
OS_BUILD="$(sw_vers -buildVersion 2>/dev/null)"
HW_MODEL="$(sysctl -n hw.model 2>/dev/null)"
CPU_BRAND="$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
ARCH="$(uname -m 2>/dev/null)"
SERIAL="$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number/{print $2; exit}')"
CURRENT_USER="$(stat -f%Su /dev/console 2>/dev/null)"
[ -z "$CURRENT_USER" ] && CURRENT_USER="$(whoami)"

# Apple Silicon vs Intel
IS_APPLE_SILICON=0
case "$ARCH" in arm64) IS_APPLE_SILICON=1 ;; esac

# ------------------------------------------------------------
#  MDM ENROLMENT DETECTION (informs cloud-managed awareness)
# ------------------------------------------------------------
MDM_ENROLLED=0
MDM_VENDOR=""
profiles_out="$(profiles status -type enrollment 2>/dev/null)"
case "$profiles_out" in
    *"MDM enrollment: Yes"*) MDM_ENROLLED=1 ;;
    *"Enrolled via DEP: Yes"*) MDM_ENROLLED=1 ;;
esac
# Identify common MDM agents
if [ -d "/Library/Application Support/JAMF" ] || command -v jamf >/dev/null 2>&1; then
    MDM_VENDOR="Jamf"; MDM_ENROLLED=1
elif [ -d "/Library/Intune" ] || [ -d "/Library/Application Support/Microsoft/Intune" ]; then
    MDM_VENDOR="Microsoft Intune"; MDM_ENROLLED=1
elif [ -d "/Library/Kandji" ]; then
    MDM_VENDOR="Kandji"; MDM_ENROLLED=1
fi

# ============================================================
#  DEVICE CONTEXT (informational)
# ============================================================
section "Device Context"
add_result "DEV-001" "Operating system" "INFO" "$OS_NAME $OS_VER (build $OS_BUILD)" "CIS" "Medium" ""
add_result "DEV-002" "Hardware model" "INFO" "$HW_MODEL / $CPU_BRAND ($ARCH)" "CIS" "Medium" ""
add_result "DEV-003" "Serial number" "INFO" "${SERIAL:-unknown}" "CIS" "Medium" ""
add_result "DEV-004" "Console user" "INFO" "$CURRENT_USER" "CIS" "Medium" ""
if [ "$MDM_ENROLLED" -eq 1 ]; then
    add_result "DEV-005" "MDM enrolment" "INFO" "Device is MDM enrolled${MDM_VENDOR:+ ($MDM_VENDOR)}. Cloud-managed controls are noted accordingly." "MDM" "Medium" ""
else
    add_result "DEV-005" "MDM enrolment" "INFO" "Device is not MDM enrolled. Local policy baselines apply." "MDM" "Medium" ""
fi

# ============================================================
#  1. DISK ENCRYPTION (FileVault)
# ============================================================
section "Disk Encryption (FileVault)"
fv_status="$(fdesetup status 2>/dev/null)"
case "$fv_status" in
    *"FileVault is On"*)
        add_result "FV-001" "FileVault full-disk encryption enabled" "PASS" "$fv_status" "CIS CE+ NCSC DCC-L2 DCC-L3" "Critical" "" ;;
    *"FileVault is Off"*)
        add_result "FV-001" "FileVault full-disk encryption enabled" "FAIL" "FileVault is Off - the system disk is not encrypted." "CIS CE+ NCSC DCC-L2 DCC-L3" "Critical" "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On, or 'sudo fdesetup enable'." ;;
    *)
        add_result "FV-001" "FileVault full-disk encryption enabled" "WARN" "Unable to determine FileVault status (root required)." "CIS CE+ NCSC DCC-L2 DCC-L3" "Critical" "Run with sudo to confirm FileVault status." ;;
esac

# Escrow / institutional recovery key (relevant when MDM managed)
if [ "$MDM_ENROLLED" -eq 1 ]; then
    add_result "FV-002" "FileVault recovery key escrow" "INFO" "Managed by MDM ($MDM_VENDOR). Verify key escrow in the MDM console." "MDM DCC-L3" "High" ""
else
    add_result "FV-002" "FileVault recovery key escrow" "WARN" "No MDM detected; ensure the FileVault recovery key is securely stored offline." "DCC-L3" "High" "Store the personal recovery key in a secure password manager or escrow it via MDM."
fi

# ============================================================
#  2. SYSTEM INTEGRITY PROTECTION (SIP)
# ============================================================
section "System Integrity Protection (SIP)"
sip_status="$(csrutil status 2>/dev/null)"
case "$sip_status" in
    *"enabled"*)
        add_result "SIP-001" "System Integrity Protection enabled" "PASS" "$sip_status" "CIS NCSC DCC-L2 DCC-L3" "Critical" "" ;;
    *"disabled"*)
        add_result "SIP-001" "System Integrity Protection enabled" "FAIL" "SIP is disabled - core OS protections are off." "CIS NCSC DCC-L2 DCC-L3" "Critical" "Re-enable SIP from Recovery: boot to Recovery, open Terminal, run 'csrutil enable', reboot." ;;
    *)
        add_result "SIP-001" "System Integrity Protection enabled" "WARN" "Unable to determine SIP status." "CIS NCSC DCC-L2 DCC-L3" "Critical" "Verify SIP with 'csrutil status'." ;;
esac

# ============================================================
#  3. GATEKEEPER & APPLICATION CONTROL
# ============================================================
section "Gatekeeper & Application Control"
gk_status="$(spctl --status 2>/dev/null)"
case "$gk_status" in
    *"assessments enabled"*)
        add_result "GK-001" "Gatekeeper assessments enabled" "PASS" "Gatekeeper is enabled - only signed/notarised apps run by default." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "" ;;
    *"assessments disabled"*)
        add_result "GK-001" "Gatekeeper assessments enabled" "FAIL" "Gatekeeper is disabled - unsigned applications may run." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Enable Gatekeeper: 'sudo spctl --master-enable'." ;;
    *)
        add_result "GK-001" "Gatekeeper assessments enabled" "WARN" "Unable to determine Gatekeeper status." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify with 'spctl --status'." ;;
esac

# ============================================================
#  4. MALWARE PROTECTION (XProtect / MRT / Notarisation)
# ============================================================
section "Malware Protection (XProtect)"
xprotect_ver="$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
[ -z "$xprotect_ver" ] && xprotect_ver="$(defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
if [ -n "$xprotect_ver" ]; then
    add_result "MAL-001" "XProtect anti-malware present" "PASS" "XProtect signature bundle version $xprotect_ver." "CIS CE+ NCSC DCC-L2" "High" ""
else
    add_result "MAL-001" "XProtect anti-malware present" "WARN" "Unable to read XProtect version." "CIS CE+ NCSC DCC-L2" "High" "Ensure system software/security updates are current ('softwareupdate -l')."
fi
# Automatic security updates feed for XProtect/MRT config data
cfgdata="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null)"
if [ "$cfgdata" = "1" ]; then
    add_result "MAL-002" "Automatic security configuration-data updates" "PASS" "ConfigDataInstall enabled (XProtect/MRT auto-update)." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
elif [ "$cfgdata" = "0" ]; then
    add_result "MAL-002" "Automatic security configuration-data updates" "FAIL" "ConfigDataInstall disabled - XProtect/MRT data will not auto-update." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Enable: System Settings > General > Software Update > Automatic Updates > Install Security Responses and system files."
else
    add_result "MAL-002" "Automatic security configuration-data updates" "WARN" "Unable to determine ConfigDataInstall setting." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify automatic security responses are enabled."
fi

# ============================================================
#  5. APPLICATION FIREWALL
# ============================================================
section "Application Firewall"
FW="/usr/libexec/ApplicationFirewall/socketfilterfw"
if [ -x "$FW" ]; then
    fw_global="$("$FW" --getglobalstate 2>/dev/null)"
    fw_stealth="$("$FW" --getstealthmode 2>/dev/null)"
    fw_signed="$("$FW" --getallowsigned 2>/dev/null)"
    case "$fw_global" in
        *"enabled"*) add_result "FW-001" "Application firewall enabled" "PASS" "$fw_global" "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "" ;;
        *"disabled"*) add_result "FW-001" "Application firewall enabled" "FAIL" "The application firewall is disabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Enable: 'sudo $FW --setglobalstate on' or System Settings > Network > Firewall." ;;
        *) add_result "FW-001" "Application firewall enabled" "WARN" "Unable to determine firewall state (root may be required)." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Run with sudo to query firewall state." ;;
    esac
    case "$fw_stealth" in
        *"enabled"*) add_result "FW-002" "Firewall stealth mode enabled" "PASS" "$fw_stealth" "CIS-L2 NCSC DCC-L3" "Medium" "" ;;
        *"disabled"*) add_result "FW-002" "Firewall stealth mode enabled" "WARN" "Stealth mode disabled - host responds to probes (e.g. ICMP)." "CIS-L2 NCSC DCC-L3" "Medium" "Enable: 'sudo $FW --setstealthmode on'." ;;
        *) add_result "FW-002" "Firewall stealth mode enabled" "WARN" "Unable to determine stealth mode." "CIS-L2 NCSC DCC-L3" "Medium" "Run with sudo to query stealth mode." ;;
    esac
else
    add_result "FW-001" "Application firewall enabled" "WARN" "socketfilterfw not found." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify firewall configuration manually."
fi

# ============================================================
#  6. SOFTWARE UPDATES & PATCHING
# ============================================================
section "Software Updates & Patching"
SU="/Library/Preferences/com.apple.SoftwareUpdate"
au_check="$(defaults read "$SU" AutomaticCheckEnabled 2>/dev/null)"
au_down="$(defaults read "$SU" AutomaticDownload 2>/dev/null)"
au_osinstall="$(defaults read "$SU" AutomaticallyInstallMacOSUpdates 2>/dev/null)"
au_appinstall="$(defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>/dev/null)"
crit_install="$(defaults read "$SU" CriticalUpdateInstall 2>/dev/null)"

if [ "$au_check" = "1" ]; then
    add_result "UPD-001" "Automatically check for updates" "PASS" "AutomaticCheckEnabled is on." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
elif [ "$au_check" = "0" ]; then
    add_result "UPD-001" "Automatically check for updates" "FAIL" "Automatic update checking is disabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Enable automatic update checks in System Settings > General > Software Update."
else
    add_result "UPD-001" "Automatically check for updates" "WARN" "Setting not determinable." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify automatic update checking is enabled."
fi
if [ "$au_down" = "1" ]; then
    add_result "UPD-002" "Automatically download updates" "PASS" "AutomaticDownload is on." "CIS CE+ DCC-L2 DCC-L3" "Medium" ""
else
    add_result "UPD-002" "Automatically download updates" "WARN" "Automatic download of updates is not enabled." "CIS CE+ DCC-L2 DCC-L3" "Medium" "Enable automatic download of updates."
fi
if [ "$crit_install" = "1" ]; then
    add_result "UPD-003" "Install security responses & system files" "PASS" "CriticalUpdateInstall is on." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
else
    add_result "UPD-003" "Install security responses & system files" "FAIL" "Critical/security updates are not auto-installed." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Enable 'Install Security Responses and system files'."
fi
if [ "$au_osinstall" = "1" ]; then
    add_result "UPD-004" "Automatically install macOS updates" "PASS" "AutomaticallyInstallMacOSUpdates is on." "CIS-L2 DCC-L3" "Medium" ""
else
    add_result "UPD-004" "Automatically install macOS updates" "WARN" "macOS updates are not installed automatically." "CIS-L2 DCC-L3" "Medium" "Consider enabling automatic install of macOS updates (or manage via MDM)."
fi
if [ "$au_appinstall" = "1" ]; then
    add_result "UPD-005" "Automatically install App Store app updates" "PASS" "Commerce AutoUpdate is on." "CIS CE+ DCC-L2" "Medium" ""
else
    add_result "UPD-005" "Automatically install App Store app updates" "WARN" "App Store apps are not updated automatically." "CIS CE+ DCC-L2" "Medium" "Enable automatic app updates in App Store settings."
fi

# ============================================================
#  7. PASSWORD POLICY
# ============================================================
section "Password Policy"
if [ "$MDM_ENROLLED" -eq 1 ]; then
    add_result "PWD-000" "Password policy source" "INFO" "Device is MDM enrolled; password policy may be enforced via configuration profile ($MDM_VENDOR)." "MDM" "Medium" ""
fi
pwpolicy_out="$(pwpolicy -getaccountpolicies 2>/dev/null | sed '1d')"
min_len="$(printf '%s' "$pwpolicy_out" | grep -o 'policyAttributePassword matches.*{[0-9]*,}' | grep -o '{[0-9]*,}' | grep -o '[0-9]*' | head -n1)"
if [ -z "$min_len" ]; then
    min_len="$(printf '%s' "$pwpolicy_out" | grep -A2 minimumLength | grep -o '[0-9]\+' | head -n1)"
fi
if [ -n "$min_len" ] && [ "$min_len" -ge 8 ] 2>/dev/null; then
    add_result "PWD-001" "Minimum password length >= 8" "PASS" "Minimum length is $min_len." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
elif [ -n "$min_len" ]; then
    add_result "PWD-001" "Minimum password length >= 8" "FAIL" "Minimum length is $min_len (below 8)." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Set a minimum password length of at least 8 (12+ recommended) via profile or pwpolicy."
else
    add_result "PWD-001" "Minimum password length >= 8" "WARN" "No local minimum password length policy detected." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Define a minimum password length policy (>=8) via configuration profile or pwpolicy."
fi

# ============================================================
#  8. SCREEN LOCK & SCREEN SAVER
# ============================================================
section "Screen Lock & Idle Timeout"
ask_pw="$(defaults read com.apple.screensaver askForPassword 2>/dev/null)"
ask_delay="$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)"
idle_time="$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null)"
if [ "$ask_pw" = "1" ]; then
    add_result "LCK-001" "Require password after sleep/screen saver" "PASS" "askForPassword is enabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
else
    add_result "LCK-001" "Require password after sleep/screen saver" "WARN" "Password is not required after sleep/screen saver (or managed by profile)." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Enable 'Require password after sleep or screen saver begins'."
fi
if [ -n "$ask_delay" ] && [ "$ask_delay" -le 5 ] 2>/dev/null; then
    add_result "LCK-002" "Password required within 5s of screen saver" "PASS" "askForPasswordDelay is ${ask_delay}s." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" ""
elif [ -n "$ask_delay" ]; then
    add_result "LCK-002" "Password required within 5s of screen saver" "WARN" "Grace period is ${ask_delay}s (>5s)." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Set askForPasswordDelay to 5 seconds or less."
else
    add_result "LCK-002" "Password required within 5s of screen saver" "WARN" "Grace period not configured." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Set the password grace period to 5 seconds or less."
fi
if [ -n "$idle_time" ] && [ "$idle_time" -gt 0 ] && [ "$idle_time" -le 1200 ] 2>/dev/null; then
    add_result "LCK-003" "Screen saver idle timeout <= 20 minutes" "PASS" "Idle timeout is $((idle_time/60)) minutes." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" ""
elif [ "$idle_time" = "0" ] || [ -z "$idle_time" ]; then
    add_result "LCK-003" "Screen saver idle timeout <= 20 minutes" "WARN" "Screen saver idle timeout is not set." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Set a screen saver idle timeout of 20 minutes or less."
else
    add_result "LCK-003" "Screen saver idle timeout <= 20 minutes" "FAIL" "Idle timeout is $((idle_time/60)) minutes (>20)." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Reduce the screen saver idle timeout to 20 minutes or less."
fi

# ============================================================
#  9. REMOTE ACCESS SERVICES
# ============================================================
section "Remote Access Services"
# Remote Login (SSH)
if [ "$IsRoot" -eq 1 ]; then
    rl="$(systemsetup -getremotelogin 2>/dev/null)"
    case "$rl" in
        *"On"*) add_result "REM-001" "Remote Login (SSH) disabled" "WARN" "Remote Login (SSH) is enabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Disable if not required: 'sudo systemsetup -setremotelogin off'." ;;
        *"Off"*) add_result "REM-001" "Remote Login (SSH) disabled" "PASS" "Remote Login (SSH) is disabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "" ;;
        *) add_result "REM-001" "Remote Login (SSH) disabled" "WARN" "Unable to determine Remote Login state." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify with 'systemsetup -getremotelogin'." ;;
    esac
else
    add_result "REM-001" "Remote Login (SSH) disabled" "WARN" "Root required to query Remote Login state." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Re-run with sudo to verify SSH state."
fi
# Screen Sharing / ARD
ss_state="$(launchctl print-disabled system 2>/dev/null | grep -i 'com.apple.screensharing')"
if printf '%s' "$ss_state" | grep -qi 'true'; then
    add_result "REM-002" "Screen Sharing disabled" "PASS" "Screen Sharing service is disabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
elif printf '%s' "$ss_state" | grep -qi 'false'; then
    add_result "REM-002" "Screen Sharing disabled" "WARN" "Screen Sharing appears enabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Disable Screen Sharing in System Settings > General > Sharing if not required."
else
    add_result "REM-002" "Screen Sharing disabled" "INFO" "Screen Sharing state not conclusively determined." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify Screen Sharing is off if not required."
fi

# ============================================================
# 10. FILE SHARING SERVICES
# ============================================================
section "File & Network Sharing Services"
check_sharing() {
    # $1 label, $2 launchd label, $3 id, $4 frameworks
    local lbl="$1" svc="$2" id="$3" fw="$4"
    local st
    st="$(launchctl print-disabled system 2>/dev/null | grep -i "$svc")"
    if printf '%s' "$st" | grep -qi 'true'; then
        add_result "$id" "$lbl disabled" "PASS" "$lbl is disabled." "$fw" "Medium" ""
    elif printf '%s' "$st" | grep -qi 'false'; then
        add_result "$id" "$lbl disabled" "WARN" "$lbl appears enabled." "$fw" "Medium" "Disable $lbl in System Settings > General > Sharing if not required."
    else
        add_result "$id" "$lbl disabled" "INFO" "$lbl state not determined." "$fw" "Medium" "Verify $lbl is off if not required."
    fi
}
check_sharing "SMB File Sharing" "com.apple.smbd" "SHR-001" "CIS CE+ NCSC DCC-L2 DCC-L3"
check_sharing "Apple File (AFP) Sharing" "com.apple.AppleFileServer" "SHR-002" "CIS CE+ DCC-L2"
check_sharing "Remote Apple Events" "com.apple.AEServer" "SHR-003" "CIS CE+ NCSC DCC-L2 DCC-L3"
check_sharing "Printer Sharing" "org.cups.cupsd" "SHR-004" "CIS-L2 DCC-L3"

# ============================================================
# 11. LOCAL ACCOUNTS & PRIVILEGE
# ============================================================
section "Local Accounts & Privilege"
# Guest account
guest_enabled="$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)"
if [ "$guest_enabled" = "0" ]; then
    add_result "ACC-001" "Guest account disabled" "PASS" "Guest login is disabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
elif [ "$guest_enabled" = "1" ]; then
    add_result "ACC-001" "Guest account disabled" "FAIL" "Guest account is enabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Disable the guest account in System Settings > Users & Groups."
else
    add_result "ACC-001" "Guest account disabled" "WARN" "Guest account state not determined." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Verify the guest account is disabled."
fi
# Automatic login
auto_user="$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)"
if [ -z "$auto_user" ]; then
    add_result "ACC-002" "Automatic login disabled" "PASS" "No automatic login user is configured." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" ""
else
    add_result "ACC-002" "Automatic login disabled" "FAIL" "Automatic login is enabled for '$auto_user'." "CIS CE+ NCSC DCC-L2 DCC-L3" "High" "Disable automatic login in System Settings > Users & Groups > Automatically log in as."
fi
# Administrator accounts count
admins="$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership://')"
admin_count="$(printf '%s' "$admins" | wc -w | tr -d ' ')"
add_result "ACC-003" "Administrator account inventory" "INFO" "Admin group members:${admins:- none}." "CIS CE+ DCC-L2 DCC-L3" "Medium" ""
if [ "$admin_count" -le 2 ] 2>/dev/null; then
    add_result "ACC-004" "Limited number of admin accounts" "PASS" "$admin_count admin account(s)." "CIS-L2 NCSC DCC-L3" "Medium" ""
else
    add_result "ACC-004" "Limited number of admin accounts" "WARN" "$admin_count admin accounts - apply least privilege." "CIS-L2 NCSC DCC-L3" "Medium" "Reduce administrator accounts to the minimum required; users should use standard accounts."
fi
# Console user is standard (not admin) - separation of duties
if printf '%s' "$admins" | tr ' ' '\n' | grep -qx "$CURRENT_USER"; then
    add_result "ACC-005" "Daily user is non-administrator" "WARN" "Console user '$CURRENT_USER' is an administrator." "CIS-L2 NCSC DCC-L3" "Medium" "Use a standard account for daily work and a separate admin account for elevation."
else
    add_result "ACC-005" "Daily user is non-administrator" "PASS" "Console user '$CURRENT_USER' is a standard user." "CIS-L2 NCSC DCC-L3" "Medium" ""
fi

# ============================================================
# 12. SECURE BOOT & FIRMWARE
# ============================================================
section "Secure Boot & Firmware"
if [ "$IS_APPLE_SILICON" -eq 1 ]; then
    add_result "BOOT-001" "Secure boot (Apple Silicon)" "INFO" "Apple Silicon enforces Full Security boot policy by default; verify it has not been reduced in Recovery." "CIS NCSC DCC-L2 DCC-L3" "High" ""
else
    # Intel: firmware password
    if [ "$IsRoot" -eq 1 ]; then
        fwpw="$(firmwarepasswd -check 2>/dev/null)"
        case "$fwpw" in
            *"Yes"*) add_result "BOOT-001" "EFI firmware password set (Intel)" "PASS" "A firmware password is set." "CIS-L2 NCSC DCC-L3" "High" "" ;;
            *"No"*) add_result "BOOT-001" "EFI firmware password set (Intel)" "WARN" "No firmware password is set." "CIS-L2 NCSC DCC-L3" "High" "Set a firmware password: 'sudo firmwarepasswd -setpasswd'." ;;
            *) add_result "BOOT-001" "EFI firmware password set (Intel)" "WARN" "Unable to determine firmware password state." "CIS-L2 NCSC DCC-L3" "High" "Verify with 'sudo firmwarepasswd -check'." ;;
        esac
    else
        add_result "BOOT-001" "EFI firmware password set (Intel)" "WARN" "Root required to check firmware password." "CIS-L2 NCSC DCC-L3" "High" "Re-run with sudo to verify the firmware password."
    fi
fi

# ============================================================
# 13. NETWORK & WIRELESS
# ============================================================
section "Network & Wireless"
# Bluetooth
bt="$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)"
if [ "$bt" = "0" ]; then
    add_result "NET-001" "Bluetooth powered off when unused" "PASS" "Bluetooth controller is powered off." "CIS-L2 DCC-L3" "Low" ""
else
    add_result "NET-001" "Bluetooth powered off when unused" "INFO" "Bluetooth is on - acceptable if peripherals require it." "CIS-L2 DCC-L3" "Low" "Disable Bluetooth if no Bluetooth peripherals are in use."
fi
# Time synchronisation (NTP)
if [ "$IsRoot" -eq 1 ]; then
    tn="$(systemsetup -getusingnetworktime 2>/dev/null)"
    case "$tn" in
        *"On"*) add_result "NET-002" "Network time synchronisation enabled" "PASS" "Using network time." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "" ;;
        *"Off"*) add_result "NET-002" "Network time synchronisation enabled" "FAIL" "Network time is off - accurate logs depend on synced time." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Enable: 'sudo systemsetup -setusingnetworktime on'." ;;
        *) add_result "NET-002" "Network time synchronisation enabled" "WARN" "Unable to determine network time state." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Verify with 'systemsetup -getusingnetworktime'." ;;
    esac
else
    timed="$(defaults read /Library/Preferences/com.apple.timed.plist 2>/dev/null)"
    add_result "NET-002" "Network time synchronisation enabled" "WARN" "Root required for definitive NTP check." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Re-run with sudo to verify network time."
fi

# ============================================================
# 14. AUDIT & LOGGING
# ============================================================
section "Audit & Logging"
# Apple System Log / unified logging is always on; check security auditing (auditd)
if launchctl print system/com.apple.auditd >/dev/null 2>&1; then
    add_result "LOG-001" "Security auditing (auditd) active" "PASS" "com.apple.auditd is loaded." "CIS-L2 NCSC DCC-L2 DCC-L3" "Medium" ""
else
    add_result "LOG-001" "Security auditing (auditd) active" "WARN" "auditd not confirmed loaded (root may be required)." "CIS-L2 NCSC DCC-L2 DCC-L3" "Medium" "Ensure the security auditing subsystem (auditd) is enabled."
fi
if [ -d /var/audit ]; then
    add_result "LOG-002" "Audit records retained" "PASS" "/var/audit exists for BSM audit trails." "CIS-L2 DCC-L3" "Low" ""
else
    add_result "LOG-002" "Audit records retained" "WARN" "/var/audit not present." "CIS-L2 DCC-L3" "Low" "Confirm BSM audit logging is configured and retaining records."
fi

# ============================================================
# 15. PRIVACY & TRANSPARENCY (TCC)
# ============================================================
section "Privacy Controls (TCC)"
add_result "PRV-001" "Transparency, Consent & Control (TCC) present" "INFO" "macOS enforces per-app privacy permissions via TCC. Review app permissions in System Settings > Privacy & Security." "CIS CE+ NCSC" "Medium" ""
# Analytics / diagnostics sharing
analytics="$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null)"
if [ "$analytics" = "0" ]; then
    add_result "PRV-002" "Diagnostic data sharing disabled" "PASS" "Automatic diagnostic submission is off." "CIS-L2 NCSC DCC-L3" "Low" ""
else
    add_result "PRV-002" "Diagnostic data sharing disabled" "INFO" "Diagnostic data sharing state could not be confirmed disabled." "CIS-L2 NCSC DCC-L3" "Low" "Disable 'Share Mac Analytics' in System Settings > Privacy & Security > Analytics & Improvements."
fi

# ============================================================
# 16. WEB BROWSER (Safari)
# ============================================================
section "Web Browser (Safari)"
safari_open="$(defaults read com.apple.Safari AutoOpenSafeDownloads 2>/dev/null)"
if [ "$safari_open" = "0" ]; then
    add_result "WEB-001" "Safari: do not auto-open 'safe' downloads" "PASS" "AutoOpenSafeDownloads is disabled." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" ""
elif [ "$safari_open" = "1" ]; then
    add_result "WEB-001" "Safari: do not auto-open 'safe' downloads" "FAIL" "Safari auto-opens downloads deemed 'safe'." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "Disable 'Open safe files after downloading' in Safari settings."
else
    add_result "WEB-001" "Safari: do not auto-open 'safe' downloads" "INFO" "Safari setting not present (Safari may not be the primary browser)." "CIS CE+ NCSC DCC-L2 DCC-L3" "Medium" "If using Safari, disable auto-opening of downloads."
fi

# ============================================================
# 17. BACKUP (Time Machine)
# ============================================================
section "Backup (Time Machine)"
tm_dest="$(tmutil destinationinfo 2>/dev/null)"
if printf '%s' "$tm_dest" | grep -qi 'Name'; then
    add_result "BKP-001" "Time Machine backup destination configured" "PASS" "A Time Machine destination is configured." "CIS-L2 CE+ DCC-L2 DCC-L3" "Medium" ""
else
    add_result "BKP-001" "Time Machine backup destination configured" "WARN" "No Time Machine destination configured (backups may be handled by another solution)." "CIS-L2 CE+ DCC-L2 DCC-L3" "Medium" "Configure Time Machine or an enterprise backup solution to protect against data loss/ransomware."
fi

# ============================================================
# 18. MDM / DEVICE MANAGEMENT POSTURE
# ============================================================
section "MDM / Device Management Posture"
if [ "$MDM_ENROLLED" -eq 1 ]; then
    add_result "MDM-001" "Device under MDM management" "PASS" "Device is MDM enrolled${MDM_VENDOR:+ ($MDM_VENDOR)}." "MDM DCC-L2 DCC-L3" "High" ""
else
    add_result "MDM-001" "Device under MDM management" "WARN" "Device is not MDM enrolled - centralised policy and remote wipe unavailable." "MDM DCC-L2 DCC-L3" "High" "Enrol the device into an approved MDM (Jamf, Intune, Kandji) for centralised security policy."
fi
# Configuration profiles present
prof_count="$(profiles list 2>/dev/null | grep -c 'attribute: name' 2>/dev/null)"
[ -z "$prof_count" ] && prof_count=0
if [ "$prof_count" -gt 0 ] 2>/dev/null; then
    add_result "MDM-002" "Configuration profiles installed" "INFO" "$prof_count configuration profile(s) installed." "MDM DCC-L2 DCC-L3" "Medium" ""
else
    add_result "MDM-002" "Configuration profiles installed" "INFO" "No configuration profiles detected (root may be required)." "MDM DCC-L2 DCC-L3" "Medium" ""
fi

# ============================================================
# 19. UK MoD DCC ENHANCED CONTROLS
# ============================================================
section "UK MoD DCC Enhanced Controls"
# Hibernate/destroy FileVault key on standby (deep security)
destroyfv="$(pmset -g 2>/dev/null | awk '/DestroyFVKeyOnStandby/{print $2}')"
if [ "$destroyfv" = "1" ]; then
    add_result "DCC-001" "Destroy FileVault key on standby" "PASS" "DestroyFVKeyOnStandby is enabled." "DCC-L3" "High" ""
else
    add_result "DCC-001" "Destroy FileVault key on standby" "WARN" "DestroyFVKeyOnStandby is not enabled." "DCC-L3" "High" "Enable: 'sudo pmset -a destroyfvkeyonstandby 1' (with hibernatemode 25) for high-assurance environments."
fi
# Standby/hibernate mode
hibmode="$(pmset -g 2>/dev/null | awk '/hibernatemode/{print $2}')"
if [ "$hibmode" = "25" ]; then
    add_result "DCC-002" "Secure hibernate mode (25)" "PASS" "hibernatemode is 25 (RAM cleared to disk)." "DCC-L3" "Medium" ""
else
    add_result "DCC-002" "Secure hibernate mode (25)" "INFO" "hibernatemode is ${hibmode:-unknown}." "DCC-L3" "Medium" "For high-assurance, set 'sudo pmset -a hibernatemode 25'."
fi
# Power nap (reduce attack surface on standby)
powernap="$(pmset -g 2>/dev/null | awk '/powernap/{print $2}' | head -n1)"
if [ "$powernap" = "0" ]; then
    add_result "DCC-003" "Power Nap disabled" "PASS" "Power Nap is disabled." "DCC-L3" "Low" ""
else
    add_result "DCC-003" "Power Nap disabled" "INFO" "Power Nap state: ${powernap:-unknown}." "DCC-L3" "Low" "Disable Power Nap for reduced standby attack surface: 'sudo pmset -a powernap 0'."
fi

# ============================================================
#  SCORING & STATISTICS ENGINE
# ============================================================
TOTAL=${#R_ID[@]}

# Overall counts (INFO excluded from scoreable denominators)
cPASS=0; cFAIL=0; cWARN=0; cINFO=0
i=0
while [ "$i" -lt "$TOTAL" ]; do
    case "${R_STATUS[$i]}" in
        PASS) cPASS=$((cPASS+1)) ;;
        FAIL) cFAIL=$((cFAIL+1)) ;;
        WARN) cWARN=$((cWARN+1)) ;;
        INFO) cINFO=$((cINFO+1)) ;;
    esac
    i=$((i+1))
done
SCOREABLE=$((cPASS + cFAIL + cWARN))
OVERALL_SCORE=$(pct "$cPASS" "$SCOREABLE")

# Severity-weighted score: weight each PASS by its severity, over weighted scoreable
wPASS=0; wTOTAL=0
i=0
while [ "$i" -lt "$TOTAL" ]; do
    st="${R_STATUS[$i]}"
    if [ "$st" = "PASS" ] || [ "$st" = "FAIL" ] || [ "$st" = "WARN" ]; then
        w="$(severity_weight "${R_SEV[$i]}")"
        wTOTAL=$((wTOTAL + w))
        [ "$st" = "PASS" ] && wPASS=$((wPASS + w))
    fi
    i=$((i+1))
done
WEIGHTED_SCORE=$(pct "$wPASS" "$wTOTAL")

# Per-framework scoring
# Frameworks and their pass thresholds
FW_LIST="CIS CIS-L2 CE+ NCSC MDM DCC-L2 DCC-L3"
fw_threshold() {
    case "$1" in
        CIS) echo 90 ;; CIS-L2) echo 90 ;; CE+) echo 100 ;;
        NCSC) echo 85 ;; MDM) echo 90 ;; DCC-L2) echo 100 ;;
        DCC-L3) echo 95 ;; *) echo 90 ;;
    esac
}

# Compute per-framework pass/fail/warn and score. NCSC uses weighted (PASS=1,WARN=0.5,FAIL=0) scaled x10 to stay integer.
fw_score_for() {
    # echoes: pass fail warn score(0-100)
    local target="$1" p=0 f=0 w=0 num10=0 den10=0 j=0
    while [ "$j" -lt "$TOTAL" ]; do
        case " ${R_FW[$j]} " in
            *" $target "*)
                case "${R_STATUS[$j]}" in
                    PASS) p=$((p+1)); num10=$((num10+10)); den10=$((den10+10)) ;;
                    FAIL) f=$((f+1)); den10=$((den10+10)) ;;
                    WARN) w=$((w+1)); num10=$((num10+5)); den10=$((den10+10)) ;;
                    INFO) : ;;
                esac
                ;;
        esac
        j=$((j+1))
    done
    local score
    if [ "$target" = "NCSC" ]; then
        if [ "$den10" -le 0 ]; then score=0; else score=$(( num10 * 100 / den10 )); fi
    else
        local sc=$((p + f + w))
        if [ "$sc" -le 0 ]; then score=0; else score=$(( p * 100 / sc )); fi
    fi
    echo "$p $f $w $score"
}

# ============================================================
#  EXECUTIVE SUMMARY (console + txt)
# ============================================================
section "Executive Summary"
RISK="$(risk_rating "$OVERALL_SCORE")"
emit "Audit scope        : $AuditLabel"
emit "Device             : $MachineName ($OS_NAME $OS_VER, $HW_MODEL)"
emit "MDM enrolment      : $([ "$MDM_ENROLLED" -eq 1 ] && echo "Yes${MDM_VENDOR:+ - $MDM_VENDOR}" || echo "No")"
emit "Checks performed   : $TOTAL ($SCOREABLE scoreable, $cINFO informational)"
emit "Passed / Failed     : $cPASS / $cFAIL  (Warnings: $cWARN)"
emit "Overall score      : ${OVERALL_SCORE}%  $(progress_bar "$OVERALL_SCORE")"
emit "Weighted score     : ${WEIGHTED_SCORE}% (severity-weighted)"
emit "Overall risk rating: $RISK"

# ------------------------------------------------------------
#  FRAMEWORK COMPLIANCE DASHBOARD
# ------------------------------------------------------------
section "Framework Compliance Dashboard"
emit "$(printf '%-10s %6s %6s %6s %8s %10s %s' 'Framework' 'Pass' 'Fail' 'Warn' 'Score' 'Threshold' 'Status')"
emit "$(printf '%s' '---------------------------------------------------------------------------')"
for fw in $FW_LIST; do
    set -- $(fw_score_for "$fw")
    p="$1"; f="$2"; w="$3"; sc="$4"
    [ $((p+f+w)) -eq 0 ] && continue
    th="$(fw_threshold "$fw")"
    if [ "$sc" -ge "$th" ]; then stat="COMPLIANT"; else stat="NON-COMPLIANT"; fi
    emit "$(printf '%-10s %6s %6s %6s %7s%% %9s%% %s  %s' "$fw" "$p" "$f" "$w" "$sc" "$th" "$stat" "$(progress_bar "$sc")")"
done

# ------------------------------------------------------------
#  TOP RISKS (failed, highest severity first)
# ------------------------------------------------------------
section "Top 5 Risks"
top_emitted=0
for sevrank in Critical High Medium Low; do
    [ "$top_emitted" -ge 5 ] && break
    i=0
    while [ "$i" -lt "$TOTAL" ]; do
        if [ "${R_STATUS[$i]}" = "FAIL" ] && [ "${R_SEV[$i]}" = "$sevrank" ]; then
            emit "  [$sevrank] ${R_ID[$i]} - ${R_DESC[$i]}"
            [ -n "${R_REM[$i]}" ] && emit "      Fix: ${R_REM[$i]}"
            top_emitted=$((top_emitted+1))
            [ "$top_emitted" -ge 5 ] && break
        fi
        i=$((i+1))
    done
done
[ "$top_emitted" -eq 0 ] && emit "  No failed controls - excellent."

# ------------------------------------------------------------
#  QUICK WINS (Medium/Low severity failures - easy fixes)
# ------------------------------------------------------------
section "Quick Wins"
qw=0
i=0
while [ "$i" -lt "$TOTAL" ]; do
    if [ "${R_STATUS[$i]}" = "FAIL" ] && { [ "${R_SEV[$i]}" = "Medium" ] || [ "${R_SEV[$i]}" = "Low" ]; }; then
        emit "  ${R_ID[$i]} - ${R_DESC[$i]}"
        [ -n "${R_REM[$i]}" ] && emit "      Fix: ${R_REM[$i]}"
        qw=$((qw+1))
        [ "$qw" -ge 5 ] && break
    fi
    i=$((i+1))
done
[ "$qw" -eq 0 ] && emit "  No quick-win items identified."

# ------------------------------------------------------------
#  WARNINGS SUMMARY
# ------------------------------------------------------------
section "Warnings Summary"
wc_emit=0
i=0
while [ "$i" -lt "$TOTAL" ]; do
    if [ "${R_STATUS[$i]}" = "WARN" ]; then
        emit "  ${R_ID[$i]} - ${R_DESC[$i]}"
        wc_emit=$((wc_emit+1))
    fi
    i=$((i+1))
done
[ "$wc_emit" -eq 0 ] && emit "  No warnings."

# ------------------------------------------------------------
#  PRIORITY REMEDIATION PLAN (all failures, severity ordered)
# ------------------------------------------------------------
section "Priority Remediation Plan"
rank=1
for sevrank in Critical High Medium Low; do
    i=0
    while [ "$i" -lt "$TOTAL" ]; do
        if [ "${R_STATUS[$i]}" = "FAIL" ] && [ "${R_SEV[$i]}" = "$sevrank" ]; then
            emit "  $rank. [$sevrank] ${R_ID[$i]} - ${R_DESC[$i]}"
            [ -n "${R_DETAIL[$i]}" ] && emit "        Finding: ${R_DETAIL[$i]}"
            [ -n "${R_REM[$i]}" ] && emit "        Remediation: ${R_REM[$i]}"
            rank=$((rank+1))
        fi
        i=$((i+1))
    done
done
[ "$rank" -eq 1 ] && emit "  No remediation required - all scored controls passed."

# ------------------------------------------------------------
#  DELTA / TREND COMPARISON (against a previous JSON report)
# ------------------------------------------------------------
PREV_SCORE=""
if [ -n "$PreviousReport" ] && [ -f "$PreviousReport" ]; then
    section "Trend Comparison"
    # Extract previous overall score from the JSON (best-effort, no jq dependency)
    PREV_SCORE="$(grep -o '"overall_score"[ ]*:[ ]*[0-9]\+' "$PreviousReport" 2>/dev/null | grep -o '[0-9]\+' | head -n1)"
    if [ -n "$PREV_SCORE" ]; then
        diff=$(( OVERALL_SCORE - PREV_SCORE ))
        if [ "$diff" -gt 0 ]; then
            emit "Overall score improved by ${diff}% (was ${PREV_SCORE}%, now ${OVERALL_SCORE}%)."
        elif [ "$diff" -lt 0 ]; then
            emit "Overall score declined by $(( -diff ))% (was ${PREV_SCORE}%, now ${OVERALL_SCORE}%)."
        else
            emit "Overall score unchanged at ${OVERALL_SCORE}%."
        fi
    else
        emit "Could not parse previous overall score from $PreviousReport."
    fi
elif [ -n "$PreviousReport" ]; then
    section "Trend Comparison"
    emit "Previous report not found: $PreviousReport"
fi

# ------------------------------------------------------------
#  COMPLIANCE ATTESTATION
# ------------------------------------------------------------
section "Compliance Attestation"
emit "This automated assessment was generated by the macOS Workstation"
emit "Security Auditor v$ScriptVersion on $(date '+%Y-%m-%d %H:%M:%S %Z')."
emit "It provides indicative alignment with the referenced frameworks and"
emit "does not constitute a formal certification. Findings should be"
emit "validated by a qualified assessor where certification is required."

# ============================================================
#  CSV EXPORT
# ============================================================
{
    printf 'ID,Description,Status,Severity,Frameworks,Detail,Remediation\n'
    i=0
    while [ "$i" -lt "$TOTAL" ]; do
        printf '%s,%s,%s,%s,%s,%s,%s\n' \
            "$(csv_escape "${R_ID[$i]}")" \
            "$(csv_escape "${R_DESC[$i]}")" \
            "$(csv_escape "${R_STATUS[$i]}")" \
            "$(csv_escape "${R_SEV[$i]}")" \
            "$(csv_escape "${R_FW[$i]}")" \
            "$(csv_escape "${R_DETAIL[$i]}")" \
            "$(csv_escape "${R_REM[$i]}")"
        i=$((i+1))
    done
} > "$CsvPath"

# ============================================================
#  JSON EXPORT
# ============================================================
{
    printf '{\n'
    printf '  "metadata": {\n'
    printf '    "tool": "macOS Workstation Security Auditor",\n'
    printf '    "version": "%s",\n' "$ScriptVersion"
    printf '    "generated": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '    "scope": "%s",\n' "$(json_escape "$AuditLabel")"
    printf '    "device": {\n'
    printf '      "name": "%s",\n' "$(json_escape "$MachineName")"
    printf '      "os": "%s %s",\n' "$(json_escape "$OS_NAME")" "$(json_escape "$OS_VER")"
    printf '      "build": "%s",\n' "$(json_escape "$OS_BUILD")"
    printf '      "model": "%s",\n' "$(json_escape "$HW_MODEL")"
    printf '      "serial": "%s",\n' "$(json_escape "$SERIAL")"
    printf '      "architecture": "%s",\n' "$(json_escape "$ARCH")"
    printf '      "mdm_enrolled": %s,\n' "$([ "$MDM_ENROLLED" -eq 1 ] && echo true || echo false)"
    printf '      "mdm_vendor": "%s"\n' "$(json_escape "$MDM_VENDOR")"
    printf '    }\n'
    printf '  },\n'
    printf '  "summary": {\n'
    printf '    "total_checks": %s,\n' "$TOTAL"
    printf '    "scoreable": %s,\n' "$SCOREABLE"
    printf '    "passed": %s,\n' "$cPASS"
    printf '    "failed": %s,\n' "$cFAIL"
    printf '    "warnings": %s,\n' "$cWARN"
    printf '    "informational": %s,\n' "$cINFO"
    printf '    "overall_score": %s,\n' "$OVERALL_SCORE"
    printf '    "weighted_score": %s,\n' "$WEIGHTED_SCORE"
    printf '    "risk_rating": "%s"\n' "$RISK"
    printf '  },\n'
    printf '  "framework_scores": {\n'
    first_fw=1
    for fw in $FW_LIST; do
        set -- $(fw_score_for "$fw")
        p="$1"; f="$2"; w="$3"; sc="$4"
        [ $((p+f+w)) -eq 0 ] && continue
        th="$(fw_threshold "$fw")"
        comp="$([ "$sc" -ge "$th" ] && echo true || echo false)"
        [ "$first_fw" -eq 0 ] && printf ',\n'
        first_fw=0
        printf '    "%s": { "pass": %s, "fail": %s, "warn": %s, "score": %s, "threshold": %s, "compliant": %s }' \
            "$(json_escape "$fw")" "$p" "$f" "$w" "$sc" "$th" "$comp"
    done
    printf '\n  },\n'
    printf '  "results": [\n'
    i=0
    while [ "$i" -lt "$TOTAL" ]; do
        [ "$i" -gt 0 ] && printf ',\n'
        printf '    { "id": "%s", "description": "%s", "status": "%s", "severity": "%s", "frameworks": "%s", "detail": "%s", "remediation": "%s" }' \
            "$(json_escape "${R_ID[$i]}")" \
            "$(json_escape "${R_DESC[$i]}")" \
            "$(json_escape "${R_STATUS[$i]}")" \
            "$(json_escape "${R_SEV[$i]}")" \
            "$(json_escape "${R_FW[$i]}")" \
            "$(json_escape "${R_DETAIL[$i]}")" \
            "$(json_escape "${R_REM[$i]}")"
        i=$((i+1))
    done
    printf '\n  ]\n'
    printf '}\n'
} > "$JsonPath"

# ============================================================
#  SBOM EXPORT (CycloneDX 1.5) - installed applications inventory
# ============================================================
{
    printf '{\n'
    printf '  "bomFormat": "CycloneDX",\n'
    printf '  "specVersion": "1.5",\n'
    printf '  "version": 1,\n'
    printf '  "metadata": {\n'
    printf '    "timestamp": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '    "tools": [ { "vendor": "OTY Heavy Industries", "name": "macOS Workstation Security Auditor", "version": "%s" } ],\n' "$ScriptVersion"
    printf '    "component": { "type": "operating-system", "name": "%s", "version": "%s" }\n' "$(json_escape "$OS_NAME")" "$(json_escape "$OS_VER")"
    printf '  },\n'
    printf '  "components": [\n'
    # Enumerate applications via system_profiler (best effort)
    app_tmp="$(mktemp 2>/dev/null || echo /tmp/audit_apps.$$)"
    system_profiler SPApplicationsDataType 2>/dev/null | \
        awk '/^    [A-Za-z].*:$/{name=$0; sub(/^ +/,"",name); sub(/:$/,"",name); next}
             /Version:/{v=$0; sub(/.*Version: */,"",v); if(name!=""){print name "\t" v; name=""}}' \
        > "$app_tmp" 2>/dev/null
    first_c=1
    if [ -s "$app_tmp" ]; then
        while IFS="$(printf '\t')" read -r aname aver; do
            [ -z "$aname" ] && continue
            [ "$first_c" -eq 0 ] && printf ',\n'
            first_c=0
            printf '    { "type": "application", "name": "%s", "version": "%s" }' \
                "$(json_escape "$aname")" "$(json_escape "$aver")"
        done < "$app_tmp"
    fi
    rm -f "$app_tmp" 2>/dev/null
    [ "$first_c" -eq 1 ] && printf '    { "type": "application", "name": "inventory-unavailable", "version": "0" }'
    printf '\n  ]\n'
    printf '}\n'
} > "$SbomPath"

# ============================================================
#  HTML REPORT
# ============================================================
{
cat <<HTML_HEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macOS Security Audit - $(html_escape "$MachineName")</title>
<style>
:root{--bg:#0f1220;--card:#1a1f35;--txt:#e6e9f0;--mut:#9aa3b2;--pass:#2ecc71;--fail:#e74c3c;--warn:#f39c12;--info:#3498db;--acc:#5b8def}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:24px 32px;background:linear-gradient(135deg,#1a1f35,#2a335c)}
h1{margin:0;font-size:22px}h2{border-bottom:1px solid #2a3150;padding-bottom:6px;margin-top:32px}
.wrap{max-width:1200px;margin:0 auto;padding:0 32px 64px}
.cards{display:flex;flex-wrap:wrap;gap:16px;margin-top:24px}
.card{background:var(--card);border-radius:12px;padding:18px 22px;flex:1;min-width:160px;box-shadow:0 2px 8px rgba(0,0,0,.3)}
.card .v{font-size:30px;font-weight:700}.card .l{color:var(--mut);font-size:13px;text-transform:uppercase;letter-spacing:.5px}
.score-big{font-size:46px;font-weight:800}
table{width:100%;border-collapse:collapse;margin-top:16px;font-size:14px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #232a47;vertical-align:top}
th{color:var(--mut);cursor:pointer;user-select:none;position:sticky;top:0;background:var(--card)}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700;color:#0f1220}
.PASS{background:var(--pass)}.FAIL{background:var(--fail);color:#fff}.WARN{background:var(--warn)}.INFO{background:var(--info);color:#fff}
.bar{height:10px;border-radius:6px;background:#232a47;overflow:hidden}.bar>span{display:block;height:100%;background:var(--acc)}
.controls{margin-top:16px;display:flex;gap:10px;flex-wrap:wrap}
input,select{background:var(--card);color:var(--txt);border:1px solid #2a3150;border-radius:8px;padding:8px 12px}
.fw-row td{font-variant-numeric:tabular-nums}
.muted{color:var(--mut)}
</style>
</head>
<body>
<header>
<h1>macOS Workstation Security Audit</h1>
<div class="muted">$(html_escape "$MachineName") &middot; $(html_escape "$OS_NAME") $(html_escape "$OS_VER") &middot; $(html_escape "$HW_MODEL") &middot; $(date '+%Y-%m-%d %H:%M')</div>
<div class="muted">Scope: $(html_escape "$AuditLabel") &middot; MDM: $([ "$MDM_ENROLLED" -eq 1 ] && html_escape "Yes${MDM_VENDOR:+ ($MDM_VENDOR)}" || echo No)</div>
</header>
<div class="wrap">
<div class="cards">
  <div class="card"><div class="l">Overall Score</div><div class="score-big">${OVERALL_SCORE}%</div><div class="bar"><span style="width:${OVERALL_SCORE}%"></span></div></div>
  <div class="card"><div class="l">Weighted Score</div><div class="v">${WEIGHTED_SCORE}%</div></div>
  <div class="card"><div class="l">Risk Rating</div><div class="v">${RISK}</div></div>
  <div class="card"><div class="l">Passed</div><div class="v" style="color:var(--pass)">${cPASS}</div></div>
  <div class="card"><div class="l">Failed</div><div class="v" style="color:var(--fail)">${cFAIL}</div></div>
  <div class="card"><div class="l">Warnings</div><div class="v" style="color:var(--warn)">${cWARN}</div></div>
</div>
<h2>Framework Compliance</h2>
<table><thead><tr><th>Framework</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th><th>Threshold</th><th>Status</th></tr></thead><tbody>
HTML_HEAD

for fw in $FW_LIST; do
    set -- $(fw_score_for "$fw")
    p="$1"; f="$2"; w="$3"; sc="$4"
    [ $((p+f+w)) -eq 0 ] && continue
    th="$(fw_threshold "$fw")"
    if [ "$sc" -ge "$th" ]; then stat='<span class="badge PASS">COMPLIANT</span>'; else stat='<span class="badge FAIL">NON-COMPLIANT</span>'; fi
    printf '<tr class="fw-row"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s%%</td><td>%s%%</td><td>%s</td></tr>\n' \
        "$(html_escape "$fw")" "$p" "$f" "$w" "$sc" "$th" "$stat"
done

cat <<HTML_MID
</tbody></table>
<h2>Detailed Findings</h2>
<div class="controls">
  <input id="q" placeholder="Filter findings..." oninput="flt()">
  <select id="sf" onchange="flt()">
    <option value="">All statuses</option><option>PASS</option><option>FAIL</option><option>WARN</option><option>INFO</option>
  </select>
</div>
<table id="rt"><thead><tr>
<th onclick="srt(0)">ID</th><th onclick="srt(1)">Description</th><th onclick="srt(2)">Status</th>
<th onclick="srt(3)">Severity</th><th onclick="srt(4)">Frameworks</th><th>Detail / Remediation</th>
</tr></thead><tbody>
HTML_MID

i=0
while [ "$i" -lt "$TOTAL" ]; do
    det="$(html_escape "${R_DETAIL[$i]}")"
    rem="${R_REM[$i]}"
    [ -n "$rem" ] && det="$det<br><span class=\"muted\">Fix: $(html_escape "$rem")</span>"
    printf '<tr><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
        "$(html_escape "${R_ID[$i]}")" \
        "$(html_escape "${R_DESC[$i]}")" \
        "${R_STATUS[$i]}" "${R_STATUS[$i]}" \
        "$(html_escape "${R_SEV[$i]}")" \
        "$(html_escape "${R_FW[$i]}")" \
        "$det"
    i=$((i+1))
done

cat <<'HTML_TAIL'
</tbody></table>
<p class="muted">Generated by the macOS Workstation Security Auditor. Indicative alignment only; not a formal certification.</p>
</div>
<script>
function flt(){var q=document.getElementById('q').value.toLowerCase(),s=document.getElementById('sf').value;
var rows=document.querySelectorAll('#rt tbody tr');rows.forEach(function(r){var t=r.innerText.toLowerCase();
var st=r.querySelector('.badge').innerText;var ok=t.indexOf(q)>-1&&(s===''||st===s);r.style.display=ok?'':'none';});}
function srt(n){var tb=document.querySelector('#rt tbody'),rows=Array.prototype.slice.call(tb.rows);
var asc=tb.getAttribute('data-asc')!=='1';tb.setAttribute('data-asc',asc?'1':'0');
rows.sort(function(a,b){var x=a.cells[n].innerText.toLowerCase(),y=b.cells[n].innerText.toLowerCase();
return x<y?(asc?-1:1):x>y?(asc?1:-1):0;});rows.forEach(function(r){tb.appendChild(r);});}
</script>
</body></html>
HTML_TAIL
} > "$HtmlPath"

# ============================================================
#  FOOTER
# ============================================================
AuditEndEpoch="$(date +%s)"
Elapsed=$(( AuditEndEpoch - AuditStartEpoch ))
section "Reports Generated"
emit "Text report : $ReportPath"
emit "CSV export  : $CsvPath"
emit "JSON export : $JsonPath"
emit "HTML report : $HtmlPath"
emit "SBOM (CDX)  : $SbomPath"
emit "Elapsed     : ${Elapsed}s"
emit ""
emit "Audit complete. Overall score ${OVERALL_SCORE}% ($RISK risk)."

exit 0
