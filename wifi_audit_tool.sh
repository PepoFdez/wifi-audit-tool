#!/bin/bash

# =====================================================================
# WiFi Auditing Automation Tool - v2.1 (Bash Edition)
# Estética mejorada + prompt personalizado + base de datos persistente
# =====================================================================

# ---------------------------
# Colores
# ---------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ---------------------------
# Funciones de impresión
# ---------------------------
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# ---------------------------
# Verificaciones
# ---------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root (sudo)"
        exit 1
    fi
}

check_dependencies() {
    local deps=(hcxdumptool hcxpcapngtool hashcat curl)
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

# ---------------------------
# Banner
# ---------------------------
show_banner() {
    clear
    echo ""
    if command -v figlet >/dev/null 2>&1; then
        echo -e "${CYAN}"
        figlet -f slant "WiFi Audit Tool"
        echo -e "${NC}"
    else
        echo -e "${CYAN}╔═════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${WHITE}     WiFi Auditing Automation Tool v2.2${CYAN}      ║${NC}"
        echo -e "${CYAN}║${WHITE}     IEEE 802.11 Security Analysis${CYAN}           ║${NC}"
        echo -e "${CYAN}╚═════════════════════════════════════════════╝${NC}"
    fi
}

# ---------------------------
# Comando: help
# ---------------------------
show_help() {
    echo -e "${WHITE}"
    echo "──────────────────────────────────────────────"
    echo "   USO DE COMANDOS DISPONIBLES"
    echo "──────────────────────────────────────────────"
    echo ""
    echo -e "${YELLOW}analyze${NC} ${WHITE}<interfaz> <archivo.pcapng>${NC}"
    echo "  Captura tráfico WiFi, extrae EAPOL y actualiza la base de datos."
    echo ""
    echo -e "${YELLOW}lsmac${NC} [${WHITE}archivo.hc22000${NC}]"
    echo "  Lista las MACs detectadas. Si se especifica un archivo, solo analiza ese."
    echo ""
    echo -e "${YELLOW}attack${NC} ${WHITE}<mac> <máscara>${NC}"
    echo "  Ejecuta hashcat sobre una MAC específica."
    echo ""
    echo -e "${YELLOW}help${NC}     Muestra esta ayuda."
    echo -e "${YELLOW}exit${NC}     Sale del programa."
    echo -e "${CYAN}──────────────────────────────────────────────${NC}"
}

# ---------------------------
# analyze
# ---------------------------
analyze() {
    local iface="$1"
    local outfile="$2"
    local dbfile="database.hc22000"

    if [[ -z "$iface" || -z "$outfile" ]]; then
        print_error "Uso: analyze <interfaz> <archivo.pcapng>"
        return 1
    fi
    if ! ip link show "$iface" &>/dev/null; then
        print_error "Interfaz no encontrada: $iface"
        return 1
    fi

    print_info "Iniciando captura con hcxdumptool en $iface..."
    print_warning "Presiona Ctrl+C para detener."
    systemctl stop NetworkManager wpa_supplicant 2>/dev/null
    hcxdumptool -i "$iface" -w "$outfile" -F --rds=1
    systemctl restart NetworkManager wpa_supplicant 2>/dev/null

    if [[ ! -f "$outfile" ]]; then
        print_error "No se generó el archivo $outfile."
        return 1
    fi

    print_info "Convirtiendo a formato hashcat..."
    local hcfile="${outfile%.pcapng}.hc22000"
    hcxpcapngtool -o "$hcfile" "$outfile"

    # Guardar en base de datos global
    if [[ -f "$hcfile" ]]; then
        print_info "Actualizando base de datos global..."
        cat "$hcfile" >> "$dbfile"
        sort -u "$dbfile" -o "$dbfile"
        print_success "Base de datos actualizada: $dbfile"
    else
        print_error "No se generó correctamente $hcfile."
        return 1
    fi

    print_success "Captura completada y agregada a la base de datos."
}

# ---------------------------
# Lookup vendor (con cache, fallback y local)
# ---------------------------
lookup_vendor() {
    local mac="$1"
    local cache_dir="$HOME/.wifi_audit"
    local cache_file="$cache_dir/vendors.cache"
    mkdir -p "$cache_dir"

    local prefix=$(echo "$mac" | cut -d: -f1-3 | tr -d ':' | tr '[:lower:]' '[:upper:]')
    local cached=$(grep -i "^$prefix;" "$cache_file" 2>/dev/null | cut -d';' -f2)

    if [[ -n "$cached" ]]; then
        echo "$cached"
        return
    fi

    vendor=""

    # API primaria: macvendors.com
    response=$(curl -s --max-time 3 "https://api.macvendors.com/$mac")
    if [[ "$response" == *"Too Many Requests"* || "$response" == *"<html"* || -z "$response" ]]; then
        # API secundaria: maclookup.app
        response2=$(curl -s --max-time 3 "https://api.maclookup.app/v2/macs/$mac/company/name")
        if [[ -n "$response2" && "$response2" != *"error"* ]]; then
            vendor="$response2"
        fi
    else
        vendor="$response"
    fi

    # Si no hay Internet o ambas fallan, consultar base IEEE local (requiere ieee-data)
    if [[ -z "$vendor" || "$vendor" == *"<html"* ]]; then
        if [[ -f "/usr/share/ieee-data/oui.txt" ]]; then
            vendor_local=$(grep -i "^$prefix" /usr/share/ieee-data/oui.txt | awk -F'\t' '{print $3}' | head -n1)
            [[ -n "$vendor_local" ]] && vendor="$vendor_local" || vendor="Desconocido"
        else
            vendor="Desconocido"
        fi
    fi

    # Guardar en cache
    echo "$prefix;$vendor" >> "$cache_file"
    echo "$vendor"
}

# ---------------------------
# lsmac
# ---------------------------
lsmac() {
    local file="${1:-database.hc22000}"

    if [[ ! -f "$file" ]]; then
        print_error "No se encontró el archivo $file."
        print_info "Ejecuta analyze o pasa un .hc22000 válido."
        return 1
    fi

    print_info "Extrayendo MACs desde: $file"
    declare -A seen
    local mac_list=()

    while IFS='*' read -r f1 f2 f3 f4 rest; do
        [[ -z "$f4" ]] && continue
        formatted_mac=$(echo "$f4" | sed 's/..../&:/g;s/:$//' | tr '[:lower:]' '[:upper:]' | sed 's/://8')
        if [[ -n "$formatted_mac" && -z "${seen[$formatted_mac]}" ]]; then
            seen[$formatted_mac]=1
            mac_list+=("$formatted_mac")
        fi
    done < "$file"

    if (( ${#mac_list[@]} == 0 )); then
        print_warning "No se encontraron MACs válidas."
        return
    fi

    printf "%-20s %-50s\n" "MAC ADDRESS" "VENDOR"
    printf "%-20s %-50s\n" "--------------------" "--------------------------------------------------"

    for mac in "${mac_list[@]}"; do
        vendor=$(lookup_vendor "$mac")
        printf "%-20s %-50s\n" "$mac" "$vendor"
        sleep 1
    done

    print_success "Total de MACs encontradas: ${#mac_list[@]}"
}
# ---------------------------
# attack
# ---------------------------
attack() {
    local mac="$1"
    local mask="$2"
    local dbfile="database.hc22000"

    if [[ -z "$mac" || -z "$mask" ]]; then
        print_error "Uso: attack <mac> <máscara>"
        return 1
    fi
    if [[ ! -f "$dbfile" ]]; then
        print_error "Base de datos no encontrada: $dbfile."
        return 1
    fi

    print_info "Buscando hash correspondiente a $mac..."
    temp_file="hash_${mac//:/}.hc22000"
    grep -i "${mac//:/}" "$dbfile" > "$temp_file"
    if [[ ! -s "$temp_file" ]]; then
        print_error "No se encontró ningún hash para esa MAC."
        rm -f "$temp_file"
        return 1
    fi
    print_info "Ejecutando Hashcat..."
    hashcat -m 22000 "$temp_file" -a 3 "$mask"
    print_success "Ataque completado (usa --show para ver resultados)."
}

# ---------------------------
# Interfaz interactiva
# ---------------------------
main() {
    check_root
    check_dependencies
    show_banner
    show_help

    local PROMPT_COLOR="${CYAN}"
    local PROMPT_NAME="<wifi_audit_tool>"
    local PROMPT_RESET="${NC}"

    while true; do
        echo ""
        read -e -p "$(echo -e "${PROMPT_COLOR}${PROMPT_NAME}${PROMPT_RESET} ▶ ${WHITE}")" -a cmd
        case "${cmd[0]}" in
            analyze) analyze "${cmd[1]}" "${cmd[2]}";;
            lsmac) lsmac "${cmd[1]}";;
            attack) attack "${cmd[1]}" "${cmd[2]}";;
            help) show_help;;
            exit|quit) print_info "Saliendo..."; break;;
            *) print_error "Comando no reconocido: ${cmd[0]}";;
        esac
    done
}

main