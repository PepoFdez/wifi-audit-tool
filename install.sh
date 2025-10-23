
# Create installation script
install_script = """#!/bin/bash

# WiFi Auditing Tool - Installation Script
# Este script instala y configura la herramienta de auditoría WiFi

set -e

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════╗"
echo "║  WiFi Auditing Tool - Instalación     ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "Este script debe ejecutarse con sudo"
   exit 1
fi

# Detect OS
print_info "Detectando sistema operativo..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
    print_success "Detectado: $PRETTY_NAME"
else
    print_error "No se pudo detectar el sistema operativo"
    exit 1
fi

# Update package lists
print_info "Actualizando lista de paquetes..."
case $OS in
    ubuntu|debian|kali)
        apt-get update -qq
        print_success "Lista de paquetes actualizada"
        ;;
    arch|manjaro)
        pacman -Sy --noconfirm
        print_success "Lista de paquetes actualizada"
        ;;
    fedora|centos|rhel)
        dnf check-update || true
        print_success "Lista de paquetes actualizada"
        ;;
    *)
        print_warning "Sistema no reconocido, intentando continuar..."
        ;;
esac

# Install dependencies
print_info "Instalando dependencias..."

case $OS in
    ubuntu|debian|kali)
        apt-get install -y hcxdumptool hcxtools hashcat python3 || {
            print_error "Error instalando dependencias"
            exit 1
        }
        ;;
    arch|manjaro)
        pacman -S --noconfirm hcxdumptool hcxtools hashcat python || {
            print_error "Error instalando dependencias"
            exit 1
        }
        ;;
    fedora|centos|rhel)
        dnf install -y hcxdumptool hcxtools hashcat python3 || {
            print_error "Error instalando dependencias"
            exit 1
        }
        ;;
    *)
        print_error "Sistema operativo no soportado: $OS"
        exit 1
        ;;
esac

print_success "Dependencias instaladas correctamente"

# Create installation directory
INSTALL_DIR="/opt/wifi-audit-tool"
print_info "Creando directorio de instalación: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy scripts (assuming they're in the same directory)
print_info "Copiando scripts..."
if [ -f "wifi_audit_tool.sh" ]; then
    cp wifi_audit_tool.sh "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/wifi_audit_tool.sh"
    print_success "wifi_audit_tool.sh copiado"
fi

if [ -f "wifi_audit_standalone.sh" ]; then
    cp wifi_audit_standalone.sh "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/wifi_audit_standalone.sh"
    print_success "wifi_audit_standalone.sh copiado"
fi

if [ -f "wifi_audit_tool.py" ]; then
    cp wifi_audit_tool.py "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/wifi_audit_tool.py"
    print_success "wifi_audit_tool.py copiado"
fi

# Create symbolic links
print_info "Creando enlaces simbólicos en /usr/local/bin..."
ln -sf "$INSTALL_DIR/wifi_audit_tool.sh" /usr/local/bin/wifi-audit
ln -sf "$INSTALL_DIR/wifi_audit_standalone.sh" /usr/local/bin/wifi-audit-standalone
ln -sf "$INSTALL_DIR/wifi_audit_tool.py" /usr/local/bin/wifi-audit-py
print_success "Enlaces creados"

# Create captures directory
CAPTURES_DIR="$HOME/wifi-audits"
print_info "Creando directorio para capturas: $CAPTURES_DIR"
mkdir -p "$CAPTURES_DIR"
chown $SUDO_USER:$SUDO_USER "$CAPTURES_DIR" 2>/dev/null || true
print_success "Directorio de capturas creado"

# Verify installation
print_info "Verificando instalación..."
errors=0

for cmd in hcxdumptool hcxpcapngtool hashcat; do
    if command -v $cmd &> /dev/null; then
        print_success "$cmd: OK"
    else
        print_error "$cmd: NO ENCONTRADO"
        errors=$((errors + 1))
    fi
done

if [ $errors -gt 0 ]; then
    print_error "Instalación incompleta. Faltan $errors herramientas."
    exit 1
fi

echo ""
echo "╔════════════════════════════════════════╗"
echo "║      Instalación Completada ✓          ║"
echo "╚════════════════════════════════════════╝"
echo ""
print_success "WiFi Auditing Tool instalado correctamente"
echo ""
echo "Comandos disponibles:"
echo "  ${GREEN}wifi-audit${NC}            - Versión interactiva (Bash)"
echo "  ${GREEN}wifi-audit-standalone${NC} - Versión comandos directos (Bash)"
echo "  ${GREEN}wifi-audit-py${NC}         - Versión Python"
echo ""
echo "Ejemplos de uso:"
echo "  ${YELLOW}sudo wifi-audit${NC}"
echo "  ${YELLOW}sudo wifi-audit-standalone analyze wlan0 captura.pcapng${NC}"
echo "  ${YELLOW}sudo wifi-audit-py analyze wlan0 captura.pcapng${NC}"
echo ""
echo "Directorio de capturas: ${BLUE}$CAPTURES_DIR${NC}"
echo "Archivos de herramienta: ${BLUE}$INSTALL_DIR${NC}"
echo ""
print_warning "Recuerda: Usar solo con autorización explícita"
echo ""
"""

with open('/tmp/install.sh', 'w') as f:
    f.write(install_script)

print("Script de instalación guardado en: /tmp/install.sh")
print("\nPara instalar:")
print("1. Copia todos los archivos a un directorio")
print("2. chmod +x install.sh")
print("3. sudo ./install.sh")
