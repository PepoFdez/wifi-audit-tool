
# Create documentation file
documentation = """# WiFi Auditing Automation Tool

## Descripción

Herramienta de automatización para auditorías de seguridad WiFi IEEE 802.11 que facilita el proceso de captura, análisis y ataque a redes WiFi con contraseñas débiles, especialmente routers TP-LINK con contraseñas por defecto.

## Características

### Funcionalidades Principales

1. **Captura Automática de Tráfico WiFi**
   - Gestión automática de servicios NetworkManager y wpa_supplicant
   - Captura de handshakes EAPOL con hcxdumptool
   - Conversión automática a formato hashcat (hc22000)

2. **Análisis de Redes**
   - Extracción de direcciones MAC y SSIDs
   - Detección automática de routers TP-LINK por OUI
   - Filtrado y categorización de dispositivos

3. **Ataques Dirigidos**
   - Ataque a MACs específicas con hashcat
   - Soporte para máscaras personalizadas
   - Modo ataque brute-force optimizado

## Requisitos del Sistema

### Dependencias

```bash
# Herramientas principales
sudo apt install hcxdumptool hcxtools hashcat

# Para Python (opcional)
python3 (>= 3.7)
```

### Permisos

El script requiere privilegios de root para:
- Gestionar servicios de red
- Poner la interfaz en modo monitor
- Capturar tráfico de red

## Instalación

### Opción 1: Script Bash Interactivo

```bash
# Descargar el script
chmod +x wifi_audit_tool.sh

# Ejecutar en modo interactivo
sudo ./wifi_audit_tool.sh
```

### Opción 2: Script Bash Standalone

```bash
# Descargar el script
chmod +x wifi_audit_standalone.sh

# Usar comandos directos
sudo ./wifi_audit_standalone.sh analyze wlan0 captura.pcapng
./wifi_audit_standalone.sh lsmac captura.maclist
sudo ./wifi_audit_standalone.sh attack captura.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d
```

### Opción 3: Script Python

```bash
# Descargar el script
chmod +x wifi_audit_tool.py

# Modo interactivo
sudo python3 wifi_audit_tool.py

# Modo comando directo
sudo python3 wifi_audit_tool.py analyze wlan0 captura.pcapng
python3 wifi_audit_tool.py lsmac
sudo python3 wifi_audit_tool.py attack captura.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d
```

## Uso

### Comandos Disponibles

#### 1. analyze - Captura y Análisis

**Sintaxis:**
```bash
analyze <interfaz> <archivo.pcapng>
```

**Descripción:**
- Detiene servicios NetworkManager y wpa_supplicant
- Captura tráfico WiFi con hcxdumptool
- Extrae handshakes EAPOL
- Convierte a formato hashcat
- Filtra routers TP-LINK
- Reinicia servicios de red

**Ejemplo:**
```bash
analyze wlan0 captura_oficina.pcapng
```

**Archivos generados:**
- `captura_oficina.pcapng` - Captura raw
- `captura_oficina.hc22000` - Hashes para hashcat
- `captura_oficina.essid` - Lista de SSIDs
- `captura_oficina.maclist` - MACs categorizadas

#### 2. lsmac - Listar Redes Capturadas

**Sintaxis:**
```bash
lsmac [archivo.maclist] [filtro]
```

**Descripción:**
Lista las redes capturadas con formato tabular.

**Ejemplos:**
```bash
# Listar todas las redes del archivo más reciente
lsmac

# Listar de un archivo específico
lsmac captura_oficina.maclist

# Filtrar solo TP-LINK
lsmac TP-LINK

# Archivo específico con filtro
lsmac captura_oficina.maclist TP-LINK
```

**Salida:**
```
MAC ADDRESS          SSID                           VENDOR    
-------------------- ------------------------------ ----------
AA:BB:CC:DD:EE:FF    WiFi_Casa                      TP-LINK   
11:22:33:44:55:66    Movistar_Fibra                 OTHER     
```

#### 3. attack - Ataque con Hashcat

**Sintaxis:**
```bash
attack <archivo.hc22000> <mac> <máscara>
```

**Descripción:**
Extrae el hash de una MAC específica y ejecuta hashcat con la máscara indicada.

**Ejemplos:**
```bash
# Ataque con 8 dígitos
attack captura.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d

# Ataque con 10 dígitos
attack captura.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d?d?d

# Patrón personalizado: Capital + 4 minúsculas + 4 dígitos
attack captura.hc22000 AA:BB:CC:DD:EE:FF ?u?l?l?l?l?d?d?d?d
```

### Máscaras de Hashcat

| Símbolo | Descripción | Ejemplos |
|---------|-------------|----------|
| ?l | Letras minúsculas | a-z |
| ?u | Letras mayúsculas | A-Z |
| ?d | Dígitos | 0-9 |
| ?s | Símbolos especiales | !@#$%^&* |
| ?a | Todos los caracteres | ?l?u?d?s |

### Patrones Comunes de Contraseñas de Routers

#### TP-LINK
```bash
# 8 dígitos (común en muchos modelos)
?d?d?d?d?d?d?d?d

# 10 dígitos
?d?d?d?d?d?d?d?d?d?d

# 8 caracteres alfanuméricos
?a?a?a?a?a?a?a?a
```

#### Otros Routers
```bash
# Formato: Capital + palabra + 4 dígitos
?u?l?l?l?l?l?d?d?d?d

# 6 dígitos
?d?d?d?d?d?d

# Hexadecimal (A-F, 0-9)
?h?h?h?h?h?h?h?h
```

## Flujo de Trabajo Típico

### 1. Preparación
```bash
# Identificar interfaz WiFi
ip link show

# Verificar que la interfaz soporta modo monitor
iw list | grep -A 10 "Supported interface modes"
```

### 2. Captura
```bash
# Iniciar captura (modo interactivo)
sudo ./wifi_audit_tool.sh
wifi-audit> analyze wlan0 auditoria_$(date +%Y%m%d).pcapng

# Dejar capturando por 10-30 minutos para recoger handshakes
# Presionar Ctrl+C para detener
```

### 3. Análisis
```bash
# Listar todas las redes capturadas
wifi-audit> lsmac

# Filtrar solo TP-LINK
wifi-audit> lsmac TP-LINK
```

### 4. Ataque
```bash
# Atacar una red específica con patrón de 8 dígitos
wifi-audit> attack auditoria_20250122.hc22000 AA:BB:CC:DD:EE:FF ?d?d?d?d?d?d?d?d
```

### 5. Verificación de Resultados
```bash
# Ver contraseñas encontradas
hashcat -m 22000 hash_aabbccddeeff.hc22000 --show
```

## Mejoras y Optimizaciones Implementadas

### 1. Detección Inteligente de TP-LINK

El script incluye una base de datos completa de OUI (Organizationally Unique Identifier) de TP-LINK:

```bash
- 00:31:92, 00:5F:67, 10:27:F5, 14:EB:B6, 1C:61:B4
- 20:23:51, 24:2F:D0, 28:87:BA, 30:DE:4B, 34:60:F9
- Y más de 40 prefijos adicionales...
```

### 2. Gestión Automática de Servicios

```bash
# Antes de la captura
systemctl stop NetworkManager
systemctl stop wpa_supplicant

# Después de la captura
systemctl start wpa_supplicant
systemctl start NetworkManager
```

### 3. Conversión Automática de Formatos

El script maneja automáticamente:
- Conversión de pcapng → hc22000
- Extracción de ESSID de hexadecimal a ASCII
- Formateo de direcciones MAC

### 4. Manejo de Errores

- Verificación de privilegios root
- Validación de existencia de interfaces
- Comprobación de dependencias
- Manejo de interrupciones (Ctrl+C)

## Consideraciones de Seguridad

### Uso Ético

⚠️ **IMPORTANTE**: Esta herramienta está diseñada exclusivamente para:

1. Auditorías de seguridad autorizadas
2. Testing de penetración en redes propias
3. Evaluaciones de seguridad contractuales
4. Propósitos educativos en entornos controlados

### Aspectos Legales

El uso no autorizado de esta herramienta puede constituir:
- Acceso no autorizado a sistemas informáticos
- Violación de la privacidad
- Delitos informáticos según la legislación local

**Siempre obtén autorización por escrito antes de realizar cualquier auditoría.**

## Troubleshooting

### Error: "La interfaz no existe"

**Solución:**
```bash
# Listar interfaces disponibles
ip link show

# Verificar nombre correcto de interfaz WiFi
iw dev
```

### Error: "Herramientas faltantes"

**Solución:**
```bash
# Instalar en Debian/Ubuntu
sudo apt update
sudo apt install hcxdumptool hcxtools hashcat

# Instalar en Kali Linux
sudo apt install hcxdumptool hcxtools hashcat
```

### Error: "No se capturan handshakes"

**Causas comunes:**
1. Interfaz no soporta modo monitor
2. Tiempo de captura insuficiente
3. No hay clientes conectándose a las redes

**Solución:**
```bash
# Verificar capacidades de la interfaz
iw list

# Aumentar tiempo de captura (15-30 minutos)
# Considerar usar --enable_status para ver actividad
hcxdumptool -i wlan0 -w test.pcapng --enable_status=3
```

### Hashcat: "No se encuentra contraseña"

**Solución:**
```bash
# Verificar que la máscara es correcta
# Probar con máscaras incrementales
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d --increment

# Usar diccionarios específicos de routers
hashcat -m 22000 hash.hc22000 -a 0 router_passwords.txt
```

## Estructura de Archivos

```
proyecto/
├── wifi_audit_tool.sh           # Script bash interactivo
├── wifi_audit_standalone.sh      # Script bash comandos directos
├── wifi_audit_tool.py            # Script Python (más robusto)
├── README.md                     # Esta documentación
└── capturas/                     # Directorio para capturas
    ├── captura_20250122.pcapng
    ├── captura_20250122.hc22000
    ├── captura_20250122.maclist
    └── captura_20250122.essid
```

## Diferencias entre Versiones

### Bash Interactivo
- ✅ Interfaz de línea de comandos tipo shell
- ✅ Mantiene contexto entre comandos
- ✅ Colores y formato mejorado
- ⚠️ Requiere bash 4.0+

### Bash Standalone
- ✅ Comandos individuales sin estado
- ✅ Ideal para scripts automatizados
- ✅ Compatible con cron/systemd
- ✅ Menor complejidad

### Python
- ✅ Manejo robusto de errores
- ✅ Code más mantenible
- ✅ Type hints para claridad
- ✅ Modo interactivo y directo
- ⚠️ Requiere Python 3.7+

## Recursos Adicionales

### Referencias Técnicas
- [hcxdumptool GitHub](https://github.com/ZerBea/hcxdumptool)
- [Hashcat Wiki](https://hashcat.net/wiki/)
- [IEEE 802.11 Standard](https://standards.ieee.org/standard/802_11-2020.html)

### Herramientas Relacionadas
- Wireshark - Análisis de tráfico
- aircrack-ng - Suite WiFi alternativa
- John the Ripper - Cracking alternativo

## Licencia

Este software se proporciona "tal cual" sin garantías de ningún tipo. El autor no se hace responsable del uso indebido o ilegal de esta herramienta.

## Contribuciones

Para mejoras o reportar bugs:
1. Verifica que las dependencias estén actualizadas
2. Documenta el comportamiento esperado vs actual
3. Proporciona logs detallados

---

**Versión:** 1.0
**Última actualización:** Octubre 2025
**Autor:** WiFi Security Auditor
"""

with open('/tmp/README_wifi_audit.md', 'w') as f:
    f.write(documentation)

print("Documentación completa guardada en: /tmp/README_wifi_audit.md")
print("\nContenido incluido:")
print("- Guía de instalación completa")
print("- Documentación de todos los comandos")
print("- Ejemplos de uso prácticos")
print("- Flujo de trabajo típico")
print("- Troubleshooting común")
print("- Consideraciones éticas y legales")
