#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <cstdio>
#include <regex>
#include <fstream>
#include <filesystem>
#include <sstream>
namespace fs = std::filesystem;
using namespace std;

// Variable global para guardar la interfaz seleccionada para enrutamiento
string interfazWan = "";
string interfazLan = "";  // Para guardar la interfaz seleccionada
string direccionIPlan = "";           // Para guardar la dirección IP
string mascara = "";               // Para guardar la máscara de red
string ipInicio;  // IP de inicio por defecto
string ipFinal;   // IP final por defecto
string identidadRed; // Red local, se ajusta automáticamente
string dns = "1.1.1.1";             // DNS por defecto
string mascara_completa;  // Mascara completa (ejemplo: 255.255.255.0)
bool ipServer=false;
string direccionNat = ""; // Dirección IP de la interfaz WAN
string mascaraNat = ""; // Máscara de la interfaz WAN
// Lista de paquetes necesarios
    vector<string> packages = {
        "isc-dhcp-server",
        "iptables",
        "dnsmasq",
        "iproute2"
    };
void obtenerInterfacesRed() {
    // Ejecuta el comando 'ip a' usando popen
    FILE *fp = popen("ip a", "r");
    if (fp == nullptr) {
        cerr << "Error al ejecutar el comando." << endl;
        return;
    }

    char linea[1024]; // Buffer para almacenar cada línea
    vector<string> interfaces; // Para almacenar la salida completa de cada interfaz
    string interfazActual;
    
    // Lee la salida línea por línea desde el archivo que nos devuelve popen
    while (fgets(linea, sizeof(linea), fp) != nullptr) {
        string strLinea(linea); // Convierte el char[] a std::string
        if (strLinea.empty()) continue; // Ignorar líneas vacías

        // Si la línea comienza con un número (que indica el comienzo de una interfaz)
        if (isdigit(strLinea[0])) {
            // Si ya había datos en la interfaz actual, guárdalos
            if (!interfazActual.empty()) {
                interfaces.push_back(interfazActual);
            }
            interfazActual = strLinea; // Inicia una nueva interfaz
        } else {
            interfazActual += strLinea; // Añade la línea a la interfaz actual
        }
    }

    // Asegúrate de agregar la última interfaz al vector
    if (!interfazActual.empty()) {
        interfaces.push_back(interfazActual);
    }

    // Ahora imprime las interfaces de forma más ordenada y simple
    for (size_t i = 0; i < interfaces.size(); ++i) {
        string interfaz = interfaces[i];
        string nombreInterfaz;
        string ipv4;
        string ipv6;
        string estado;

        // Buscar el nombre de la interfaz
        smatch match;
        regex nombreRegex(R"(\d+: (\S+):)"); // Captura el nombre de la interfaz
        if (regex_search(interfaz, match, nombreRegex)) {
            nombreInterfaz = match[1];
        }

        // Buscar dirección IPv4
        regex ipv4Regex(R"(inet (\S+))"); // Captura la dirección IPv4
        if (regex_search(interfaz, match, ipv4Regex)) {
            ipv4 = match[1];
        }

        // Buscar dirección IPv6
        regex ipv6Regex(R"(inet6 (\S+))"); // Captura la dirección IPv6
        if (regex_search(interfaz, match, ipv6Regex)) {
            ipv6 = match[1];
        }

        // Buscar estado de la interfaz (UP o LOWER_UP)
        regex estadoRegex(R"(<([^>]*UP[^>]*|[^>]*LOWER_UP[^>]*)>)"); // Captura las etiquetas UP o LOWER_UP
        if (regex_search(interfaz, match, estadoRegex)) {
            estado = "Encendido"; // Si encontramos UP o LOWER_UP, la interfaz está encendida
        } else {
            estado = "Apagado"; // Si no, está apagada
        }

        // Mostrar la información de la interfaz procesada
        cout << "Interfaz: " << nombreInterfaz << endl;
        cout << "  Estado: " << estado << endl;
        if (!ipv4.empty()) {
            cout << "  IPv4: " << ipv4 << endl;
        } else {
            cout << "  IPv4: No disponible" << endl;
        }
        if (!ipv6.empty()) {
            cout << "  IPv6: " << ipv6 << endl;
        } else {
            cout << "  IPv6: No disponible" << endl;
        }
        cout << "-----------------------------" << endl;
    }

    // Cierra el archivo después de terminar
    fclose(fp);
}
// Función para buscar un archivo con extensión .yaml en el directorio /etc/netplan/
string buscarArchivoNetplan() {
    string directorio = "/etc/netplan/";
    string archivoNetplan = "";

    // Iterar sobre los archivos en el directorio /etc/netplan/
    for (const auto& entry : fs::directory_iterator(directorio)) {
        if (entry.is_regular_file() && entry.path().extension() == ".yaml") {
            archivoNetplan = entry.path().string(); // Guardar el primer archivo .yaml encontrado
            break;
        }
    }

    return archivoNetplan;
}
// Función para manejar el submenú de interfaces de red
void submenuInterfaces() {
    int opcion;
    string comando;

    while (true) {
        //system("clear");
        obtenerInterfacesRed();
        cout << "\nSubmenú de Interfaces de Red:\n";
        cout << "1) Seleccionar interfaz de red para enrutamiento y DHCP\n";
        cout << "2) Volver\n";
        cout << "Selecciona una opción: ";
        cin >> opcion;

        switch (opcion) {
            case 1:{
                // Seleccionar interfaz de red
                cout << "Introduce el nombre de la interfaz NAT: ";
                cin >> interfazWan;
                cout << "Interfaz NAT seleccionada: " << interfazWan << endl;

                // Dirección IP para la interfaz WAN
                cout << "Ingresa la dirección IP de la interfaz NAT (dhcp o dirección IP): ";
                cin >> direccionNat;

                if (direccionNat != "dhcp") {
                    cout << "Introduce la máscara de red para la interfaz NAT: ";
                    cin >> mascaraNat;
                }

                cout << "Introduce el nombre de la interfaz de red interna (LAN): ";
                cin >> interfazLan;

                cout << "Interfaz LAN seleccionada: " << interfazLan << endl;

                // Solicitar la dirección IP y la máscara para la interfaz LAN
                cout << "Introduce la dirección IP para la interfaz LAN: ";
                cin >> direccionIPlan;
                cout << "Introduce la máscara de red para la interfaz LAN: ";
                cin >> mascara;

                // Configuración permanente de IP en Netplan
                string netplanFile = buscarArchivoNetplan();

                ofstream file(netplanFile);
                if (file.is_open()) {
                    file << "network:\n";
                    file << "  version: 2\n";
                    file << "  ethernets:\n";

                    // Configurar la interfaz WAN
                    file << "    " << interfazWan << ":\n";
                    if (direccionNat == "dhcp") {
                        file << "      dhcp4: true\n";
                    } else {
                        file << "      dhcp4: false\n";
                        file << "      addresses:\n";
                        file << "        - " << direccionNat << "/" << mascaraNat << "\n";
                    }

                    // Configurar la interfaz LAN
                    file << "    " << interfazLan << ":\n";
                    file << "      dhcp4: false\n";
                    file << "      addresses:\n";
                    file << "        - " << direccionIPlan << "/" << mascara << "\n";
                    
                    file.close();

                    // Aplicar los cambios de Netplan
                    system("sudo netplan apply");

                    cout << "La configuración IP se ha realizado de manera permanente.\n";
                } else {
                    cout << "Error al abrir el archivo de configuración de Netplan.\n";
                } }
                break;

            case 2:
                // Volver al menú principal
                return;

            default:
                cout << "Opción no válida, intenta de nuevo.\n";
                break;
        }
    }
}



// Función que verifica si un paquete está instalado
bool is_package_installed(const string& package) {
    string command = "dpkg -l | grep -w " + package + " > /dev/null 2>&1";
    return system(command.c_str()) == 0;
}

// Función para instalar todos los paquetes necesarios
void install_all_packages() {
    cout << "Instalando todos los paquetes necesarios...\n";
    string command = "sudo apt update && sudo apt install -y isc-dhcp-server iptables dnsmasq net-tools iproute2";
    system(command.c_str());
    cout << "Paquetes instalados correctamente.\n";
}
void subMenu_Programas(){
    cout << "Verificador e instalador de paquetes\n";
    cout << "-----------------------------------------\n";

    // Verificación de instalación de cada paquete
    vector<string> package_status;
    for (const string& package : packages) {
        if (is_package_installed(package)) {
            package_status.push_back(package + " [INSTALADO]");
        } else {
            package_status.push_back(package + " [NO INSTALADO]");
        }
    }

    // Mostrar lista de paquetes con estado
    for (size_t i = 0; i < package_status.size(); ++i) {
        cout << "- " << package_status[i] << endl;
    }

    int op;
    do {
        cout << "1. Instalar todos los paquetes\n";
        cout << "2. Salir\n";
        cout << "Opción: ";
        cin >> op;

        switch (op) {
            case 1:
                install_all_packages();
                break;
            case 2:
                return;
            default:
                cout << "Opción no válida. Intenta nuevamente.\n";
            break;
        }
    } while (op != 2);
}

//                                                             MENU ENRUTAMIENTO
void configurarEnrutamiento() {
    // Paso 1: Cargar el módulo iptable_nat si no está activo
    cout << "Cargando el módulo iptable_nat..." << endl;
    system("sudo modprobe iptable_nat");

    // Paso 2: Activar el reenvío de paquetes IP
    cout << "Habilitando el reenvío de paquetes IP..." << endl;
    // Editar /etc/sysctl.conf para habilitar el reenvío
    system("sudo sed -i '/#net.ipv4.ip_forward=1iptables/d' /etc/sysctl.conf");
    system("sudo sed -i '/net.ipv4.ip_forward=1iptables/d' /etc/sysctl.conf");
    system("echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf");
    // Aplicar el cambio
    system("sudo sysctl -p");

    // Paso 3: Definir reglas de iptables para el enrutamiento y NAT
    cout << "Configurando reglas de iptables..." << endl;
    system(("sudo iptables -A FORWARD -i " + interfazLan + " -o " + interfazWan + " -j ACCEPT").c_str());
    system(("sudo iptables -A FORWARD -i " + interfazWan + " -o " + interfazLan + " -j ACCEPT").c_str());
    system(("sudo iptables -t nat -A POSTROUTING -o " + interfazWan + " -j MASQUERADE").c_str());

    // Paso 4: Verificar el reenvío de paquetes
    cout << "Verificando el reenvío de paquetes..." << endl;
    string resultado;
    FILE* fp = popen("cat /proc/sys/net/ipv4/ip_forward", "r");
    if (fp == nullptr) {
        cerr << "Error al ejecutar el comando para verificar el reenvío de paquetes." << endl;
        return;
    }
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        resultado += buffer;
    }
    fclose(fp);

    if (resultado.find("1") != string::npos) {
        cout << "El reenvío de paquetes está habilitado correctamente." << endl;
    } else {
        cout << "El reenvío de paquetes no está habilitado. Por favor, revisa la configuración." << endl;
    }

    // Paso 5: Guardar las reglas de iptables para que persistan después del reinicio
    cout << "Guardando las reglas de iptables..." << endl;
    system("sudo apt install -y iptables-persistent");
    system("sudo netfilter-persistent save");
    system("sudo netfilter-persistent reload");

    cout << "Enrutamiento NAT configurado correctamente." << endl;
    return;
}


//                                                         PARTE DEL MENU DHCP
// Función para convertir una dirección IP de cadena a un número
unsigned int ipToNum(const string& ip) {
    unsigned int num = 0;
    int octet[4];
    sscanf(ip.c_str(), "%d.%d.%d.%d", &octet[0], &octet[1], &octet[2], &octet[3]);
    num = (octet[0] << 24) | (octet[1] << 16) | (octet[2] << 8) | octet[3];
    return num;
}

// Función para convertir un número a dirección IP
string numToIp(unsigned int num) {
    stringstream ss;
    ss << ((num >> 24) & 0xFF) << "."
       << ((num >> 16) & 0xFF) << "."
       << ((num >> 8) & 0xFF) << "."
       << (num & 0xFF);
    return ss.str();
}

// Función para calcular la máscara completa desde el formato CIDR (ej. /24)
void calcularMascaraCompleta() {
    int cidr = stoi(mascara);
    unsigned int mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF;
    mascara_completa = numToIp(mask);
}

// Función para calcular la red (por ejemplo, 192.168.1.0)
void calcularIdentidadRed() {
    unsigned int ipNum = ipToNum(direccionIPlan);
    unsigned int maskNum = ipToNum(mascara_completa);
    unsigned int redNum = ipNum & maskNum;
    identidadRed = numToIp(redNum);
}

// Función para calcular el rango de direcciones IP
void calcularRangoIps() {
    unsigned int redNum = ipToNum(identidadRed);
    unsigned int maskNum = ipToNum(mascara_completa);
    unsigned int broadcastNum = redNum | (~maskNum);  // Dirección de broadcast

    // La IP inicial será red + 1
    ipInicio = numToIp(redNum + 1);
    // La IP final será broadcast - 1
    ipFinal = numToIp(broadcastNum - 1);
}

// Función para editar el archivo /etc/default/isc-dhcp-server
void editarArchivoInterfaces() {
    ofstream file("/etc/default/isc-dhcp-server");
    if (file.is_open()) {
        file << "INTERFACESv4=\"" << interfazLan << "\"" << endl;
        file.close();
    } else {
        cerr << "No se pudo abrir el archivo /etc/default/isc-dhcp-server." << endl;
    }
}

// Función para editar el archivo /etc/dhcp/dhcpd.conf
void editarArchivoDhcpdConf() {
    string archivo = "/etc/dhcp/dhcpd.conf";
    ifstream file_in(archivo);
    string line;
    stringstream buffer;
    bool encontrado = false;

    // Leemos el archivo completo
    while (getline(file_in, line)) {
        if (line.find("subnet " + identidadRed) != string::npos) {
            encontrado = true;
            continue;  // Omitimos el bloque existente de configuración de subnet
        }
        buffer << line << endl;
    }
    file_in.close();

    // Reemplazamos o agregamos la configuración
    if (!encontrado) {
        buffer << "\nsubnet " << identidadRed << " netmask " << mascara_completa << " {\n";
        buffer << "    range " << ipInicio << " " << ipFinal << ";\n";
        buffer << "    option routers " << direccionIPlan << ";\n";
        buffer << "    option domain-name-servers " << dns << ";\n";
        buffer << "    default-lease-time 600;\n";
        buffer << "    max-lease-time 7200;\n";
        buffer << "}\n";
    }

    // Guardamos los cambios
    ofstream file_out(archivo);
    file_out << buffer.str();
    file_out.close();
}

// Función para iniciar el servicio DHCP
void iniciarServicioDhcp() {
    system("sudo systemctl start isc-dhcp-server");
    system("sudo systemctl enable isc-dhcp-server");
    cout << "El servicio DHCP ha sido iniciado y habilitado." << endl;
}

// Menú principal
void menuDHCP() {
    calcularRangoIps();
    while (true) {
        cout << "\n--- Menú Principal ---" << endl;
        cout << "Rango de IP mínimo: " << ipInicio << endl;
        cout << "Rango de IP máximo: " << ipFinal << endl;
        cout << "1) Asignar rango de direcciones IP" << endl;
        cout << "2) Configurar DNS" << endl;
        cout << "3) Configurar Servidor DHCP" << endl;
        cout << "4) Salir" << endl;

        int opcion;
        cout << "Seleccione una opción: ";
        cin >> opcion;

        switch (opcion) {
            case 1: {
                cout << "Ingrese el rango de direcciones IP:" << endl;
                cout << "IP inicial: ";
                cin >> ipInicio;
                cout << "IP final: ";
                cin >> ipFinal;
                break;
            }
            case 2: {
                cout << "Ingrese la dirección DNS (por defecto 1.1.1.1): ";
                cin >> dns;
                if (dns.empty()) {
                    dns = "1.1.1.1";
                }
                break;
            }
            case 3: {
                // Calcular el rango de IPs
                calcularRangoIps();
                // Mostrar configuración
                cout << "\nConfiguración del Servidor DHCP:" << endl;
                cout << "Interfaz: " << interfazLan << endl;
                cout << "Rango de IPs: " << ipInicio << " - " << ipFinal << endl;
                cout << "DNS: " << dns << endl;
                cout << "Gateway: " << direccionIPlan << endl;

                cout << "\n1) Iniciar servicio\n2) Volver\nSeleccione una opción: ";
                int subOpcion;
                cin >> subOpcion;
                if (subOpcion == 1) {
                    editarArchivoInterfaces();
                    editarArchivoDhcpdConf();
                    iniciarServicioDhcp();
                }
                break;
            }
            case 4:
                cout << "Saliendo del programa..." << endl;
                return;
            default:
                cout << "Opción no válida, intente nuevamente." << endl;
        }
    }
}


//                                                                     MENU PRINCIPAL
void menuPrincipal() {
    int opcion;

    while (true) {
        //system("clear");
        
        if (!interfazLan.empty()) {
        cout << "-----------------------------" << endl;
        cout << "Interfaz para la red: " << interfazLan << endl;
        cout << "IP: " << direccionIPlan << "/" << mascara <<endl;
        }
        cout << "---Menú Principal---"<< endl;
        cout << "1) Interfaces de Red\n";
        cout << "2) Programas y recursos\n";
        cout << "3) Enrutamiento\n";
        cout << "4) Servicio DHCP\n";
        cout << "5) Salir\n";
        cout << "Selecciona una opción: ";
        cin >> opcion;
        //system("clear");
        switch (opcion) {
            case 1:
                submenuInterfaces();
                break;
            case 2:
                subMenu_Programas();
                break;
            case 3:
                configurarEnrutamiento();
                break;
            case 4:
                    // Calcular valores iniciales
                   calcularMascaraCompleta();
                   calcularIdentidadRed();
                menuDHCP();
                break;
            case 5:
                cout << "Saliendo...\n";
                exit(0);
            default:
                cout << "Opción no válida, intenta de nuevo.\n";
        }
    }
} 
int main() {
    menuPrincipal();
    return 0;
}
