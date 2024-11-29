#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <cstdio>
#include <regex>
#include <fstream>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;
using namespace std;

// Variable global para guardar la interfaz seleccionada para enrutamiento
string interfazWan = "";
string direccionIPwan= "";
string mascaraCIDRwan = "";

string interfazLan = "";  
string direccionIPlan = "";
string mascaraCIDRlan = "";

string ipInicio;  // IP de inicio DHCP
string ipFinal;   // IP final DHCP
string identidadRedLan; // Red local, se ajusta automáticamente
string dnsLan = "1.1.1.1"; // DNS por defecto
string mascaraDecimalLan;  // Mascara completa ejemplo: 255.255.255.0
bool configuracionInterfaces=false; //Valida si las interfaces de red han sido configuradas
bool paquetesInstalados = false; 

// Lista de paquetes
vector<string> packages = {
    "isc-dhcp-server",
    "iptables-persistent"
};

//Muestra las interfaces de red y configuraciones
void obtenerInterfacesRed() {
    // Ejecuta el comando 'ip a' usando popen
    FILE *fp = popen("ip a", "r");
    if (fp == nullptr) {
        cerr << "Error al ejecutar el comando." << endl;
        return;
    }

    char linea[1024]; 
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
    if (!interfazActual.empty()) {
        interfaces.push_back(interfazActual);
    }
    // Mostrar las interfaces
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
        cout << "1) Interfaz de red para enrutamiento y DHCP\n";
        cout << "2) Volver\n";
        cout << "Selecciona una opción: ";
        cin >> opcion;

        switch (opcion) {
            case 1:{
                cout << "Nombre de la interfaz WAN: ";
                cin >> interfazWan;

                cout << "Dirección IP de la interfaz WAN(dhcp o ip): ";
                cin >> direccionIPwan;

                if (direccionIPwan != "dhcp") {
                    cout << "Máscara de red CIRD WAN: ";
                    cin >> mascaraCIDRwan;
                }

                cout << "Nombre de la interfaz LAN: ";
                cin >> interfazLan;

                cout << "Dirección IP LAN: ";
                cin >> direccionIPlan;

                cout << "Máscara de red CIRD: ";
                cin >> mascaraCIDRlan;

                // Configuracion Netplan
                string netplanFile = buscarArchivoNetplan();

                ofstream file(netplanFile);
                if (file.is_open()) {
                    file << "network:\n";
                    file << "  version: 2\n";
                    file << "  ethernets:\n";

                    // Configurar la interfaz WAN
                    file << "    " << interfazWan << ":\n";
                    if (direccionIPwan == "dhcp") {
                        file << "      dhcp4: true\n";
                    } else {
                        file << "      dhcp4: no\n";
                        file << "      addresses:\n";
                        file << "        - " << direccionIPwan << "/" << mascaraCIDRwan << "\n";
                    }

                    // Configurar la interfaz LAN
                    file << "    " << interfazLan << ":\n";
                    file << "      dhcp4: no\n";
                    file << "      addresses:\n";
                    file << "        - " << direccionIPlan << "/" << mascaraCIDRlan << "\n";
                    file.close();

                    // Aplicar los cambios de Netplan
                    system("clear");
                    if (system("sudo netplan apply") == 0) {
                        cout << "Configuración aplicada.\n";
                        configuracionInterfaces = true;
                    } else {
                        cerr << "Error al aplicar configuración de Netplan.\n";
                    }
                } else {
                    cout << "Error al abrir el archivo de configuración de Netplan.\n";
                }
                 }
                break;

            case 2:
                // Volver al menú principal
                system("clear");
                return;

            default:
                cout << "Opción no válida, intenta de nuevo.\n";
                break;
        }
    }
}

//                                                                               GESTION DE PAQUETES 

// Verifica si un paquete está instalado
bool is_package_installed(const string& package) {
    string command = "dpkg -l | grep -w " + package + " > /dev/null 2>&1";
    return system(command.c_str()) == 0;
}

void verificar_paquetes(const vector<string>& packages) {
    bool todos_instalados = true; // Variable local para verificar si todos están instalados

    for (const string& package : packages) {
        if (is_package_installed(package)) {
            cout << "- " << package << " [INSTALADO]" << endl;
        } else {
            cout << "- " << package << " [NO INSTALADO]" << endl;
            todos_instalados = false; // Si algún paquete no está instalado, cambiamos a false
        }
    }
    paquetesInstalados = todos_instalados;
}
// Instalar todos los paquetes necesarios
void instalar_paquetes(const vector<string>& packages) {
    cout << "Instalando todos los paquetes...\n";
    string command = "sudo apt update && sudo apt install -y";
    for (const auto& pkg : packages) {
        command += " " + pkg;
    }

    // Ejecutar el comando
    int result = system(command.c_str());
    system("clear");
    if (result == 0) {
        cout << "Paquetes instalados correctamente.\n";
    } else {
        cerr << "Error al instalar los paquetes.\n";
    }
}
void subMenu_Programas(){
    int op;
    do {
        cout << "--------Gestion de paquetes--------\n";
        // Verificación de instalación de cada paquete
        verificar_paquetes(packages);
        cout << "1. Instalar todos los paquetes\n";
        cout << "2. Salir\n";
        cout << "Opción: ";
        cin >> op;
        switch (op) {
            case 1:
                instalar_paquetes(packages);
                break;
            case 2:
                system("clear");
                return;
            default:
                cout << "Opción no válida. Intenta nuevamente.\n";
            break;
        }
    } while (op != 2);
}

//                                                                            ENRUTAMIENTO
void configurarEnrutamiento(){
    //Cargar el módulo iptable_nat
    cout << "Cargando el módulo iptable_nat..." << endl;
    system("sudo modprobe iptable_nat");

    //Activar el reenvío de paquetes IP
    cout << "Habilitando el reenvío de paquetes IP..." << endl;
    // Editar /etc/sysctl.conf para habilitar el reenvío
    system("sudo sed -i '/#net.ipv4.ip_forward=1iptables/d' /etc/sysctl.conf");
    system("sudo sed -i '/net.ipv4.ip_forward=1iptables/d' /etc/sysctl.conf");
    system("echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf");
    // Aplicar el cambio
    system("sudo sysctl -p");

    //Definir reglas de iptables para el enrutamiento y NAT
    cout << "Configurando reglas de iptables..." << endl;
    system(("sudo iptables -A FORWARD -i " + interfazLan + " -o " + interfazWan + " -j ACCEPT").c_str());
    system(("sudo iptables -A FORWARD -i " + interfazWan + " -o " + interfazLan + " -j ACCEPT").c_str());
    system(("sudo iptables -t nat -A POSTROUTING -o " + interfazWan + " -j MASQUERADE").c_str());

    //Verificar el reenvío de paquetes
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

    //Guardar las reglas de iptables para que persistan después del reinicio
    cout << "Guardando las reglas de iptables..." << endl;
    
    system("sudo netfilter-persistent save");
    system("sudo netfilter-persistent reload");

    cout << "Enrutamiento NAT configurado correctamente." << endl;
}
void submenuEnrutamiento() {
    if(!configuracionInterfaces){
        system("clear");
        cout << "Se deben configurar las interfaces de red \n";
        cout << "Para iniciar el enrutamiento \n";
        return;
    }
    int op;
    system("clear");
    do {
        cout << "---------Interfaces de enrutamiento----------" << endl;
        cout << "Interfaz WAN: " << interfazWan << endl;
        cout << "interfaz LAN: " << interfazLan << endl;
        cout << "---------------------------------------------" <<endl;
        cout << "1. Iniciar enrutamiento\n";
        cout << "2. Volver\n";
        cout << "Opción: ";
        cin >> op;
        switch (op) {
            case 1:
                configurarEnrutamiento();
                break;
            case 2:
            system("clear");
                return;
            default:
                cout << "Opción no válida. Intenta nuevamente.\n";
            break;
        }
    } while (op != 2);

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

// Función para calcular la máscara completa desde el formato CIDR
void calcularMascaraCompleta() {
    int cidr = stoi(mascaraCIDRlan);
    unsigned int mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF;
    mascaraDecimalLan = numToIp(mask);
}

// Función para calcular la identidad de red (por ejemplo, 192.168.1.0)
void calcularIdentidadRed() {
    unsigned int ipNum = ipToNum(direccionIPlan);
    unsigned int maskNum = ipToNum(mascaraDecimalLan);
    unsigned int redNum = ipNum & maskNum;
    identidadRedLan = numToIp(redNum);
}

// Función para calcular el rango de direcciones IP DHCP
void calcularRangoIps() {
    unsigned int redNum = ipToNum(identidadRedLan);
    unsigned int maskNum = ipToNum(mascaraDecimalLan);
    unsigned int broadcastNum = redNum | (~maskNum);  // Dirección de broadcast

    // La IP inicial será red + 1
    ipInicio = numToIp(redNum + 1);
    // La IP final será broadcast - 1
    ipFinal = numToIp(broadcastNum - 1);
}

// Función para iniciar el servicio DHCP
void iniciarServicioDhcp() {
    system("sudo systemctl start isc-dhcp-server");
    system("sudo systemctl enable isc-dhcp-server");
    system("clear");
    cout << "El servicio DHCP ha sido iniciado y habilitado." << endl;
    cout << "-----------------------------------------------" << endl;
}

// Función para editar el archivo /etc/dhcp/dhcpd.conf
void editarArchivoDhcpdConf() {
    string archivo = "/etc/dhcp/dhcpd.conf";
    ifstream file_in(archivo);
    if (!file_in.is_open()) {
        cerr << "Error: No se pudo abrir /etc/dhcp/dhcpd.conf para lectura.\n";
        return;
    }
    string line;
    stringstream buffer;
    bool encontrado = false;

    // Leer el archivo completo
    while (getline(file_in, line)) {
        if (line.find("subnet " + identidadRedLan) != string::npos) {
            encontrado = true;
            continue; 
        }
        buffer << line << endl;
    }
    file_in.close();

    // Reemplazamos o agregamos la configuración
    if (!encontrado) {
        buffer << "\nsubnet " << identidadRedLan << " netmask " << mascaraDecimalLan << " {\n";
        buffer << "    range " << ipInicio << " " << ipFinal << ";\n";
        buffer << "    option routers " << direccionIPlan << ";\n";
        buffer << "    option domain-name-servers " << dnsLan << ";\n";
        buffer << "    default-lease-time 600;\n";
        buffer << "    max-lease-time 7200;\n";
        buffer << "}\n";
    }

    // Guardar los cambios
    ofstream file_out(archivo);
    file_out << buffer.str();
    file_out.close();
    iniciarServicioDhcp();
}
// Función para editar el archivo /etc/default/isc-dhcp-server
void editarArchivoInterfaces() {
    ofstream file("/etc/default/isc-dhcp-server");
    if (file.is_open()) {
        file << "INTERFACESv4=\"" << interfazLan << "\"" << endl;
        file.close();
        editarArchivoDhcpdConf();
    } else {
        cerr << "No se pudo abrir el archivo /etc/default/isc-dhcp-server." << endl;
    }
}


//                                                                                    Menú dhcp
void submenuDHCP() {
    system("clear");
    verificar_paquetes(packages);
    system("clear");
    if(!configuracionInterfaces){       
        cout << "Se deben configurar las interfaces de red \n";
        cout << "Para iniciar el servicio DHCP \n";
        return;
    }
    if(!paquetesInstalados){
        cout << "Se deben instalar los paquetes necesarios\n";
        cout << "Revise la gestion de paquetes.\n";
        cout << "-------------------------------------------\n";
        return;
    }
    // Calcular valores iniciales
    calcularMascaraCompleta();
    calcularIdentidadRed();
    calcularRangoIps();
    while (true) {
        cout << "\n------- Configuracion DHCP -------" << endl;
        cout << "IP de Inicio: " << ipInicio << endl;
        cout << "IP final: " << ipFinal << endl;
        cout << "1) Cambiar rango de direcciones IP" << endl;
        cout << "2) Configurar DNS (por defecto 1.1.1.1)" << endl;
        cout << "3) Configurar Servidor DHCP" << endl;
        cout << "4) Volver" << endl;

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
                cout << "Dirección DNS (por defecto 1.1.1.1): ";
                cin >> dnsLan;
                if (dnsLan.empty()) {
                    dnsLan = "1.1.1.1";
                }
                break;
            }
            case 3: {
                // Mostrar configuración
                system("clear");
                cout << "-------------------------------------------"<<endl;
                cout << "\nConfiguración del Servidor DHCP:" << endl;
                cout << "Interfaz: " << interfazLan << endl;
                cout << "Rango de IPs: " << ipInicio << " - " << ipFinal << endl;
                cout << "DNS: " << dnsLan << endl;
                cout << "Gateway: " << direccionIPlan << endl;

                cout << "\n1) Iniciar servicio\n2) Volver\nOpción: ";
                int subOpcion;
                cin >> subOpcion;
                if (subOpcion == 1) {
                    editarArchivoInterfaces();
                }
                break;
            }
            case 4:
                system("clear");
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
        if (!interfazLan.empty()) {
        cout << "-----------------------------" << endl;
        cout << "Interfaz para la red: " << interfazLan << endl;
        cout << "IP: " << direccionIPlan << "/" << mascaraCIDRlan <<endl;
        }
        cout << "-------AUTO NET-------"<< endl;
        cout << "1) Interfaces de Red\n";
        cout << "2) Paquetes \n";
        cout << "3) Enrutamiento\n";
        cout << "4) Servicio DHCP\n";
        cout << "5) Salir\n";
        cout << "Opción: ";
        cin >> opcion;
        system("clear");
        switch (opcion) {
            case 1:
                submenuInterfaces();
                break;
            case 2:
                subMenu_Programas();
                break;
            case 3:
                submenuEnrutamiento();
                break;
            case 4:
                submenuDHCP();
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
