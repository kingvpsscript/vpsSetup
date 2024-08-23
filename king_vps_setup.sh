#!/bin/bash
clear
cd $HOME

# Define directories
SCPdir="/etc/newadm"
SCPinstal="$HOME/install"
SCPidioma="${SCPdir}/idioma"
SCPusr="${SCPdir}/ger-user"
SCPfrm="/etc/ger-frm"
SCPinst="/etc/ger-inst"

# Create directories
mkdir -p ${SCPdir} ${SCPusr} ${SCPfrm} ${SCPinst} ${SCPinstal}

# Function to display colored messages
msg () {
    BRAN='\033[1;37m' && VERMELHO='\e[31m' && VERDE='\e[32m' && AMARELO='\e[33m'
    AZUL='\e[34m' && MAGENTA='\e[35m' && MAG='\033[1;36m' && NEGRITO='\e[1m' && SEMCOR='\e[0m'
    case $1 in
        -ne)cor="${VERMELHO}${NEGRITO}" && echo -ne "${cor}${2}${SEMCOR}";;
        -ama)cor="${AMARELO}${NEGRITO}" && echo -e "${cor}${2}${SEMCOR}";;
        -verm)cor="${AMARELO}${NEGRITO}[!] ${VERMELHO}" && echo -e "${cor}${2}${SEMCOR}";;
        -azu)cor="${MAG}${NEGRITO}" && echo -e "${cor}${2}${SEMCOR}";;
        -verd)cor="${VERDE}${NEGRITO}" && echo -e "${cor}${2}${SEMCOR}";;
        -bra)cor="${VERMELHO}" && echo -ne "${cor}${2}${SEMCOR}";;
        "-bar2"|"-bar")cor="${VERMELHO}————————————————————————————————————————————————————" && echo -e "${SEMCOR}${cor}${SEMCOR}";;
    esac
}

# Function to get IP address
fun_ip () {
    MIP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    MIP2=$(wget -qO- ipv4.icanhazip.com)
    [[ "$MIP" != "$MIP2" ]] && IP="$MIP2" || IP="$MIP"
}

# Function to install components
inst_components () {
    for pkg in nano bc screen python python3 curl unzip zip wget; do
        [[ $(dpkg --get-selections|grep -w "$pkg"|head -1) ]] || apt-get install $pkg -y &>/dev/null
    done
    [[ $(dpkg --get-selections|grep -w "apache2"|head -1) ]] || {
        apt-get install apache2 -y &>/dev/null
        sed -i "s;Listen 80;Listen 81;g" /etc/apache2/ports.conf
        service apache2 restart > /dev/null 2>&1 &
    }
}

# Function to set language
funcao_idioma () {
    msg -bar2
    declare -A idioma=( [1]="en English" [2]="fr French" [3]="de German" [4]="it Italian" [5]="pl Polish" [6]="pt Portuguese" [7]="es Spanish" [8]="tr Turkish" )
    for ((i=1; i<=8; i++)); do
        echo -ne "\033[1;32m[$i] > \033[1;33m${idioma[$i]}\n"
    done
    msg -bar2
    echo -ne "\033[1;37mSelect Language: " && read selection
    [[ -z $selection ]] && selection="1"
    [[ ! $(echo "${selection}" | egrep '[1-8]') ]] && selection="1"
    id="${idioma[$selection]}"
    [[ -z $id ]] && id="en English"
    echo "$id" > ${SCPidioma}
}

# Function to display installation completion message
install_fim () {
    msg -ama "Installation Complete, Use the Commands: menu / adm"
    msg -bar2
}

# Function to verify and move files
verificar_arq () {
    case $1 in
        "menu"|"message.txt")ARQ="${SCPdir}/";;
        "usercodes")ARQ="${SCPusr}/";;
        "openssh.sh")ARQ="${SCPinst}/";;
        "squid.sh")ARQ="${SCPinst}/";;
        "dropbear.sh")ARQ="${SCPinst}/";;
        "openvpn.sh")ARQ="${SCPinst}/";;
        "ssl.sh")ARQ="${SCPinst}/";;
        "shadowsocks.sh")ARQ="${SCPinst}/";;
        "sockspy.sh"|"PDirect.py"|"PPub.py"|"PPriv.py"|"POpen.py"|"PGet.py")ARQ="${SCPinst}/";;
        *)ARQ="${SCPfrm}/";;
    esac
    mv -f ${SCPinstal}/$1 ${ARQ}/$1
    chmod +x ${ARQ}/$1
}

# Main installation process
fun_ip
msg -bar2
msg -ama "[ SCRIPT MOD LACASITA \033[1;37m ]\033[1;33m[OFFICIAL]"
funcao_idioma

msg -bar2
msg -ama "WELCOME, THANKS FOR USING: \033[1;31m[SCRIPT MOD LACASITA]"
[[ ! -d ${SCPinstal} ]] && mkdir ${SCPinstal}
inst_components

# Simulating file downloads (replace with actual downloads if needed)
echo "#!/bin/bash" > ${SCPinstal}/menu
echo "echo 'Menu functionality not implemented yet.'" >> ${SCPinstal}/menu
verificar_arq "menu"

echo "This is a message" > ${SCPinstal}/message.txt
verificar_arq "message.txt"

# Create symbolic links
ln -sf ${SCPdir}/menu /usr/bin/menu
ln -sf ${SCPdir}/menu /usr/bin/adm

# Clean up
[[ -d ${SCPinstal} ]] && rm -rf ${SCPinstal}

install_fim

# End of script
