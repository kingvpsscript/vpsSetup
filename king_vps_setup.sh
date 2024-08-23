#!/bin/bash
clear
cd $HOME
SCPdir="/etc/newadm"
SCPinstal="$HOME/install"
SCPidioma="${SCPdir}/idioma"
SCPusr="${SCPdir}/user"
SCPfrm="/etc/user-txt"
SCPinst="/etc/inst-txt"
[[ -e /etc/bash.bashrc-bakup ]] && mv -f /etc/bash.bashrc-bakup /etc/bash.bashrc
rm -rf $SCPdir 2>/dev/null
rm -rf $SCPinst 2>/dev/null
rm -rf $SCPfrm 2>/dev/null

fun_bar () {
command[0]="$1"
command[1]="$2"
 (
[[ -e $HOME/fin ]] && rm $HOME/fin
${command[0]} -y > /dev/null 2>&1
${command[1]} -y > /dev/null 2>&1
touch $HOME/fin
 ) > /dev/null 2>&1 &
 tput civis
echo -ne "  \033[1;33mWAIT \033[1;37m- \033[1;33m["
while true; do
   for((i=0; i<18; i++)); do
   echo -ne "\033[1;31m#"
   sleep 0.1s
   done
   [[ -e $HOME/fin ]] && rm $HOME/fin && break
   echo -e "\033[1;33m]"
   sleep 1s
   tput cuu1
   tput dl1
   echo -ne "  \033[1;33mWAIT \033[1;37m- \033[1;33m["
done
echo -e "\033[1;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
tput cnorm
}

install_packages() {
    echo -e "\033[1;33mInstalling necessary packages...\033[0m"
    fun_bar 'apt-get update' 'apt-get upgrade -y'
    fun_bar 'apt-get install curl -y' 'apt-get install apache2 -y'
    fun_bar 'apt-get install php -y' 'apt-get install libapache2-mod-php -y'
    fun_bar 'apt-get install screen -y' 'apt-get install python -y'
    fun_bar 'apt-get install lsof -y' 'apt-get install python3-pip -y'
    fun_bar 'apt-get install unzip -y' 'apt-get install zip -y'
    fun_bar 'apt-get install ufw -y' 'apt-get install nmap -y'
    fun_bar 'apt-get install figlet -y' 'apt-get install bc -y'
    fun_bar 'apt-get install lynx -y' 'apt-get install curl -y'
}

configure_apache() {
    echo -e "\033[1;33mConfiguring Apache...\033[0m"
    sed -i "s;Listen 80;Listen 81;g" /etc/apache2/ports.conf
    service apache2 restart
}

install_script() {
    echo -e "\033[1;33mInstalling script...\033[0m"
    fun_bar "$SCPinstal/list 'rm -rf /var/www/html' && 'mkdir /var/www/html'"
    fun_bar "$SCPinstal/list 'cp -af /etc/newadm/html/. /var/www/html/'"
    fun_bar "$SCPinstal/list 'chmod -R 755 /var/www/html'"
    fun_bar "$SCPinstal/list 'service apache2 restart'"
}

install_newadm() {
    echo -e "\033[1;33mInstalling NEW-ULTIMATE...\033[0m"
    fun_bar "$SCPinstal/list 'mkdir /etc/newadm'"
    fun_bar "$SCPinstal/list 'cd /etc/newadm && wget https://raw.githubusercontent.com/lacasitamx/scripts/master/instalador/instalscript'"
    fun_bar "$SCPinstal/list 'cd /etc/newadm && chmod +x instalscript && ./instalscript'"
}

error_fun () {
echo -e "\033[1;31mYour linux distribution is not compatible!"
echo -e "\033[1;31mUse Ubuntu 16 - 18 or higher\033[0m"
}

os_system () {
system=$(echo $(cat -n /etc/issue |grep 1 |cut -d' ' -f6,7,8 |sed 's/1//' |sed 's/      //'))
echo $system|awk '{print $1, $2}'
}

remove_script () {
clear
echo -e "\033[1;36mUNINSTALLING SCRIPT\033[0m"
echo ""
echo -e "\033[1;36mRemoving installed packages\033[0m"
echo ""
fun_bar "apt-get remove screen -y"
fun_bar "apt-get remove python -y"
fun_bar "apt-get remove lsof -y"
fun_bar "apt-get remove python3-pip -y"
fun_bar "apt-get remove python -y"
fun_bar "apt-get remove unzip -y"
fun_bar "apt-get remove zip -y"
fun_bar "apt-get remove apache2 -y"
fun_bar "apt-get remove ufw -y"
fun_bar "apt-get remove nmap -y"
fun_bar "apt-get remove figlet -y"
fun_bar "apt-get remove bc -y"
fun_bar "apt-get remove lynx -y"
fun_bar "apt-get remove curl -y"
sed -i "s;Listen 81;Listen 80;g" /etc/apache2/ports.conf
service apache2 restart > /dev/null 2>&1
echo ""
echo -e "\033[1;36mRemoving script files\033[0m"
echo ""
fun_bar "rm -rf /etc/newadm"
fun_bar "rm -rf /var/www/html"
fun_bar "rm -rf /usr/bin/menu"
fun_bar "rm -rf /bin/menu"
fun_bar "rm -rf /usr/bin/adm"
fun_bar "rm -rf /bin/adm"
echo ""
echo -e "\033[1;36mScript removed successfully!\033[0m"
}

while true $x != "ok"
do
if [[ "$(whoami)" != "root" ]]; then
clear
echo -e "\033[1;31mEXECUTE AS ROOT USER\033[0m"
exit
elif [[ "$(os_system)" = "Ubuntu" ]]; then
clear
echo -e "\033[1;37mYOU ARE USING UBUNTU 16 - 18!\033[0m"
echo -e "\033[1;33mTO CONTINUE TYPE \033[1;32msi \033[1;33mOR \033[1;32mno\033[0m"
read -p " : " x
[[ $x = @(n|N|no|NO) ]] && error_fun && exit
[[ $x = @(y|Y|s|S|si|SI) ]] && install_packages && configure_apache && install_script && install_newadm
elif [[ "$(os_system)" = "Debian" ]]; then
clear
echo -e "\033[1;37mYOU ARE USING DEBIAN 9 - 10!\033[0m"
echo -e "\033[1;33mTO CONTINUE TYPE \033[1;32msi \033[1;33mOR \033[1;32mno\033[0m"
read -p " : " x
[[ $x = @(n|N|no|NO) ]] && error_fun && exit
[[ $x = @(y|Y|s|S|si|SI) ]] && install_packages && configure_apache && install_script && install_newadm
elif [[ "$(os_system)" = "Ubuntu 20" ]]; then
clear
echo -e "\033[1;37mYOU ARE USING UBUNTU 20!\033[0m"
echo -e "\033[1;33mTO CONTINUE TYPE \033[1;32msi \033[1;33mOR \033[1;32mno\033[0m"
read -p " : " x
[[ $x = @(n|N|no|NO) ]] && error_fun && exit
[[ $x = @(y|Y|s|S|si|SI) ]] && install_packages && configure_apache && install_script && install_newadm
else
clear
echo -e "\033[1;31mUNSUPPORTED SYSTEM\033[0m"
echo -e "\033[1;31mUse Ubuntu 16 - 18 or higher\033[0m"
exit
fi
done

echo ""
echo -e "\033[1;33mInstallation completed!"
echo ""
echo -e "\033[1;31m\033[1;33mMain Command: \033[1;32mmenu\033[0m"
echo -e "\033[1;33mMore information \033[1;31m(\033[1;36mTELEGRAM\033[1;31m): \033[1;37m@LACASITAMX\033[0m"
rm -rf $SCPdir/README.md && rm -rf $SCPdir/install.sh
rm -rf $SCPdir/instalscript
