#!/bin/bash

# Function to print messages in color
print_msg() {
    local color=$1
    local msg=$2
    case $color in
        "red") echo -e "\033[31m$msg\033[0m" ;;
        "green") echo -e "\033[32m$msg\033[0m" ;;
        "yellow") echo -e "\033[33m$msg\033[0m" ;;
        *) echo "$msg" ;;
    esac
}

# Function to install a package if not already installed
install_package() {
    local package=$1
    if ! dpkg -l | grep -q $package; then
        print_msg "yellow" "Installing $package..."
        apt install -y $package
        if [ $? -ne 0 ]; then
            print_msg "red" "Error installing $package."
            exit 1
        fi
    else
        print_msg "green" "$package is already installed."
    fi
}

# Update and install necessary packages
apt update && apt upgrade -y
install_package "dropbear"
install_package "v2ray"
install_package "curl"
install_package "nano"
install_package "python3"
install_package "python3-pip"

# Functions to manage users
add_user() {
    read -p "Enter username: " username
    if id "$username" &>/dev/null; then
        print_msg "red" "User $username already exists."
        return
    fi
    read -s -p "Enter password: " password
    echo
    useradd -m -s /bin/bash $username
    echo "$username:$password" | chpasswd
    if [ $? -ne 0 ]; then
        print_msg "red" "Failed to add user $username."
    else
        print_msg "green" "User $username added successfully."
    fi
}

delete_user() {
    read -p "Enter username: " username
    if ! id "$username" &>/dev/null; then
        print_msg "red" "User $username does not exist."
        return
    fi
    userdel -r $username
    if [ $? -ne 0 ]; then
        print_msg "red" "Failed to delete user $username."
    else
        print_msg "green" "User $username deleted successfully."
    fi
}

list_users() {
    print_msg "yellow" "Listing all users:"
    cut -d: -f1 /etc/passwd
}

# Function to configure ports
configure_ports() {
    read -p "Enter new SSH port: " ssh_port
    read -p "Enter new Dropbear port: " dropbear_port
    read -p "Enter new V2Ray port: " v2ray_port

    # Update SSH port
    if [ ! -z "$ssh_port" ]; then
        sed -i "s/#Port 22/Port $ssh_port/" /etc/ssh/sshd_config
        systemctl restart sshd
        print_msg "green" "SSH port updated to $ssh_port."
    fi
    
    # Update Dropbear port
    if [ ! -z "$dropbear_port" ]; then
        sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=$dropbear_port/" /etc/default/dropbear
        systemctl restart dropbear
        print_msg "green" "Dropbear port updated to $dropbear_port."
    fi

    # Update V2Ray configuration
    if [ ! -z "$v2ray_port" ]; then
        sed -i "s/\"port\": .*/\"port\": $v2ray_port,/" /etc/v2ray/config.json
        systemctl restart v2ray
        print_msg "green" "V2Ray port updated to $v2ray_port."
    fi
}

# Function to configure V2Ray VLESS
configure_v2ray() {
    cat <<EOF > /etc/v2ray/config.json
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$(uuidgen)",
            "level": 1,
            "email": "user@v2ray.com"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

    systemctl restart v2ray
    if [ $? -ne 0 ]; then
        print_msg "red" "Failed to configure V2Ray VLESS."
    else
        print_msg "green" "V2Ray VLESS configured successfully."
    fi
}

# Function to configure Python proxy
configure_python_proxy() {
    pip3 install -U proxy.py
    cat <<EOF > /etc/systemd/system/python-proxy.service
[Unit]
Description=Python Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/proxy
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable python-proxy
    systemctl start python-proxy
    if [ $? -ne 0 ]; then
        print_msg "red" "Failed to configure Python proxy."
    else
        print_msg "green" "Python proxy configured successfully."
    fi
}

# Function to configure SSH banner
configure_ssh_banner() {
    cat <<'EOF' > /etc/issue.net
Welcome to your server!
Unauthorized access is prohibited.
EOF

    sed -i 's/#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    systemctl restart sshd
    if [ $? -ne 0 ]; then
        print_msg "red" "Failed to configure SSH banner."
    else
        print_msg "green" "SSH banner configured successfully."
    fi
}

# Function to configure Python proxy banner
configure_python_proxy_banner() {
    cat <<'EOF' > /etc/python-proxy-banner.txt
Welcome to the Python Proxy service!
Unauthorized access is prohibited.
EOF
    print_msg "green" "Python proxy banner configured. Apply it in your proxy configuration as needed."
}

# Admin menu
admin_menu() {
    PS3='Please enter your choice: '
    options=("Add User" "Delete User" "List Users" "Configure Ports" "Configure V2Ray" "Configure Python Proxy" "Configure SSH Banner" "Configure Python Proxy Banner" "Quit")
    select opt in "${options[@]}"
    do
        case $opt in
            "Add User")
                add_user
                ;;
            "Delete User")
                delete_user
                ;;
            "List Users")
                list_users
                ;;
            "Configure Ports")
                configure_ports
                ;;
            "Configure V2Ray")
                configure_v2ray
                ;;
            "Configure Python Proxy")
                configure_python_proxy
                ;;
            "Configure SSH Banner")
                configure_ssh_banner
                ;;
            "Configure Python Proxy Banner")
                configure_python_proxy_banner
                ;;
            "Quit")
                break
                ;;
            *) print_msg "red" "Invalid option $REPLY";;
        esac
    done
}

# Initial setup
print_msg "yellow" "Configuring Dropbear..."
sed -i 's/NO_START=1/NO_START=0/' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=4422/' /etc/default/dropbear
systemctl enable dropbear
systemctl start dropbear

print_msg "yellow" "Setting up V2Ray..."
curl -L -o /etc/v2ray/v2ray.zip https://github.com/v2ray/v2ray-core/releases/download/v4.27.0/v2ray-linux-64.zip
unzip /etc/v2ray/v2ray.zip -d /etc/v2ray/
chmod +x /etc/v2ray/v2ray /etc/v2ray/v2ctl
configure_v2ray

print_msg "yellow" "Configuring Python proxy..."
configure_python_proxy

print_msg "yellow" "Configuring SSH banner..."
configure_ssh_banner

print_msg "yellow" "Configuring Python proxy banner..."
configure_python_proxy_banner

print_msg "yellow" "Starting admin menu..."
admin_menu

# Create a script for the admin menu that can be run anytime
cat <<'EOF' > /usr/local/bin/admin_menu.sh
#!/bin/bash

PS3='Please enter your choice: '
options=("Add User" "Delete User" "List Users" "Configure Ports" "Configure V2Ray" "Configure Python Proxy" "Configure SSH Banner" "Configure Python Proxy Banner" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Add User")
            sudo add_user
            ;;
        "Delete User")
            sudo delete_user
            ;;
        "List Users")
            sudo list_users
            ;;
        "Configure Ports")
            sudo configure_ports
            ;;
        "Configure V2Ray")
            sudo configure_v2ray
            ;;
        "Configure Python Proxy")
            sudo configure_python_proxy
            ;;
        "Configure SSH Banner")
            sudo configure_ssh_banner
            ;;
        "Configure Python Proxy Banner")
            sudo configure_python_proxy_banner
            ;;
        "Quit")
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done
EOF

chmod +x /usr/local/bin/admin_menu.sh

print_msg "green" "Admin menu can be accessed anytime by running: sudo /usr/local/bin/admin_menu.sh"
