#!/bin/bash

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display messages
show_message() {
    echo -e "${GREEN}$1${NC}"
}

# Function to display errors
show_error() {
    echo -e "${RED}Error: $1${NC}"
}

# Function to get user input
get_input() {
    read -p "$1: " input
    echo "$input"
}

# Function to get password input
get_password() {
    read -s -p "$1: " password
    echo "$password"
}

# Function to get yes/no input
get_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Function to get domain input
get_domain() {
    while true; do
        local domain=$(get_input "Enter your domain name (required)")
        if [ -n "$domain" ]; then
            echo "$domain"
            return
        else
            show_error "Domain name is required. Please enter a valid domain."
        fi
    done
}

# Function to install necessary components
install_components() {
    show_message "Installing necessary components..."
    
    # Update system
    apt update && apt upgrade -y
    # Install required packages
    apt install -y curl wget unzip jq python3 python3-pip nginx certbot python3-certbot-nginx uuid-runtime openssh-server
    # Install V2Ray
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    # Install BBR
    if ! lsmod | grep -q bbr; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
    fi
    # Install WebSocket to TCP proxy
    pip3 install websockify twisted

    # Set up VPS admin interface
    cp "$0" /usr/local/bin/vps_install.sh
    chmod +x /usr/local/bin/vps_install.sh

    cat > /usr/local/bin/vps_admin.sh <<EOF
#!/bin/bash
source /etc/vps_config.sh

while true; do
    read -p "Enter a command (type 'admin' for admin menu or 'exit' to quit): " command
    case \$command in
        admin)
            admin_menu
            ;;
        exit)
            echo "Exiting admin interface"
            exit 0
            ;;
        *)
            echo "Invalid command. Type 'admin' for admin menu or 'exit' to quit."
            ;;
    esac
done
EOF

    chmod +x /usr/local/bin/vps_admin.sh

    cat > /etc/systemd/system/vps_admin.service <<EOF
[Unit]
Description=VPS Admin Interface
After=network.target

[Service]
ExecStart=/usr/local/bin/vps_admin.sh
Restart=always
User=root
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable vps_admin.service
    systemctl start vps_admin.service

    show_message "All components installed successfully!"
}

# Function to configure V2Ray
configure_v2ray() {
    show_message "Configuring V2Ray..."
    
    VMESS_PORT=${VMESS_PORT:-10086}
    VLESS_PORT=${VLESS_PORT:-10087}
    VMESS_WS_PATH=${VMESS_WS_PATH:-/vmess}
    VLESS_WS_PATH=${VLESS_WS_PATH:-/vless}
    
    VMESS_UUID=$(uuidgen)
    VLESS_UUID=$(uuidgen)
    
    cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "inbounds": [
    {
      "port": $VMESS_PORT,
      "protocol": "vmess",
      "settings": {
        "clients": [{ "id": "$VMESS_UUID" }]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$VMESS_WS_PATH"
        }
      }
    },
    {
      "port": $VLESS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$VLESS_UUID" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$VLESS_WS_PATH"
        }
      }
    }
  ],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    systemctl restart v2ray
    show_message "V2Ray configured successfully!"
}

# Function to configure SSH
configure_ssh() {
    show_message "Configuring SSH..."
    
    SSH_PORT=${SSH_PORT:-22}
    SSH_WS_PORT=${SSH_WS_PORT:-80}
    SSH_WS_PATH=${SSH_WS_PATH:-/ssh}

    # Configure SSH
    sed -i "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
    echo "GatewayPorts yes" >> /etc/ssh/sshd_config
    echo "AllowUDPForwarding yes" >> /etc/ssh/sshd_config
    # Restart SSH service
    systemctl restart ssh

    # Create WebSocket to TCP proxy service
    cat > /etc/systemd/system/websockify.service <<EOF
[Unit]
Description=Websockify
After=network.target

[Service]
ExecStart=/usr/local/bin/websockify --web /usr/share/websockify $SSH_WS_PORT 127.0.0.1:$SSH_PORT
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable websockify
    systemctl start websockify
    show_message "SSH configured successfully!"
}

# Function to configure Nginx
configure_nginx() {
    show_message "Configuring Nginx..."
    
    # Install SSL certificate
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/v2ray <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location $VMESS_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$VMESS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location $VLESS_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$VLESS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location $SSH_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$SSH_WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    ln -sf /etc/nginx/sites-available/v2ray /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
    show_message "Nginx configured successfully!"
}

# Function to set up Python proxy
setup_python_proxy() {
    show_message "Setting up Python proxy..."
    
    PROXY_PORT=${PROXY_PORT:-8080}
    
    # Create Python proxy script
    cat > /usr/local/bin/python_proxy.py <<EOF
from twisted.internet import reactor, protocol
from twisted.protocols import basic

class ProxyProtocol(basic.LineReceiver):
    def connectionMade(self):
        self.sendLine(b"HTTP/1.1 101 Switching Protocols")
        self.sendLine(b"Upgrade: WebSocket")
        self.sendLine(b"Connection: Upgrade")
        self.sendLine(b"")
        self.sendLine(PROXY_MESSAGE.encode())

class ProxyFactory(protocol.ServerFactory):
    protocol = ProxyProtocol

PROXY_MESSAGE = "Welcome to Python Proxy"

if __name__ == "__main__":
    reactor.listenTCP($PROXY_PORT, ProxyFactory())
    reactor.run()
EOF

    # Create systemd service for Python proxy
    cat > /etc/systemd/system/python_proxy.service <<EOF
[Unit]
Description=Python Proxy
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/python_proxy.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable python_proxy
    systemctl start python_proxy
    show_message "Python proxy set up successfully on port $PROXY_PORT!"
}

# Function to add SSH user
add_ssh_user() {
    local username=$(get_input "Enter SSH username")
    local password=$(get_password "Enter SSH password")
    echo
    local expiration_date=$(get_input "Enter expiration date (YYYY-MM-DD) or leave blank for no expiration")
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    if [ -n "$expiration_date" ]; then
        chage -E "$expiration_date" "$username"
    fi
    show_message "SSH user $username added successfully!"
}

# Function to list SSH users
list_ssh_users() {
    show_message "SSH Users:"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd
}

# Function to remove SSH user
remove_ssh_user() {
    local username=$(get_input "Enter SSH username to remove")
    if id "$username" &>/dev/null; then
        userdel -r "$username"
        show_message "SSH user $username removed successfully!"
    else
        show_error "User $username does not exist."
    fi
}

# Function to add V2Ray user
add_v2ray_user() {
    local protocol=$(get_input "Enter protocol (vmess/vless)")
    local username=$(get_input "Enter username")
    local uuid=$(uuidgen)
    local expiration_date=$(get_input "Enter expiration date (YYYY-MM-DD) or leave blank for no expiration")
    if [ "$protocol" == "vmess" ] || [ "$protocol" == "vless" ]; then
        jq --arg protocol "$protocol" --arg username "$username" --arg uuid "$uuid" --arg exp "$expiration_date" \
        '.inbounds[] | select(.protocol == $protocol) | .settings.clients += [{"id": $uuid, "email": $username, "expiryTime": (if $exp != "" then ($exp | fromdateiso8601 | tostring) else null end)}]' \
        /usr/local/etc/v2ray/config.json > /tmp/v2ray_config.json && mv /tmp/v2ray_config.json /usr/local/etc/v2ray/config.json
        systemctl restart v2ray
        show_message "V2Ray user $username added successfully for $protocol protocol!"
        echo "UUID: $uuid"
        [ -n "$expiration_date" ] && echo "Expiration date: $expiration_date"
    else
        show_error "Invalid protocol. Please enter vmess or vless."
    fi
}

# Function to list V2Ray users
list_v2ray_users() {
    show_message "V2Ray Users:"
    echo "VMess Users:"
    jq -r '.inbounds[] | select(.protocol == "vmess") | .settings.clients[] | "Username: \(.email), UUID: \(.id), Expiry: \(.expiryTime // "No expiration")"' /usr/local/etc/v2ray/config.json
    echo "VLESS Users:"
    jq -r '.inbounds[] | select(.protocol == "vless") | .settings.clients[] | "Username: \(.email), UUID: \(.id), Expiry: \(.expiryTime // "No expiration")"' /usr/local/etc/v2ray/config.json
}

# Function to remove V2Ray user
remove_v2ray_user() {
    local protocol=$(get_input "Enter protocol (vmess/vless)")
    local username=$(get_input "Enter username to remove")
    if [ "$protocol" == "vmess" ] || [ "$protocol" == "vless" ]; then
        jq --arg protocol "$protocol" --arg username "$username" \
        '.inbounds[] | select(.protocol == $protocol) | .settings.clients = [.settings.clients[] | select(.email != $username)]' \
        /usr/local/etc/v2ray/config.json > /tmp/v2ray_config.json && mv /tmp/v2ray_config.json /usr/local/etc/v2ray/config.json
        systemctl restart v2ray
        show_message "V2Ray user $username removed successfully from $protocol protocol!"
    else
        show_error "Invalid protocol. Please enter vmess or vless."
    fi
}

# Function to add or change banner message
change_banner_message() {
    local banner_message=$(get_input "Enter the new banner message (or press Enter to remove)")
    
    if [ -n "$banner_message" ]; then
        echo "$banner_message" > /etc/banner
        sed -i 's/^#Banner .*/Banner \/etc\/banner/' /etc/ssh/sshd_config
    else
        rm -f /etc/banner
        sed -i 's/^Banner .*/#Banner none/' /etc/ssh/sshd_config
    fi
    systemctl restart ssh
    show_message "Banner message updated successfully!"
}

# Function to change Python proxy message
change_proxy_message() {
    local new_message=$(get_input "Enter new Python proxy message")
    sed -i "s/PROXY_MESSAGE = .*/PROXY_MESSAGE = \"$new_message\"/" /usr/local/bin/python_proxy.py
    systemctl restart python_proxy
    show_message "Python proxy message updated successfully!"
}

# Function to display current configuration
display_config() {
    show_message "Current Configuration:"
    echo "Domain: $DOMAIN"
    echo "VMess UUID: $VMESS_UUID"
    echo "VMess Port: $VMESS_PORT"
    echo "VMess WebSocket Path: $VMESS_WS_PATH"
    echo "VLESS UUID: $VLESS_UUID"
    echo "VLESS Port: $VLESS_PORT"
    echo "VLESS WebSocket Path: $VLESS_WS_PATH"
    echo "SSH Port: $SSH_PORT"
    echo "SSH WebSocket Port: $SSH_WS_PORT"
    echo "SSH WebSocket Path: $SSH_WS_PATH"
    echo "Python Proxy Port: $PROXY_PORT"
    echo "Python Proxy Message: $(grep 'PROXY_MESSAGE =' /usr/local/bin/python_proxy.py | cut -d '"' -f 2)"
}

# Admin menu function
admin_menu() {
    while true; do
        echo -e "\nAdmin Menu:"
        echo "1. Manage SSH Users"
        echo "2. Manage V2Ray Users"
        echo "3. Change V2Ray Ports"
        echo "4. Change SSH Ports"
        echo "5. Change Banner Message"
        echo "6. Manage Python Proxy"
        echo "7. Display Current Configuration"
        echo "8. Exit"
        
        local choice=$(get_input "Enter your choice")
        case $choice in
            1)
                echo "1. Add SSH User"
                echo "2. List SSH Users"
                echo "3. Remove SSH User"
                local ssh_choice=$(get_input "Enter your choice")
                case $ssh_choice in
                    1) add_ssh_user ;;
                    2) list_ssh_users ;;
                    3) remove_ssh_user ;;
                    *) show_error "Invalid choice" ;;
                esac
                ;;
            2)
                echo "1. Add V2Ray User"
                echo "2. List V2Ray Users"
                echo "3. Remove V2Ray User"
                local v2ray_choice=$(get_input "Enter your choice")
                case $v2ray_choice in
                    1) add_v2ray_user ;;
                    2) list_v2ray_users ;;
                    3) remove_v2ray_user ;;
                    *) show_error "Invalid choice" ;;
                esac
                ;;
            3)
                VMESS_PORT=$(get_input "Enter new VMess port")
                VLESS_PORT=$(get_input "Enter new VLESS port")
                configure_v2ray
                configure_nginx
                ;;
            4)
                SSH_PORT=$(get_input "Enter new SSH port")
                SSH_WS_PORT=$(get_input "Enter new SSH WebSocket port")
                configure_ssh
                configure_nginx
                ;;
            5) change_banner_message ;;
            6)
                echo "1. Change Python Proxy Port"
                echo "2. Change Python Proxy Message"
                local proxy_choice=$(get_input "Enter your choice")
                case $proxy_choice in
                    1)
                        PROXY_PORT=$(get_input "Enter new Python proxy port")
                        sed -i "s/listenTCP(.*/listenTCP($PROXY_PORT, ProxyFactory())/" /usr/local/bin/python_proxy.py
                        systemctl restart python_proxy
                        show_message "Python proxy port updated to $PROXY_PORT!"
                        ;;
                    2) change_proxy_message ;;
                    *) show_error "Invalid choice" ;;
                esac
                ;;
            7) display_config ;;
            8) return ;;
            *) show_error "Invalid choice" ;;
        esac
    done
}

# Main installation function
install_and_configure() {
    DOMAIN=$(get_domain)
    install_components
    configure_v2ray
    configure_ssh
    configure_nginx
    setup_python_proxy
    add_ssh_user

    # Save configurations to a file
    cat > /etc/vps_config.sh <<EOF
#!/bin/bash
DOMAIN="$DOMAIN"
VMESS_UUID="$VMESS_UUID"
VMESS_PORT="$VMESS_PORT"
VMESS_WS_PATH="$VMESS_WS_PATH"
VLESS_UUID="$VLESS_UUID"
VLESS_PORT="$VLESS_PORT"
VLESS_WS_PATH="$VLESS_WS_PATH"
SSH_PORT="$SSH_PORT"
SSH_WS_PORT="$SSH_WS_PORT"
SSH_WS_PATH="$SSH_WS_PATH"
PROXY_PORT="$PROXY_PORT"

$(declare -f show_message)
$(declare -f show_error)
$(declare -f get_input)
$(declare -f get_password)
$(declare -f get_yes_no)
$(declare -f add_ssh_user)
$(declare -f list_ssh_users)
$(declare -f remove_ssh_user)
$(declare -f add_v2ray_user)
$(declare -f list_v2ray_users)
$(declare -f remove_v2ray_user)
$(declare -f change_banner_message)
$(declare -f change_proxy_message)
$(declare -f display_config)
$(declare -f admin_menu)
EOF

    chmod +x /etc/vps_config.sh

    show_message "Installation and configuration completed successfully!"
    display_config
}

# Main script execution
show_message "Welcome to KING VPS Management Script"
if [ "$EUID" -ne 0 ]; then
    show_error "Please run as root"
    exit 1
fi

if get_yes_no "Do you want to install and configure the VPS?"; then
    install_and_configure
fi

show_message "Setup complete. You can now access the admin menu by typing 'admin' in the VPS Admin Interface."
show_message "To access the VPS Admin Interface, use 'sudo systemctl start vps_admin' or reboot your server."
show_message "The interface will be available on TTY1 (Ctrl+Alt+F1 on most systems)."

exit 0
