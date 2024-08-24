#!/bin/bash

# Global variables
CONFIG_FILE="/root/server_config.conf"
LOG_FILE="/var/log/server_setup.log"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to check if a command was successful
check_command() {
    if [ $? -ne 0 ]; then
        log_message "Error: $1 failed"
        return 1
    fi
    return 0
}

# Function to get user input for ports
get_port() {
    local service=$1
    local default=$2
    read -p "Enter port for $service (default: $default): " port
    echo ${port:-$default}
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

# Function to get a custom path
get_custom_path() {
    local service=$1
    local default=$2
    read -p "Enter custom path for $service (default: $default): " custom_path
    echo ${custom_path:-$default}
}

# Function to get domain
get_domain() {
    read -p "Enter your domain name: " domain
    echo $domain
}

# Function to update and upgrade system
update_system() {
    log_message "Updating and upgrading system..."
    if ! sudo apt update && sudo apt upgrade -y; then
        log_message "Error: System update failed"
        return 1
    fi
    return 0
}

# Function to install necessary packages
install_packages() {
    log_message "Installing necessary packages..."
    if ! sudo apt install -y curl wget unzip net-tools python3 python3-pip dropbear stunnel4 nginx build-essential certbot python3-certbot-nginx jq ufw; then
        log_message "Error: Package installation failed"
        return 1
    fi
    return 0
}

# Function to install and configure V2Ray
install_v2ray() {
    log_message "Installing and configuring V2Ray..."
    if ! bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh); then
        log_message "Error: V2Ray installation failed"
        return 1
    fi
    
    local uuid=$(uuidgen)
    local config_file="/usr/local/etc/v2ray/config.json"
    
    if [ "$USE_TLS" = true ]; then
        generate_v2ray_config_tls "$config_file" "$uuid"
    else
        generate_v2ray_config_no_tls "$config_file" "$uuid"
    fi

    if ! systemctl start v2ray; then
        log_message "Error: Failed to start V2Ray"
        return 1
    fi
    systemctl enable v2ray
    
    echo "V2RAY_UUID=$uuid" >> "$CONFIG_FILE"
    return 0
}

# Function to generate V2Ray config with TLS
generate_v2ray_config_tls() {
    local config_file=$1
    local uuid=$2
    cat << EOF > "$config_file"
{
  "inbounds": [
    {
      "port": $V2RAY_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$V2RAY_WS_PATH"
        },
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
}

# Function to generate V2Ray config without TLS
generate_v2ray_config_no_tls() {
    local config_file=$1
    local uuid=$2
    cat << EOF > "$config_file"
{
  "inbounds": [
    {
      "port": $V2RAY_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$V2RAY_WS_PATH"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
}

# Function to configure SSH
configure_ssh() {
    log_message "Configuring SSH..."
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    if ! systemctl restart sshd; then
        log_message "Error: Failed to restart SSH service"
        return 1
    fi
    return 0
}

# Function to configure Dropbear
configure_dropbear() {
    log_message "Configuring Dropbear..."
    sed -i "s/NO_START=1/NO_START=0/" /etc/default/dropbear
    sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=$DROPBEAR_PORT/" /etc/default/dropbear
    if ! systemctl restart dropbear; then
        log_message "Error: Failed to restart Dropbear service"
        return 1
    fi
    return 0
}

# Function to configure SSL
configure_ssl() {
    log_message "Configuring SSL..."
    cat << EOF > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
key = /etc/letsencrypt/live/$DOMAIN/privkey.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = $SSL_PORT
connect = 127.0.0.1:$DROPBEAR_PORT
EOF

    if ! systemctl restart stunnel4; then
        log_message "Error: Failed to restart Stunnel service"
        return 1
    fi
    return 0
}

# Function to configure Nginx for WebSocket
configure_nginx() {
    log_message "Configuring Nginx for WebSocket..."
    cat << EOF > /etc/nginx/sites-available/websocket
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    location $V2RAY_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$V2RAY_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location $SSH_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$SSH_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/websocket /etc/nginx/sites-enabled/
    if ! nginx -t; then
        log_message "Error: Nginx configuration test failed"
        return 1
    fi
    if ! systemctl restart nginx; then
        log_message "Error: Failed to restart Nginx service"
        return 1
    fi
    return 0
}

# Function to setup Python Proxy
setup_python_proxy() {
    log_message "Setting up Python Proxy..."
    if ! pip3 install websockets; then
        log_message "Error: Failed to install websockets library"
        return 1
    fi

    cat << EOF > /root/custom_proxy.py
import asyncio
import websockets
import ssl

class WebSocketProxy:
    def __init__(self, listen_host, listen_port):
        self.listen_host = listen_host
        self.listen_port = listen_port

    async def handle_connection(self, websocket, path):
        try:
            # Perform any authentication or initial setup here if needed
            
            # This is where you would typically establish a connection to the actual backend server
            # For demonstration, we'll just echo messages back
            async for message in websocket:
                await websocket.send(f"Echo: {message}")
        except websockets.exceptions.ConnectionClosed:
            pass

    async def run(self):
        server = await websockets.serve(
            self.handle_connection,
            self.listen_host,
            self.listen_port,
            process_request=self.process_request
        )
        await server.wait_closed()

    async def process_request(self, path, headers):
        # This method allows us to handle the HTTP Upgrade request
        # and return a 101 Switching Protocols response
        return None

if __name__ == '__main__':
    proxy = WebSocketProxy('0.0.0.0', $PYTHON_PROXY_PORT)
    asyncio.get_event_loop().run_until_complete(proxy.run())
EOF

    create_systemd_service "python-proxy" "/usr/bin/python3 /root/custom_proxy.py"
    return 0
}

# Function to install and configure BadVPN
setup_badvpn() {
    log_message "Setting up BadVPN..."
    if ! wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64"; then
        log_message "Error: Failed to download BadVPN"
        return 1
    fi
    chmod +x /usr/bin/badvpn-udpgw

    create_systemd_service "badvpn" "/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:$BADVPN_PORT --max-clients 1000 --max-connections-for-client 10"
    return 0
}

# Function to create a systemd service
create_systemd_service() {
    local service_name=$1
    local exec_start=$2

    cat << EOF > /etc/systemd/system/${service_name}.service
[Unit]
Description=$service_name
After=network.target

[Service]
ExecStart=$exec_start
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    if ! systemctl start $service_name; then
        log_message "Error: Failed to start $service_name service"
        return 1
    fi
    systemctl enable $service_name
    return 0
}

# Function to optimize system performance
optimize_system() {
    log_message "Optimizing system performance..."
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p

    echo "* soft nofile 51200" >> /etc/security/limits.conf
    echo "* hard nofile 51200" >> /etc/security/limits.conf

    sed -i 's/worker_processes.*/worker_processes auto;/' /etc/nginx/nginx.conf
    sed -i 's/# multi_accept.*/multi_accept on;/' /etc/nginx/nginx.conf
    sed -i 's/# tcp_nopush.*/tcp_nopush on;/' /etc/nginx/nginx.conf
    sed -i 's/# tcp_nodelay.*/tcp_nodelay on;/' /etc/nginx/nginx.conf
    if ! systemctl restart nginx; then
        log_message "Error: Failed to restart Nginx after optimization"
        return 1
    fi
    return 0
}

# Function to configure firewall
configure_firewall() {
    log_message "Configuring firewall..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow $SSH_PORT/tcp
    ufw allow $DROPBEAR_PORT/tcp
    ufw allow $SSL_PORT/tcp
    ufw allow $V2RAY_PORT/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow $PYTHON_PROXY_PORT/tcp
    ufw allow $BADVPN_PORT/udp
    if ! ufw --force enable; then
        log_message "Error: Failed to enable firewall"
        return 1
    fi
    return 0
}

# Function to check services status
check_services_status() {
    log_message "Checking services status..."
    services=("sshd" "dropbear" "stunnel4" "nginx" "v2ray" "python-proxy" "badvpn")
    for service in "${services[@]}"; do
        status=$(systemctl is-active $service)
        log_message "$service status: $status"
        if [ "$status" != "active" ]; then
            log_message "Warning: $service is not active. Check configuration and logs."
        fi
    done
}

# Main function to run the setup
main() {
    log_message "Starting VPN server setup..."

    # Get user inputs
    DOMAIN=$(get_domain)
    USE_TLS=$(get_yes_no "Use TLS?")
    V2RAY_PORT=$(get_port "V2Ray" 8443)
    SSH_PORT=$(get_port "SSH" 22)
    DROPBEAR_PORT=$(get_port "Dropbear" 444)
    SSL_PORT=$(get_port "SSL" 443)
    PYTHON_PROXY_PORT=$(get_port "Python Proxy" 8080)
    BADVPN_PORT=$(get_port "BadVPN" 7300)
    V2RAY_WS_PATH=$(get_custom_path "V2Ray WebSocket" "/v2ray")
    SSH_WS_PATH=$(get_custom_path "SSH WebSocket" "/ssh")

    # Save configuration
    cat << EOF > "$CONFIG_FILE"
DOMAIN=$DOMAIN
USE_TLS=$USE_TLS
V2RAY_PORT=$V2RAY_PORT
SSH_PORT=$SSH_PORT
DROPBEAR_PORT=$DROPBEAR_PORT
SSL_PORT=$SSL_PORT
PYTHON_PROXY_PORT=$PYTHON_PROXY_PORT
BADVPN_PORT=$BADVPN_PORT
V2RAY_WS_PATH=$V2RAY_WS_PATH
SSH_WS_PATH=$SSH_WS_PATH
EOF

    # Update and install packages
    update_system || return 1
    install_packages || return 1

    # Setup services
    install_v2ray || return 1
    configure_ssh || return 1
    configure_dropbear || return 1
    configure_ssl || return 1
    configure_nginx || return 1
    setup_python_proxy || return 1
    setup_badvpn || return 1

    # Optimize system
    optimize_system || return 1

    # Configure firewall
    configure_firewall || return 1

    # Check services status
    check_services_status

    log_message "VPN server setup completed successfully."
}

# Function to add an SSH user
add_ssh_user() {
    local username=$1
    local password=$2
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd
    log_message "Added SSH user: $username"
}

# Function to list SSH users
list_ssh_users() {
    log_message "SSH Users:"
    log_message "----------"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd
}

# Function to remove SSH user
remove_ssh_user() {
    local username=$1
    userdel -r "$username"
    log_message "Removed SSH user: $username"
}

# Function to add a V2Ray user
add_v2ray_user() {
    local username=$1
    local uuid=$(uuidgen)
    local config_file="/usr/local/etc/v2ray/config.json"
    
    jq ".inbounds[0].settings.clients += [{\"id\": \"$uuid\", \"level\": 0, \"email\": \"$username\"}]" "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
    
    if ! systemctl restart v2ray; then
        log_message "Error: Failed to restart V2Ray after adding user"
        return 1
    fi
    log_message "Added V2Ray user: $username with UUID: $uuid"
}

# Function to list V2Ray users
list_v2ray_users() {
    log_message "V2Ray Users:"
    log_message "------------"
    jq -r '.inbounds[0].settings.clients[] | .email' /usr/local/etc/v2ray/config.json
}

# Function to remove V2Ray user
remove_v2ray_user() {
    local username=$1
    local config_file="/usr/local/etc/v2ray/config.json"
    
    jq --arg user "$username" '.inbounds[0].settings.clients = [.inbounds[0].settings.clients[] | select(.email != $user)]' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
    
    if ! systemctl restart v2ray; then
        log_message "Error: Failed to restart V2Ray after removing user"
        return 1
    fi
    log_message "Removed V2Ray user: $username"
}

# Function to change a port
change_port() {
    local service=$1
    local new_port=$2
    
    case $service in
        v2ray)
            sed -i "s/\"port\": [0-9]*/\"port\": $new_port/" /usr/local/etc/v2ray/config.json
            systemctl restart v2ray
            ;;
        ssh)
            sed -i "s/^Port .*/Port $new_port/" /etc/ssh/sshd_config
            systemctl restart sshd
            ;;
        dropbear)
            sed -i "s/DROPBEAR_PORT=.*/DROPBEAR_PORT=$new_port/" /etc/default/dropbear
            systemctl restart dropbear
            ;;
        ssl)
            sed -i "s/accept = .*/accept = $new_port/" /etc/stunnel/stunnel.conf
            systemctl restart stunnel4
            ;;
        websocket)
            sed -i "s/listen .*/listen $new_port ssl http2;/" /etc/nginx/sites-available/websocket
            systemctl restart nginx
            ;;
        python_proxy)
            sed -i "s/port=.*/port=$new_port/" /root/custom_proxy.py
            systemctl restart python-proxy
            ;;
        badvpn)
            sed -i "s/--listen-addr 127.0.0.1:[0-9]*/--listen-addr 127.0.0.1:$new_port/" /etc/systemd/system/badvpn.service
            systemctl daemon-reload
            systemctl restart badvpn
            ;;
        *)
            log_message "Error: Unknown service: $service"
            return 1
            ;;
    esac
    
    sed -i "s/^${service^^}_PORT=.*/${service^^}_PORT=$new_port/" "$CONFIG_FILE"
    log_message "Changed $service port to $new_port"
    
    # Update firewall rules
    ufw delete allow $old_port
    ufw allow $new_port
    log_message "Updated firewall rules for new port"
}

# Function to update domain
update_domain() {
    local new_domain=$1
    sed -i "s/^DOMAIN=.*/DOMAIN=$new_domain/" "$CONFIG_FILE"
    
    if ! certbot certonly --nginx -d $new_domain; then
        log_message "Error: Failed to obtain SSL certificate for new domain"
        return 1
    fi
    
    sed -i "s/server_name .*/server_name $new_domain;/" /etc/nginx/sites-available/websocket
    
    sed -i "s|cert = .*|cert = /etc/letsencrypt/live/$new_domain/fullchain.pem|" /etc/stunnel/stunnel.conf
    sed -i "s|key = .*|key = /etc/letsencrypt/live/$new_domain/privkey.pem|" /etc/stunnel/stunnel.conf
    
    if ! systemctl restart nginx stunnel4; then
        log_message "Error: Failed to restart Nginx and Stunnel after domain update"
        return 1
    fi
    
    log_message "Updated domain to $new_domain"
}

# Function to list configured ports
list_ports() {
    log_message "Configured Ports:"
    log_message "----------------"
    grep "_PORT=" "$CONFIG_FILE" | while read -r line; do
        service=$(echo "$line" | cut -d'_' -f1)
        port=$(echo "$line" | cut -d'=' -f2)
        log_message "$service: $port"
    done
}

# Function to handle admin tasks
admin_menu() {
    while true; do
        echo
        echo "VPN Admin Menu"
        echo "1. Add SSH User"
        echo "2. List SSH Users"
        echo "3. Remove SSH User"
        echo "4. Add V2Ray User"
        echo "5. List V2Ray Users"
        echo "6. Remove V2Ray User"
        echo "7. Change Port"
        echo "8. Update Domain"
        echo "9. List Configured Ports"
        echo "10. Check Services Status"
        echo "11. Exit"
        read -p "Enter your choice: " choice
        
        case $choice in
            1)
                read -p "Enter username for new SSH user: " username
                read -s -p "Enter password for new SSH user: " password
                echo
                add_ssh_user "$username" "$password"
                ;;
            2)
                list_ssh_users
                ;;
            3)
                read -p "Enter username of SSH user to remove: " username
                remove_ssh_user "$username"
                ;;
            4)
                read -p "Enter username for new V2Ray user: " username
                add_v2ray_user "$username"
                ;;
            5)
                list_v2ray_users
                ;;
            6)
                read -p "Enter username of V2Ray user to remove: " username
                remove_v2ray_user "$username"
                ;;
            7)
                read -p "Enter service name (v2ray/ssh/dropbear/ssl/websocket/python_proxy/badvpn): " service
                read -p "Enter new port number: " new_port
                change_port "$service" "$new_port"
                ;;
            8)
                read -p "Enter new domain name: " new_domain
                update_domain "$new_domain"
                ;;
            9)
                list_ports
                ;;
            10)
                check_services_status
                ;;
            11)
                return
                ;;
            *)
                log_message "Invalid choice. Please try again."
                ;;
        esac
        
        echo
    done
}

# Run the main function if the script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ "$1" = "setup" ]; then
        main
    elif [ "$1" = "admin" ]; then
        admin_menu
    else
        echo "Usage: $0 [setup|admin]"
        exit 1
    fi
fi
