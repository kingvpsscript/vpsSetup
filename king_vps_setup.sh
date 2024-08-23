#!/bin/bash

# Global variables
CONFIG_FILE="/root/server_config.conf"
LOG_FILE="/var/log/server_setup.log"

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "$1"
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

# Function to update and upgrade system
update_system() {
    log_message "Updating and upgrading system..."
    sudo apt update && sudo apt upgrade -y
}

# Function to install necessary packages
install_packages() {
    log_message "Installing necessary packages..."
    sudo apt install -y curl wget unzip net-tools python3 python3-pip dropbear stunnel4 nginx build-essential
}

# Function to install and configure V2Ray
install_v2ray() {
    log_message "Installing and configuring V2Ray..."
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
    local uuid=$(uuidgen)
    local config_file="/usr/local/etc/v2ray/config.json"
    
    # Generate V2Ray config based on TLS setting
    if [ "$USE_TLS" = true ]; then
        generate_v2ray_config_tls "$config_file" "$uuid"
    else
        generate_v2ray_config_no_tls "$config_file" "$uuid"
    fi

    if [ "$USE_TLS" = true ]; then
        generate_v2ray_cert
    fi

    systemctl start v2ray
    systemctl enable v2ray
    
    echo "V2RAY_UUID=$uuid" >> "$CONFIG_FILE"
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
        }
      }
    },
    {
      "port": $V2RAY_TLS_PORT,
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
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/v2ray/v2ray.crt",
              "keyFile": "/etc/v2ray/v2ray.key"
            }
          ]
        },
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

# Function to generate V2Ray self-signed certificate
generate_v2ray_cert() {
    log_message "Generating self-signed certificate for V2Ray TLS..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout /etc/v2ray/v2ray.key -out /etc/v2ray/v2ray.crt
}

# Function to configure SSH
configure_ssh() {
    log_message "Configuring SSH..."
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    if [ ! -z "$SSH_BANNER" ]; then
        echo "$SSH_BANNER" > /etc/ssh/banner
        echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
    fi
    systemctl restart sshd
}

# Function to configure Dropbear
configure_dropbear() {
    log_message "Configuring Dropbear..."
    sed -i "s/NO_START=1/NO_START=0/" /etc/default/dropbear
    sed -i "s/DROPBEAR_PORT=22/DROPBEAR_PORT=$DROPBEAR_PORT/" /etc/default/dropbear
    if [ ! -z "$SSH_BANNER" ]; then
        echo "DROPBEAR_BANNER=\"/etc/ssh/banner\"" >> /etc/default/dropbear
    fi
    systemctl restart dropbear
}

# Function to configure SSL
configure_ssl() {
    log_message "Configuring SSL..."
    cat << EOF > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = $SSL_PORT
connect = 127.0.0.1:$DROPBEAR_PORT
EOF

    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem

    systemctl restart stunnel4
}

# Function to configure Nginx for WebSocket
configure_nginx() {
    log_message "Configuring Nginx for WebSocket..."
    cat << EOF > /etc/nginx/sites-available/websocket
server {
    listen $WEBSOCKET_PORT;
    server_name localhost;

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

    ln -s /etc/nginx/sites-available/websocket /etc/nginx/sites-enabled/
    nginx -t && systemctl restart nginx
}

# Function to setup Python Proxy
setup_python_proxy() {
    log_message "Setting up Python Proxy..."
    pip3 install proxy.py

    cat << EOF > /root/custom_proxy.py
import time
from proxy import ProxyServer, ProxyHandler

class CustomHandler(ProxyHandler):
    def handle_client_request(self, request):
        if request.method == 'CONNECT':
            self.send_response(200, 'Connection Established')
            self.send_header('Proxy-Agent', 'Custom Python Proxy')
            self.end_headers()
        else:
            super().handle_client_request(request)

    def handle_client_connection(self, conn, addr):
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\n")
        conn.sendall(b"Upgrade: websocket\r\n")
        conn.sendall(b"Connection: Upgrade\r\n")
        conn.sendall(f"X-Proxy-Message: {PYTHON_PROXY_MESSAGE}\r\n".encode())
        conn.sendall(b"\r\n")
        super().handle_client_connection(conn, addr)

if __name__ == '__main__':
    proxy = ProxyServer(hostname='0.0.0.0', port=$PYTHON_PROXY_PORT, handler_class=CustomHandler)
    proxy.run()
EOF

    create_systemd_service "python-proxy" "/usr/bin/python3 /root/custom_proxy.py"
}

# Function to install and configure BadVPN
setup_badvpn() {
    log_message "Setting up BadVPN..."
    wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64"
    chmod +x /usr/bin/badvpn-udpgw

    create_systemd_service "badvpn" "/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:$BADVPN_PORT --max-clients 1000 --max-connections-for-client 10"
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

    systemctl start $service_name
    systemctl enable $service_name
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
    systemctl restart nginx
}

# Function to display connection information
display_info() {
    local server_ip=$(curl -s ifconfig.me)
    local v2ray_uuid=$(grep V2RAY_UUID "$CONFIG_FILE" | cut -d= -f2)

    echo "----------------------------------------"
    echo "Server Setup Complete"
    echo "----------------------------------------"
    echo "V2Ray VLESS: Port $V2RAY_PORT, Path $V2RAY_WS_PATH"
    [ "$USE_TLS" = true ] && echo "V2Ray VLESS (TLS): Port $V2RAY_TLS_PORT, Path $V2RAY_WS_PATH"
    echo "SSH: Port $SSH_PORT"
    echo "SSH WebSocket: Path $SSH_WS_PATH"
    echo "Dropbear: Port $DROPBEAR_PORT"
    echo "SSL: Port $SSL_PORT"
    echo "WebSocket: Port $WEBSOCKET_PORT"
    echo "Python Proxy: Port $PYTHON_PROXY_PORT"
    echo "BadVPN: Port $BADVPN_PORT"
    echo "V2Ray UUID: $v2ray_uuid"
    echo "Server IP: $server_ip"
    echo "Python Proxy 101 Protocol Message: $PYTHON_PROXY_MESSAGE"
    echo "----------------------------------------"
    echo "Configuration saved in $CONFIG_FILE"
    echo "Log file: $LOG_FILE"
    echo "----------------------------------------"
}

# Main function
main() {
    log_message "Starting server setup..."

    # Get user input
    V2RAY_PORT=$(get_port "V2Ray" 10086)
    SSH_PORT=$(get_port "SSH" 22)
    DROPBEAR_PORT=$(get_port "Dropbear" 444)
    SSL_PORT=$(get_port "SSL" 443)
    WEBSOCKET_PORT=$(get_port "WebSocket" 80)
    PYTHON_PROXY_PORT=$(get_port "Python Proxy" 8080)
    BADVPN_PORT=$(get_port "BadVPN" 7300)

    V2RAY_WS_PATH=$(get_custom_path "V2Ray WebSocket" "/v2ray")
    SSH_WS_PATH=$(get_custom_path "SSH WebSocket" "/ssh")

    if get_yes_no "Do you want to enable TLS for V2Ray?"; then
        USE_TLS=true
        V2RAY_TLS_PORT=$(get_port "V2Ray TLS" 443)
    else
        USE_TLS=false
    fi

    if get_yes_no "Do you want to set up an SSH banner message?"; then
        read -p "Enter your SSH banner message: " SSH_BANNER
    fi

    read -p "Enter your Python proxy 101 protocol message (default: Welcome to Python Proxy): " PYTHON_PROXY_MESSAGE
    PYTHON_PROXY_MESSAGE=${PYTHON_PROXY_MESSAGE:-"Welcome to Python Proxy"}

    # Save configuration
    {
        echo "V2RAY_PORT=$V2RAY_PORT"
        echo "SSH_PORT=$SSH_PORT"
        echo "DROPBEAR_PORT=$DROPBEAR_PORT"
        echo "SSL_PORT=$SSL_PORT"
        echo "WEBSOCKET_PORT=$WEBSOCKET_PORT"
        echo "PYTHON_PROXY_PORT=$PYTHON_PROXY_PORT"
        echo "BADVPN_PORT=$BADVPN_PORT"
        echo "V2RAY_WS_PATH=$V2RAY_WS_PATH"
        echo "SSH_WS_PATH=$SSH_WS_PATH"
        echo "USE_TLS=$USE_TLS"
        [ "$USE_TLS" = true ] && echo "V2RAY_TLS_PORT=$V2RAY_TLS_PORT"
        [ ! -z "$SSH_BANNER" ] && echo "SSH_BANNER=$SSH_BANNER"
        echo "PYTHON_PROXY_MESSAGE=$PYTHON_PROXY_MESSAGE"
    } > "$CONFIG_FILE"

    # Perform setup steps
    update_system
    install_packages
    install_v2ray
    configure_ssh
    configure_dropbear
    configure_ssl
    configure_nginx
    setup_python_proxy
    setup_badvpn
    optimize_system

    # Display setup information
    display_info

    log_message "Server setup completed successfully."
}

# Run the main function
main
