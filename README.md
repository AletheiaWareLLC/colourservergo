colourservergo
==============

This is a Go implementation of a Colour Server - an exploration of colour through collaborative, blockchain-backed, digital canvases.

Build
=====

    go build

Setup
=====

This guide will demonstrate how to setup Colour on a remote server, such as a Digital Ocean Droplet running Ubuntu 18.04 x64.

Create a new droplet and ssh into the IP address

    ssh root@your_server_ip

Firewall (UFW)

    # Install firewall
    apt install ufw
    # Allow http port
    ufw allow 80
    # Allow https port
    ufw allow 443
    # Allow colour ports
    ufw allow 22222
    ufw allow 22322
    ufw allow 23232
    # Enable firewall
    ufw enable

HTTPS (Let's Encrypt)

    # Install certbot
    apt install certbot
    certbot certonly --standalone -d your_server_domain

Stripe

    # Setup a stripe account
    # Create a product (Pixel Rendering Service, Pixel Purchasing Market, and Pixel Voting Platform)
    # Create a plan (PRS, PPM, & PVP pricing plan eg $0.000,000,1 per render, 0.1% of purchase, $0.000,000,01 per vote)

Colour

    # Create colour user
    adduser your_server_alias
    # Create colour directory
    mkdir -p /home/your_server_alias/colour/

    # From your development machine
    # Copy server binary
    rsync $GOPATH/bin/colourservergo-linux-amd64 your_server_alias@your_server_ip:~/colour/
    # Copy website content
    rsync -r $GOPATH/src/github.com/AletheiaWareLLC/colourservergo/html your_server_alias@your_server_ip:~/colour/
    # Copy client binaries into website static content
    rsync $GOPATH/bin/colourclientgo-* your_server_alias@your_server_ip:~/colour/html/static/

    # Initialize Colour
    ALIAS=your_server_alias CACHE=~/colour/cache/ KEYSTORE=~/colour/keys/ LOGSTORE=~/colour/logs/ ~/colour/html/static/colourclient-linux-amd64 init

    # Allow colourservergo to read security credentials created by certbot
    chown -R your_server_alias:your_server_alias /etc/letsencrypt/
    # Allow colourservergo to bind to port 443 (HTTPS)
    # This is required each time the server binary is updated
    setcap CAP_NET_BIND_SERVICE=+eip /home/your_server_alias/colour/colourservergo-linux-amd64

Service (Systemd)

    # Create colour config
    cat > /home/your_server_alias/colour/config <<EOF
    >STRIPE_PUBLISHABLE_KEY=VVVVVV
    >STRIPE_SECRET_KEY=WWWWWW
    >STRIPE_PRODUCT_ID=XXXXXX
    >STRIPE_PLAN_ID=YYYYYY
    >STRIPE_WEB_HOOK_SECRET_KEY=ZZZZZZ
    >ALIAS=your_server_alias
    >PASSWORD='VWXYZ'
    >CACHE=cache/
    >KEYSTORE=keys/
    >LOGSTORE=logs/
    >SECURITYSTORE=/etc/letsencrypt/live/your_server_domain/
    >PEERS=colour.aletheiaware.com,bc.aletheiaware.com
    >EOF

    # Create colour service
    cat > /etc/systemd/system/colour.service <<EOF
    >[Unit]
    >Description=Colour Server
    >[Service]
    >User=your_server_alias
    >WorkingDirectory=/home/your_server_alias/colour
    >EnvironmentFile=/home/your_server_alias/colour/config
    >ExecStart=/home/your_server_alias/colour/colourservergo-linux-amd64
    >SuccessExitStatus=143
    >TimeoutStopSec=10
    >Restart=on-failure
    >RestartSec=5
    >[Install]
    >WantedBy=multi-user.target
    >EOF

    # Reload daemon
    systemctl daemon-reload
    # Start service
    systemctl start colour

    # Monitor service
    journalctl -u colour
