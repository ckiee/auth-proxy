# auth-proxy
A web auth proxy that works with Docker

## docker compose
here is an example from my prod config, you probably know how to stick it in your setup.
```yaml
    adminpanel_authproxy:
        image: ronthecookie/auth-proxy
        ports:
            - "127.0.0.1:3000:3000"
        environment:
            - COOKIE_SECRET=MyCookiesAreCool
            - "PROXY_NAME=Admin Panel"
            - PROXY_URL=http://adminpanel:3000
            - "AUTH_PAIRS=ron:bcryptHashWith$$InsteadOf$"
            - DB_ADDR=rethink:28015
        networks:
            - rdb
        links: 
            - adminpanel
        depends_on:
            - rethink
```