![](assets/logo.svg)
# Go SMTP Relay
A minimal SMTP-SMTP Relay written in Go. The main purpose is to have a local relay which authenticates and verifies permissions for sending via a remote SMTP server (e.g. Amazon AWS, SMTP2GO).

## Usage
### Go
Compile the go code (e.g. ```go build -o smtp-relay main.go```) and run the binary or use the kubernetes operator (docs coming soon...)

### Docker
There are docker images avaiable on GHCR and Docker Hub
- docker.io/scheiblingco/smtp-relay:latest
- ghcr.io/scheiblingco/smtp-relay:latest

### Configuration

OUT OF DATE: Needs update.


```json
{
    "server": {
        // Hostname for the server
        "host": "smtp.example.com",

        // Port to listen on for regular/StartTLS
        "listen": ":2525",

        // Enable separate SMTPS listener
        "smtps": true,

        // Listen port for SMTPS
        "listenSmtps": ":4650",

        // Enable STARTTLS (Requires tlsCert and tlsKey)
        "startTls": true,

        // Path to TLS Certificate
        "tlsCert": "tls.crt",

        // Path to TLS Private Key
        "tlsKey": "tls.key",

        // Allow users with insecure connections (no SSL/TLS/StartTLS)
        "allowInsecure": true,

        // Timeout for read/write operations
        "readTimeout": 10,
        "writeTimeout": 10,

        // Maximum number of recipients per message
        "maxRecipients": 100,

        // Maximum message size in MB
        "maxMessageSizeMb": 30,

        // User credentials
        "credentials": {
            "all": {
                "password": "all",
                
                // Allow all domains
                "allowedDomains": []
            },
            "specific": {
                "password": "specific",

                // Allow user to send only from the specified domains
                "allowedDomains": [
                    "example.com"
                ]
            }
        }
    },
    // Remote SMTP Server Configuration
    "remote": {
        // Hostname
        "host": "mail.provider.com",

        // Port
        "port": "25",

        // Enable StartTLS
        "startTls": true,

        // Credentials
        "username": "",
        "password": "",

        // Use PLAIN authentication
        "authPlain": false,

        // Use LOGIN authentication
        "authLogin": false
    }
}
```

## Functionality
### Authentication
Authentication with username/password (PLAIN/LOGIN) defined in the json configuration.

### Backend
Any SMTP backend can be used

### Authorization
Set allowed sender domains for each individual account to prevent abuse.

### TLS
Support for StartTLS (regular port) and SMTPS (SMTPS Port, optional).

