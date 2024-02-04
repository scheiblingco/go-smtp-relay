package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

var TERMINATED string
var LASTMOD int64

type Credential struct {
	Password       string   `json:"password"`
	AllowedDomains []string `json:"allowedDomains"`
}

type ServerConfig struct {
	Host             string        `json:"host" default:"localhost"`
	Listen           int           `json:"listen" default:"2525"`
	StartTLS         bool          `json:"startTls" default:"false"`
	SMTPS            bool          `json:"smtps" default:"false"`
	ListenSMTPS      int           `json:"listenSmtps" default:"4650"`
	TLSCert          string        `json:"tlsCert" default:""`
	TLSKey           string        `json:"tlsKey" default:""`
	AllowInsecure    bool          `json:"allowInsecure" default:"true"`
	ReadTimeout      time.Duration `json:"readTimeout" default:"10"`
	WriteTimeout     time.Duration `json:"writeTimeout" default:"10"`
	MaxRecipients    int           `json:"maxRecipients" default:"50"`
	MaxMessageSizeMb int           `json:"maxMessageSizeMb" default:"30"`
}

type RemoteConfig struct {
	Host          string `json:"host" default:"localhost"`
	Port          int    `json:"port" default:"2525"`
	StartTls      bool   `json:"startTls" default:"false"`
	AuthPlain     bool   `json:"authPlain" default:"false"`
	AuthLogin     bool   `json:"authLogin" default:"false"`
	Username      string `json:"username" default:""`
	Password      string `json:"password" default:""`
	TlsSkipVerify bool   `json:"tlsSkipVerify" default:"false"`
}

type Config struct {
	Server      ServerConfig          `json:"server"`
	Remote      RemoteConfig          `json:"remote"`
	Credentials map[string]Credential `json:"credentials"`
}

// The Backend implements SMTP server methods.
type RelayBackend struct{}

type Mail struct {
	Credential Credential
	From       string
	To         []string
	Data       []byte
}

type Remote struct {
	Config RemoteConfig
}

var remote Remote
var config *Config

func (bkd *RelayBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	log.Println("Session started")
	return &Session{Anonymous: true}, nil
}

type Session struct {
	Anonymous    bool
	RelayMessage Mail
}

func (s *Session) SendMail() error {
	c, err := smtp.Dial(remote.Config.Host + ":" + fmt.Sprint(remote.Config.Port))
	if err != nil {
		return err
	}

	defer c.Close()

	reader := bytes.NewReader(s.RelayMessage.Data)

	if remote.Config.StartTls {
		var tlsc *tls.Config
		if remote.Config.TlsSkipVerify {
			tlsc = &tls.Config{
				InsecureSkipVerify: true,
			}
		}

		if err := c.StartTLS(tlsc); err != nil {
			return err
		}
	}

	if remote.Config.AuthPlain {
		auth := sasl.NewPlainClient("", remote.Config.Username, remote.Config.Password)
		if err := c.Auth(auth); err != nil {
			return err
		}
	} else if remote.Config.AuthLogin {
		auth := sasl.NewLoginClient(remote.Config.Username, remote.Config.Password)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}

	log.Println("Mail from", s.RelayMessage.From, "to", s.RelayMessage.To)
	err = c.SendMail(s.RelayMessage.From, s.RelayMessage.To, reader)
	s.RelayMessage = Mail{}

	if err != nil {
		log.Println("Sending email failed: ", err.Error())
		return err
	}

	log.Println("Sent successfully")
	return nil
}

func (s *Session) AuthPlain(username, password string) error {
	fmt.Println(config.Credentials)
	val, ok := config.Credentials[username]

	if ok && val.Password == password {
		log.Println("User", username, "authenticated successfully")
		s.Anonymous = false
		s.RelayMessage.Credential = val
		return nil
	}
	log.Println("User", username, "authenticated failed")
	return errors.New("invalid username or password")
}

func sliceContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	if s.Anonymous {
		return errors.New("anonymous users are not allowed to send mail")
	}

	log.Println("sending mail from:", from)
	if len(s.RelayMessage.Credential.AllowedDomains) > 0 {
		splt := strings.Split(from, "@")
		if !sliceContains(s.RelayMessage.Credential.AllowedDomains, splt[1]) {
			allowstr := strings.Join(s.RelayMessage.Credential.AllowedDomains, ", ")
			return fmt.Errorf("invalid sender domain: %s not allowed (%s)", splt[1], allowstr)
		}
	}
	s.RelayMessage.From = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	s.RelayMessage.To = append(s.RelayMessage.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	if b, err := io.ReadAll(r); err != nil {
		return err
	} else {
		s.RelayMessage.Data = b
	}

	err := s.SendMail()
	if err != nil {
		return errors.New("sending email failed: " + err.Error())
	}
	return nil
}

func (s *Session) Reset() {
	log.Println("resetting message, preparing for next")
	s.RelayMessage = Mail{}
}

func (s *Session) Logout() error {
	log.Println("session ended, closing")
	s = &Session{}
	return nil
}

func Listen(s *smtp.Server) {
	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
		panic(err)
	}
}

func ListemSmtps(tlss *smtp.Server) {
	log.Println("Starting TLS server at ", tlss.Addr)
	if err := tlss.ListenAndServeTLS(); err != nil {
		log.Fatal(err)
		panic(err)
	}
}

func ListenHealthcheck(cfg *Config) {
	updateToken := os.Getenv("X_UPDATE_TOKEN")

	http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "accounts.json" && r.Method != "POST" {
			w.WriteHeader(200)
			w.Write([]byte("OK"))
			return
		}

		if updateToken == "" {
			w.WriteHeader(500)
			w.Write([]byte("X_UPDATE_TOKEN not set"))
			return
		}

		headerToken := r.Header.Get("X-Update-Token")

		if headerToken == "" || headerToken != updateToken {
			w.WriteHeader(403)
			w.Write([]byte("Invalid token"))
			return
		}

		var updatedAccounts map[string]Credential
		err := json.NewDecoder(r.Body).Decode(&updatedAccounts)

		if err != nil {
			fmt.Println("Failed updating accounts")
			fmt.Println(err.Error())
			w.WriteHeader(500)
			w.Write([]byte("Failed updating accounts"))
			return
		}

		cfg.Credentials = updatedAccounts
		fmt.Println("Updated accounts: ")
		fmt.Println(cfg.Credentials)

	})) // nolint:errcheck
}

func main() {
	TERMINATED = ""

	// Create config
	config = &Config{}
	credentials := &map[string]Credential{}

	// Get last changed timestamp
	credentialsInfo, err := os.Stat("credentials.json")
	if err != nil {
		log.Fatal(err)
		TERMINATED = err.Error()
	}

	LASTMOD = credentialsInfo.ModTime().Unix()

	// Read config.json into temp string
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal(err)
		TERMINATED = err.Error()
	}

	credentialFile, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatal(err)
		TERMINATED = err.Error()
	}

	// Unmarshal config
	json.Unmarshal(configFile, &config)
	json.Unmarshal(credentialFile, &credentials)

	config.Credentials = *credentials

	be := &RelayBackend{}

	remote = Remote{
		Config: config.Remote,
	}

	smtps := smtp.NewServer(be)
	var smtpss *smtp.Server

	var tlsc *tls.Config

	if config.Server.SMTPS || config.Server.StartTLS {
		log.Println("StartTLS/TLS enabled, checking certificates...")

		tlsCert, err := tls.LoadX509KeyPair(
			config.Server.TLSCert,
			config.Server.TLSKey,
		)

		if err != nil {
			log.Fatal(err)
		}

		certInfo, err := x509.ParseCertificate(tlsCert.Certificate[0])

		if err != nil {
			log.Fatal(err)
		}

		log.Println("Certificate hostnames: ", certInfo.DNSNames)

		tlsc = &tls.Config{
			ServerName: config.Server.Host,
			Certificates: []tls.Certificate{
				tlsCert,
			},
			NameToCertificate: map[string]*tls.Certificate{
				config.Server.Host: &tlsCert,
			},
		}
	}

	smtps.Addr = ":" + fmt.Sprint(config.Server.Listen)
	smtps.Domain = config.Server.Host
	smtps.ReadTimeout = config.Server.ReadTimeout * time.Second
	smtps.WriteTimeout = config.Server.WriteTimeout * time.Second
	smtps.MaxMessageBytes = config.Server.MaxMessageSizeMb * 1024 * 1024
	smtps.MaxRecipients = config.Server.MaxRecipients
	smtps.AllowInsecureAuth = config.Server.AllowInsecure
	smtps.AuthDisabled = false
	smtps.TLSConfig = tlsc

	smtps.EnableAuth(sasl.Login,
		func(conn *smtp.Conn) sasl.Server {
			return sasl.NewLoginServer(func(username, password string) error {
				sess := conn.Session()
				if sess == nil {
					panic("No session when AUTH is called")
				}

				return sess.AuthPlain(username, password)
			})
		},
	)

	if config.Server.SMTPS {
		smtpss = smtp.NewServer(be)
		smtpss.Addr = ":" + fmt.Sprint(config.Server.ListenSMTPS)
		smtpss.Domain = config.Server.Host
		smtpss.ReadTimeout = config.Server.ReadTimeout * time.Second
		smtpss.WriteTimeout = config.Server.WriteTimeout * time.Second
		smtpss.MaxMessageBytes = config.Server.MaxMessageSizeMb * 1024 * 1024
		smtpss.MaxRecipients = config.Server.MaxRecipients
		smtpss.AllowInsecureAuth = config.Server.AllowInsecure
		smtpss.AuthDisabled = false
		smtpss.TLSConfig = tlsc

		smtpss.EnableAuth(sasl.Login,
			func(conn *smtp.Conn) sasl.Server {
				return sasl.NewLoginServer(func(username, password string) error {
					sess := conn.Session()
					if sess == nil {
						panic("No session when AUTH is called")
					}

					return sess.AuthPlain(username, password)
				})
			},
		)
	}

	if config.Server.SMTPS {
		go ListemSmtps(smtpss)
	}

	go Listen(smtps)

	ListenHealthcheck(config)
}
