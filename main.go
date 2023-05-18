package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"time"

	"github.com/emersion/go-smtp"
)

type Credential struct {
	Password       string   `json:"password"`
	AllowedDomains []string `json:"allowedDomains"`
}

type ServerConfig struct {
	Host             string                `json:"host" default:"localhost"`
	Listen           string                `json:"listen" default:":2525"`
	AllowInsecure    bool                  `json:"allowInsecure" default:"true"`
	ReadTimeout      time.Duration         `json:"readTimeout" default:"10"`
	WriteTimeout     time.Duration         `json:"writeTimeout" default:"10"`
	MaxRecipients    int                   `json:"maxRecipients" default:"50"`
	MaxMessageSizeMb int                   `json:"maxMessageSizeMb" default:"30"`
	Credentials      map[string]Credential `json:"credentials"`
}

type RemoteConfig struct {
	Host      string `json:"host" default:"localhost"`
	Port      string `json:"port" default:"2525"`
	StartTls  bool   `json:"startTls" default:"false"`
	AuthPlain bool   `json:"authPlain" default:"false"`
	AuthLogin bool   `json:"authLogin" default:"false"`
	Username  string `json:"username" default:""`
	Password  string `json:"password" default:""`
}

type Config struct {
	Server ServerConfig `json:"server"`
	Remote RemoteConfig `json:"remote"`
}

// The Backend implements SMTP server methods.
type Backend struct{}

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

func (bkd *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

// A Session is returned after EHLO.
type Session struct {
	FEmail Mail
}

func (s *Session) SendMail() error {
	c, err := smtp.Dial(remote.Config.Host + ":" + remote.Config.Port)
	if err != nil {
		return err
	}

	defer c.Close()

	reader := bytes.NewReader(s.FEmail.Data)

	if remote.Config.StartTls {
		if err := c.StartTLS(nil); err != nil {
			return err
		}
	}

	err = c.SendMail(s.FEmail.From, s.FEmail.To, reader)
	if err != nil {
		return err
	}

	return nil
}

func (s *Session) AuthPlain(username, password string) error {
	log.Println("AuthPlain Called")

	val, ok := config.Server.Credentials[username]
	if !ok || val.Password != password {
		return errors.New("invalid username or password")
	}

	log.Println("User accepted")
	s.FEmail.Credential = val
	return nil
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
	log.Println("Mail from:", from)
	if len(s.FEmail.Credential.AllowedDomains) > 0 {
		if !sliceContains(s.FEmail.Credential.AllowedDomains, from) {
			return errors.New("invalid sender domain: not allowed")
		}
	}
	s.FEmail.From = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	log.Println("Rcpt to:", to)
	s.FEmail.To = append(s.FEmail.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	if b, err := io.ReadAll(r); err != nil {
		return err
	} else {
		s.FEmail.Data = b
		log.Println("Data:", string(b))
	}

	err := s.SendMail()
	if err != nil {
		return errors.New("Sending email failed: " + err.Error())
	}
	return nil
}

func (s *Session) Reset() {
	log.Println("Reset Called")
}

func (s *Session) Logout() error {
	log.Println("Logout Called")
	return nil
}

func main() {
	// Create config
	config = &Config{}

	// Read config.json into temp string
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal config
	json.Unmarshal(configFile, &config)

	be := &Backend{}

	remote = Remote{
		Config: config.Remote,
	}

	s := smtp.NewServer(be)

	s.Addr = config.Server.Listen
	s.Domain = config.Server.Host
	s.ReadTimeout = config.Server.ReadTimeout * time.Second
	s.WriteTimeout = config.Server.WriteTimeout * time.Second
	s.MaxMessageBytes = config.Server.MaxMessageSizeMb * 1024 * 1024
	s.MaxRecipients = config.Server.MaxRecipients
	s.AllowInsecureAuth = config.Server.AllowInsecure

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
