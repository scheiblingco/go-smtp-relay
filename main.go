package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
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
	return &Session{Anonymous: true}, nil
}

type Session struct {
	Anonymous    bool
	RelayMessage Mail
}

func (s *Session) SendMail() error {
	fmt.Println("TO: ", s.RelayMessage.To, "Data: ", string(s.RelayMessage.Data))

	c, err := smtp.Dial(remote.Config.Host + ":" + remote.Config.Port)
	if err != nil {
		return err
	}

	defer c.Close()

	reader := bytes.NewReader(s.RelayMessage.Data)

	if remote.Config.StartTls {
		if err := c.StartTLS(nil); err != nil {
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

	err = c.SendMail(s.RelayMessage.From, s.RelayMessage.To, reader)

	s.RelayMessage = Mail{}

	if err != nil {
		return err
	}

	return nil
}

func (s *Session) AuthPlain(username, password string) error {
	log.Println("authentication started")
	val, ok := config.Server.Credentials[username]

	if ok && val.Password == password {
		log.Println("user", username, "authenticated successfully")
		s.Anonymous = false
		s.RelayMessage.Credential = val
		return nil
	}

	log.Println("invalid username/password", username, password)
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
	log.Println("sending mail to:", to)
	s.RelayMessage.To = append(s.RelayMessage.To, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	if b, err := io.ReadAll(r); err != nil {
		return err
	} else {
		s.RelayMessage.Data = b
		log.Println("sending data: ", string(b))
	}

	err := s.SendMail()
	if err != nil {
		return errors.New("Sending email failed: " + err.Error())
	}
	return nil
}

func (s *Session) Reset() {
	s.RelayMessage = Mail{}
}

func (s *Session) Logout() error {
	log.Println("session ended, resetting object")
	s = &Session{}
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

	be := &RelayBackend{}

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
	s.AuthDisabled = false

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
