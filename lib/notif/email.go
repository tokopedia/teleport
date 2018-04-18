package notif

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	gomail "gopkg.in/gomail.v2"
)

func SendRegistrationLink(cfg *service.Config, user services.UserV1, recipient, token string) error {
	smtpConf := cfg.SMTP

	SmtpUser := smtpConf.Username
	SmtpPass := smtpConf.Password
	Host := smtpConf.Host
	Port := smtpConf.Port
	Sender := smtpConf.Sender
	SenderName := smtpConf.SenderName
	Subject := "Your teleport account"

	m := gomail.NewMessage()

	hour := defaults.SignupTokenTTL / (time.Hour)

	body := fmt.Sprintf(
		"Hi %s.\n\n"+
			"You or your lead has requested teleport account for you.\n"+
			"Use this link below to complete the registration.\n"+
			"https://%s/web/newuser/%s"+
			"\n\nThis signup token only valid for %d hour(s)"+
			"\n\n---"+
			"\nPlease read documentation first in here: https://phab.tokopedia.com/w/tech/devops/teleport/",
		user.Name,
		cfg.ProxyHost,
		token,
		hour,
	)

	// Set the alternative part to plain text.
	m.AddAlternative("text/plain", body)

	// Construct the message headers, including a Configuration Set and a Tag.
	m.SetHeaders(map[string][]string{
		"From":    {m.FormatAddress(Sender, SenderName)},
		"To":      {recipient},
		"Subject": {Subject},
	})

	// Send the email.
	d := gomail.NewPlainDialer(Host, Port, SmtpUser, SmtpPass)

	if err := d.DialAndSend(m); err != nil {
		fmt.Sprintln("Failed to send email to <%s>", recipient)
		return err
	} else {
		fmt.Sprintln("Email sent email to <%s>", recipient)
		return nil
	}
}
