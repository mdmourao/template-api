package smtp

import (
	"fmt"
	"net/smtp"
	"os"
)

const (
	Sender  = "martim.mourao.irs+email@gmail.com"
	CharSet = "UTF-8"
)

func SendToken(recipientEmail string, token string) error {
	var err error

	msg := []byte("Subject: Account Token\r\n" +
		"\r\n" +
		"Token: " + token + "\r\n")

	auth := smtp.PlainAuth("", os.Getenv("SMTP_USERNAME"), os.Getenv("SMTP_PASSWORD"), os.Getenv("SMTP_ENDPOINT"))
	fmt.Println(os.Getenv("SMTP_ENDPOINT"))
	err = smtp.SendMail(fmt.Sprintf("%s:%s", os.Getenv("SMTP_ENDPOINT"), os.Getenv("SMTP_PORT")), auth, Sender, []string{recipientEmail}, msg)

	if err != nil {
		fmt.Printf("Error to sending email: %s", err)
		return err
	}

	fmt.Println("email sent success")
	return nil
}
