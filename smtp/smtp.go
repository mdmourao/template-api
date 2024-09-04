package smtp

import (
	"context"
	"fmt"
	"os"

	"github.com/resend/resend-go/v2"
)

const (
	Sender  = "martim.mourao.irs+email@gmail.com"
	CharSet = "UTF-8"
)

func SendToken(recipientEmail string, token string) error {
	var err error

	apiKey := os.Getenv("RESEND_APIKEY")
	fromEmail := os.Getenv("RESEND_FROM_EMAIL")
	fromName := os.Getenv("RESEND_FROM_NAME")

	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf(`%s <%s>`, fromName, fromEmail),
		To:      []string{recipientEmail},
		Subject: "Account Token",
		Text:    "Token: " + token + "\r\n",
	}

	_, err = client.Emails.SendWithContext(context.TODO(), params)

	return err
}
