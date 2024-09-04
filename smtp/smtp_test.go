package smtp

import (
	"log"
	"testing"

	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

func TestEmailSend(t *testing.T) {
	if err := godotenv.Load("../.dev/dev.env"); err != nil {
		log.Fatal(".env file not found")
	}

	err := SendToken("martim.mourao.irs+email@gmail.com", "123456")

	assert.Nil(t, err, nil)

}
