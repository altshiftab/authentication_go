package mail_sender

import (
	"context"

	"github.com/Motmedel/utils_go/pkg/mail/types/message"
)

type Sender interface {
	SendMessage(ctx context.Context, msg *message.Message) error
}
