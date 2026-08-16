package testing

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/mail"
	"net/url"
	"sync"

	motmedelCryptoEddsa "github.com/Motmedel/utils_go/pkg/crypto/eddsa"
	"github.com/Motmedel/utils_go/pkg/mail/types/message"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	ssoTesting "github.com/altshiftab/authentication_go/pkg/sso/testing"
)

const (
	Domain       = "example.com"
	FromAddress  = "noreply@example.com"
	LinkBaseUrl  = "https://example.com/login/magic"
	RedirectUrl  = "https://example.com/account"
	ValidEmail   = "test@example.com"
	InvalidEmail = "not-an-email"
	DefaultNonce = "00000000-0000-4000-8000-000000000000"
)

func NewSigner() *motmedelCryptoEddsa.Method {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Errorf("ed25519 generate key: %w", err))
	}
	return &motmedelCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}
}

func MustParseUrl(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(fmt.Errorf("url parse %q: %w", raw, err))
	}
	return parsed
}

func MustFromAddress() *mail.Address {
	return &mail.Address{Address: FromAddress}
}

func SetUp() (*session_manager.Manager, *motmedelCryptoEddsa.Method) {
	sessionManager, _, _, _ := ssoTesting.SetUp()
	signer := NewSigner()
	return sessionManager, signer
}

type FakeMailSender struct {
	mu       sync.Mutex
	Err      error
	Messages []*message.Message
}

func (f *FakeMailSender) SendMessage(_ context.Context, msg *message.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Messages = append(f.Messages, msg)
	return f.Err
}

func (f *FakeMailSender) Last() *message.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Messages) == 0 {
		return nil
	}
	return f.Messages[len(f.Messages)-1]
}
