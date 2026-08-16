package testing

import (
	"errors"
	"testing"

	"github.com/Motmedel/utils_go/pkg/mail/types/message"
)

func TestNewSigner(t *testing.T) {
	t.Parallel()

	signer := NewSigner()
	if signer == nil {
		t.Fatalf("nil signer")
	}

	signature, err := signer.Sign([]byte("message"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := signer.Verify([]byte("message"), signature); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestMustParseUrl(t *testing.T) {
	t.Parallel()

	if parsed := MustParseUrl(LinkBaseUrl); parsed == nil || parsed.Host != "example.com" {
		t.Errorf("parsed url: got %v", parsed)
	}

	t.Run("panics on invalid url", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if recover() == nil {
				t.Errorf("expected panic")
			}
		}()

		MustParseUrl("://invalid")
	})
}

func TestMustFromAddress(t *testing.T) {
	t.Parallel()

	if address := MustFromAddress(); address == nil || address.Address != FromAddress {
		t.Errorf("from address: got %v", address)
	}
}

func TestSetUp(t *testing.T) {
	t.Parallel()

	sessionManager, signer := SetUp()
	if sessionManager == nil || signer == nil {
		t.Fatalf("incomplete setup: (%v, %v)", sessionManager, signer)
	}
	defer sessionManager.Db.Close()
}

func TestFakeMailSender(t *testing.T) {
	t.Parallel()

	sender := &FakeMailSender{}
	if sender.Last() != nil {
		t.Errorf("expected no last message")
	}

	sentMessage := &message.Message{}
	if err := sender.SendMessage(t.Context(), sentMessage); err != nil {
		t.Fatalf("send message: %v", err)
	}

	if sender.Last() != sentMessage || len(sender.Messages) != 1 {
		t.Errorf("messages: got %v", sender.Messages)
	}

	sender.Err = errors.ErrUnsupported
	if err := sender.SendMessage(t.Context(), sentMessage); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("expected configured error, got %v", err)
	}
}
