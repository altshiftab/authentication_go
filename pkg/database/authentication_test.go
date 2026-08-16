package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	motmedelSqlTesting "github.com/Motmedel/utils_go/pkg/database/sql/testing"
)

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestInsertAuthentication(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name        string
		accountId   string
		db          *sql.DB
		ctx         context.Context
		wantErrKind string
	}{
		{name: "empty account id", db: db, ctx: context.Background(), wantErrKind: "empty"},
		{name: "nil db", accountId: "id", db: nil, ctx: context.Background(), wantErrKind: "nil"},
		{name: "canceled ctx", accountId: "id", db: db, ctx: canceledCtx(), wantErrKind: "ctx"},
		{name: "scan no rows", accountId: "id", db: db, ctx: context.Background(), wantErrKind: "scan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := InsertAuthentication(tt.ctx, tt.accountId, []byte("hash"), time.Hour, nil, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tt.wantErrKind == "ctx" && !errors.Is(err, context.Canceled) {
				t.Errorf("expected context.Canceled in chain, got %v", err)
			}
		})
	}
}

func TestSelectRefreshAuthentication(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name string
		id   string
		db   *sql.DB
		ctx  context.Context
	}{
		{name: "empty id", id: "", db: db, ctx: context.Background()},
		{name: "nil db", id: "id", db: nil, ctx: context.Background()},
		{name: "canceled ctx", id: "id", db: db, ctx: canceledCtx()},
		{name: "scan no rows", id: "id", db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := SelectRefreshAuthentication(tt.ctx, tt.id, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestSelectEmailAddressAccount(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name  string
		email string
		db    *sql.DB
		ctx   context.Context
	}{
		{name: "empty email", email: "", db: db, ctx: context.Background()},
		{name: "nil db", email: "user@example.com", db: nil, ctx: context.Background()},
		{name: "canceled ctx", email: "user@example.com", db: db, ctx: canceledCtx()},
		{name: "scan no rows", email: "user@example.com", db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := SelectEmailAddressAccount(tt.ctx, tt.email, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestUpdateAuthenticationWithDbscPublicKey(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name    string
		id      string
		key     []byte
		db      *sql.DB
		ctx     context.Context
		wantErr bool
	}{
		{name: "empty id", id: "", key: []byte("k"), db: db, ctx: context.Background(), wantErr: true},
		{name: "empty key", id: "id", key: nil, db: db, ctx: context.Background(), wantErr: true},
		{name: "nil db", id: "id", key: []byte("k"), db: nil, ctx: context.Background(), wantErr: true},
		{name: "canceled ctx", id: "id", key: []byte("k"), db: db, ctx: canceledCtx(), wantErr: true},
		{name: "success", id: "id", key: []byte("k"), db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := UpdateAuthenticationWithDbscPublicKey(tt.ctx, tt.id, tt.key, tt.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateAuthenticationWithEnded(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name    string
		id      string
		db      *sql.DB
		ctx     context.Context
		wantErr bool
	}{
		{name: "empty id", id: "", db: db, ctx: context.Background(), wantErr: true},
		{name: "nil db", id: "id", db: nil, ctx: context.Background(), wantErr: true},
		{name: "canceled ctx", id: "id", db: db, ctx: canceledCtx(), wantErr: true},
		{name: "success", id: "id", db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := UpdateAuthenticationWithEnded(tt.ctx, tt.id, tt.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestInsertOauthFlow(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name         string
		state        string
		codeVerifier string
		redirectUrl  string
		duration     time.Duration
		db           *sql.DB
		ctx          context.Context
	}{
		{name: "empty state", state: "", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: db, ctx: context.Background()},
		{name: "empty code verifier", state: "s", codeVerifier: "", redirectUrl: "u", duration: time.Hour, db: db, ctx: context.Background()},
		{name: "empty redirect", state: "s", codeVerifier: "cv", redirectUrl: "", duration: time.Hour, db: db, ctx: context.Background()},
		{name: "zero duration", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: 0, db: db, ctx: context.Background()},
		{name: "nil db", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: nil, ctx: context.Background()},
		{name: "canceled ctx", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: db, ctx: canceledCtx()},
		{name: "scan no rows", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := InsertOauthFlow(tt.ctx, tt.state, tt.codeVerifier, tt.redirectUrl, tt.duration, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestPopOauthFlow(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name string
		id   string
		db   *sql.DB
		ctx  context.Context
	}{
		{name: "empty id", id: "", db: db, ctx: context.Background()},
		{name: "nil db", id: "id", db: nil, ctx: context.Background()},
		{name: "canceled ctx", id: "id", db: db, ctx: canceledCtx()},
		{name: "scan no rows", id: "id", db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := PopOauthFlow(tt.ctx, tt.id, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestInsertDbscChallenge(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name             string
		challenge        string
		authenticationId string
		duration         time.Duration
		db               *sql.DB
		ctx              context.Context
		wantErr          bool
	}{
		{name: "empty challenge", challenge: "", authenticationId: "id", duration: time.Hour, db: db, ctx: context.Background(), wantErr: true},
		{name: "empty authentication id", challenge: "c", authenticationId: "", duration: time.Hour, db: db, ctx: context.Background(), wantErr: true},
		{name: "zero duration", challenge: "c", authenticationId: "id", duration: 0, db: db, ctx: context.Background(), wantErr: true},
		{name: "nil db", challenge: "c", authenticationId: "id", duration: time.Hour, db: nil, ctx: context.Background(), wantErr: true},
		{name: "canceled ctx", challenge: "c", authenticationId: "id", duration: time.Hour, db: db, ctx: canceledCtx(), wantErr: true},
		{name: "success", challenge: "c", authenticationId: "id", duration: time.Hour, db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := InsertDbscChallenge(tt.ctx, tt.challenge, tt.authenticationId, tt.duration, tt.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestPopDbscChallenge(t *testing.T) {
	t.Parallel()

	db := motmedelSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name             string
		challenge        string
		authenticationId string
		db               *sql.DB
		ctx              context.Context
	}{
		{name: "empty challenge", challenge: "", authenticationId: "id", db: db, ctx: context.Background()},
		{name: "empty authentication id", challenge: "c", authenticationId: "", db: db, ctx: context.Background()},
		{name: "nil db", challenge: "c", authenticationId: "id", db: nil, ctx: context.Background()},
		{name: "canceled ctx", challenge: "c", authenticationId: "id", db: db, ctx: canceledCtx()},
		{name: "scan no rows", challenge: "c", authenticationId: "id", db: db, ctx: context.Background()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := PopDbscChallenge(tt.ctx, tt.challenge, tt.authenticationId, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
