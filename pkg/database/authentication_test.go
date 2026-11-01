package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
)

// testCtx is the test's context, or one already canceled.
func testCtx(t *testing.T, canceled bool) context.Context {
	if canceled {
		return canceledCtx()
	}
	return t.Context()
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestInsertAuthentication(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name        string
		accountId   string
		db          *sql.DB
		canceled    bool
		wantErrKind string
	}{
		{name: "empty account id", db: db, wantErrKind: "empty"},
		{name: "nil db", accountId: "id", db: nil, wantErrKind: "nil"},
		{name: "canceled ctx", accountId: "id", db: db, canceled: true, wantErrKind: "ctx"},
		{name: "scan no rows", accountId: "id", db: db, wantErrKind: "scan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := InsertAuthentication(testCtx(t, tt.canceled), tt.accountId, []byte("hash"), time.Hour, nil, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tt.wantErrKind == "ctx" && !errors.Is(err, context.Canceled) {
				t.Errorf("expected context.Canceled in chain, got %v", err)
			}
		})
	}
}

// testStringKeyedLookup runs the refusals a lookup by one string shares: an empty value, no
// database, a canceled context, and no row.
func testStringKeyedLookup(t *testing.T, value string, lookup func(ctx context.Context, value string, db *sql.DB) error) {
	t.Helper()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	testCases := []struct {
		name     string
		value    string
		db       *sql.DB
		canceled bool
	}{
		{name: "empty value", value: "", db: db},
		{name: "nil db", value: value, db: nil},
		{name: "canceled ctx", value: value, db: db, canceled: true},
		{name: "scan no rows", value: value, db: db},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if err := lookup(testCtx(t, testCase.canceled), testCase.value, testCase.db); err == nil {
				t.Fatalf("%s: expected error, got nil", testCase.name)
			}
		})
	}
}

func TestSelectIdTokenHashUsed(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	testCases := []struct {
		name        string
		idTokenHash []byte
		db          *sql.DB
		canceled    bool
	}{
		{name: "empty hash", db: db},
		{name: "nil db", idTokenHash: []byte("hash")},
		{name: "canceled ctx", idTokenHash: []byte("hash"), db: db, canceled: true},
		{name: "scan no rows", idTokenHash: []byte("hash"), db: db},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if _, err := SelectIdTokenHashUsed(testCtx(t, testCase.canceled), testCase.idTokenHash, testCase.db); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestSelectRefreshAuthentication(t *testing.T) {
	t.Parallel()

	testStringKeyedLookup(t, "id", func(ctx context.Context, value string, db *sql.DB) error {
		_, err := SelectRefreshAuthentication(ctx, value, db)
		return err
	})
}

func TestSelectEmailAddressAccount(t *testing.T) {
	t.Parallel()

	testStringKeyedLookup(t, "user@example.com", func(ctx context.Context, value string, db *sql.DB) error {
		_, err := SelectEmailAddressAccount(ctx, value, db)
		return err
	})
}

func TestUpdateAuthenticationWithDbscPublicKey(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name     string
		id       string
		key      []byte
		db       *sql.DB
		canceled bool
		wantErr  bool
	}{
		{name: "empty id", id: "", key: []byte("k"), db: db, wantErr: true},
		{name: "empty key", id: "id", key: nil, db: db, wantErr: true},
		{name: "nil db", id: "id", key: []byte("k"), db: nil, wantErr: true},
		{name: "canceled ctx", id: "id", key: []byte("k"), db: db, canceled: true, wantErr: true},
		{name: "success", id: "id", key: []byte("k"), db: db},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := UpdateAuthenticationWithDbscPublicKey(testCtx(t, tt.canceled), tt.id, tt.key, tt.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateAuthenticationWithEnded(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name     string
		id       string
		db       *sql.DB
		canceled bool
		wantErr  bool
	}{
		{name: "empty id", id: "", db: db, wantErr: true},
		{name: "nil db", id: "id", db: nil, wantErr: true},
		{name: "canceled ctx", id: "id", db: db, canceled: true, wantErr: true},
		{name: "success", id: "id", db: db},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := UpdateAuthenticationWithEnded(testCtx(t, tt.canceled), tt.id, tt.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestInsertOauthFlow(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name         string
		state        string
		codeVerifier string
		redirectUrl  string
		duration     time.Duration
		db           *sql.DB
		canceled     bool
	}{
		{name: "empty state", state: "", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: db},
		{name: "empty code verifier", state: "s", codeVerifier: "", redirectUrl: "u", duration: time.Hour, db: db},
		{name: "empty redirect", state: "s", codeVerifier: "cv", redirectUrl: "", duration: time.Hour, db: db},
		{name: "zero duration", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: 0, db: db},
		{name: "nil db", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: nil},
		{name: "canceled ctx", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: db, canceled: true},
		{name: "scan no rows", state: "s", codeVerifier: "cv", redirectUrl: "u", duration: time.Hour, db: db},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := InsertOauthFlow(testCtx(t, tt.canceled), tt.state, tt.codeVerifier, tt.redirectUrl, tt.duration, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestPopOauthFlow(t *testing.T) {
	t.Parallel()

	testStringKeyedLookup(t, "id", func(ctx context.Context, value string, db *sql.DB) error {
		_, err := PopOauthFlow(ctx, value, db)
		return err
	})
}

func TestPopExpiredOauthFlowByState(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	testCases := []struct {
		name       string
		state      string
		db         *sql.DB
		canceled   bool
		wantNoRows bool
	}{
		{name: "empty state", state: "", db: db},
		{name: "nil db", state: "state", db: nil},
		{name: "canceled ctx", state: "state", db: db, canceled: true},
		// The callback reads no rows as nothing to restart, so it must survive the wrapping.
		{name: "scan no rows", state: "state", db: db, wantNoRows: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if testCase.canceled {
				ctx = canceledCtx()
			}
			flow, err := PopExpiredOauthFlowByState(ctx, testCase.state, time.Now(), testCase.db)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", testCase.name)
			}
			if flow != nil {
				t.Errorf("%s: expected no flow, got %+v", testCase.name, flow)
			}
			if testCase.wantNoRows && !errors.Is(err, sql.ErrNoRows) {
				t.Errorf("%s: expected sql.ErrNoRows in chain, got %v", testCase.name, err)
			}
		})
	}
}

func TestInsertDbscChallenge(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name             string
		challenge        string
		authenticationId string
		duration         time.Duration
		db               *sql.DB
		canceled         bool
		wantErr          bool
	}{
		{name: "empty challenge", challenge: "", authenticationId: "id", duration: time.Hour, db: db, wantErr: true},
		{name: "empty authentication id", challenge: "c", authenticationId: "", duration: time.Hour, db: db, wantErr: true},
		{name: "zero duration", challenge: "c", authenticationId: "id", duration: 0, db: db, wantErr: true},
		{name: "nil db", challenge: "c", authenticationId: "id", duration: time.Hour, db: nil, wantErr: true},
		{name: "canceled ctx", challenge: "c", authenticationId: "id", duration: time.Hour, db: db, canceled: true, wantErr: true},
		{name: "success", challenge: "c", authenticationId: "id", duration: time.Hour, db: db},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := InsertDbscChallenge(testCtx(t, tt.canceled), tt.challenge, tt.authenticationId, tt.duration, tt.db)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestPopDbscChallenge(t *testing.T) {
	t.Parallel()

	db := altshiftSqlTesting.NewDb()
	t.Cleanup(func() { _ = db.Close() })

	tests := []struct {
		name             string
		challenge        string
		authenticationId string
		db               *sql.DB
		canceled         bool
	}{
		{name: "empty challenge", challenge: "", authenticationId: "id", db: db},
		{name: "empty authentication id", challenge: "c", authenticationId: "", db: db},
		{name: "nil db", challenge: "c", authenticationId: "id", db: nil},
		{name: "canceled ctx", challenge: "c", authenticationId: "id", db: db, canceled: true},
		{name: "scan no rows", challenge: "c", authenticationId: "id", db: db},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := PopDbscChallenge(testCtx(t, tt.canceled), tt.challenge, tt.authenticationId, tt.db)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
