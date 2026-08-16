package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"reflect"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/database/types/account"
	"github.com/altshiftab/authentication_go/pkg/database/types/customer"
)

// rowDriver is a minimal database/sql driver that returns a single, pre-configured
// row for any query. It lets us exercise the row-scanning logic of
// SelectEmailAddressAccount without a real database.
type rowDriver struct {
	columns []string
	values  []driver.Value
}

func (d *rowDriver) Connect(context.Context) (driver.Conn, error) { return &rowConn{driver: d}, nil }
func (d *rowDriver) Driver() driver.Driver                        { return &staticDriver{} }

type staticDriver struct{}

func (*staticDriver) Open(string) (driver.Conn, error) { return nil, io.ErrUnexpectedEOF }

type rowConn struct {
	driver *rowDriver
}

func (c *rowConn) Prepare(string) (driver.Stmt, error) { return nil, io.ErrUnexpectedEOF }
func (c *rowConn) Close() error                        { return nil }
func (c *rowConn) Begin() (driver.Tx, error)           { return nil, io.ErrUnexpectedEOF }

func (c *rowConn) QueryContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	return &rowRows{columns: c.driver.columns, values: c.driver.values}, nil
}

var _ driver.QueryerContext = (*rowConn)(nil)

type rowRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *rowRows) Columns() []string { return r.columns }
func (r *rowRows) Close() error      { return nil }
func (r *rowRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	copy(dest, r.values)
	r.done = true
	return nil
}

func newRowDb(columns []string, values []driver.Value) *sql.DB {
	return sql.OpenDB(&rowDriver{columns: columns, values: values})
}

// accountColumns matches the projection of SelectEmailAddressAccount's query:
// a.id, a.locked, c.id, c.name, roles.
var accountColumns = []string{"id", "locked", "id", "name", "roles"}

// TestSelectEmailAddressAccount_Scan covers the row-mapping of
// SelectEmailAddressAccount. It is a regression test for a bug where the scanned
// "locked" column was never assigned to the returned Account, which let locked
// accounts create sessions (session_manager.CreateSession refuses locked
// accounts). It also verifies the customer join and roles are mapped.
func TestSelectEmailAddressAccount_Scan(t *testing.T) {
	t.Parallel()

	type args struct {
		emailAddress string
		columns      []string
		values       []driver.Value
	}
	tests := []struct {
		name    string
		args    args
		want    *account.Account
		wantErr bool
	}{
		{
			name: "locked account",
			args: args{
				emailAddress: "user@example.com",
				columns:      accountColumns,
				values:       []driver.Value{"account-id", true, nil, nil, []byte("{admin,user}")},
			},
			want: &account.Account{
				Id:           "account-id",
				EmailAddress: "user@example.com",
				Locked:       true,
				Roles:        []string{"admin", "user"},
			},
		},
		{
			name: "unlocked account",
			args: args{
				emailAddress: "user@example.com",
				columns:      accountColumns,
				values:       []driver.Value{"account-id", false, nil, nil, []byte("{admin,user}")},
			},
			want: &account.Account{
				Id:           "account-id",
				EmailAddress: "user@example.com",
				Locked:       false,
				Roles:        []string{"admin", "user"},
			},
		},
		{
			name: "account with customer",
			args: args{
				emailAddress: "user@example.com",
				columns:      accountColumns,
				values:       []driver.Value{"account-id", false, "customer-id", "Customer Name", []byte("{}")},
			},
			want: &account.Account{
				Id:           "account-id",
				EmailAddress: "user@example.com",
				Locked:       false,
				Customer:     &customer.Customer{Id: "customer-id", Name: "Customer Name"},
				Roles:        []string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db := newRowDb(tt.args.columns, tt.args.values)
			t.Cleanup(func() { _ = db.Close() })

			got, err := SelectEmailAddressAccount(context.Background(), tt.args.emailAddress, db)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SelectEmailAddressAccount() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SelectEmailAddressAccount() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
