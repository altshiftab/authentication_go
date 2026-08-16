package account

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/customer"
)

type Account struct {
	Id           string             `json:"id" postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	Name         string             `json:"name" postgres:"name,default:''"`
	EmailAddress string             `json:"email_address" postgres:"email_address,unique,type:citext,check:(email_address ~* '^[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$')"`
	CreatedAt    *time.Time         `json:"created_at" postgres:"created_at,default:now()"`
	Locked       bool               `json:"locked" postgres:"locked,default:false"`
	Customer     *customer.Customer `json:"customer" postgres:"customer,nullable"`
	Roles        []string           `json:"roles" postgres:"roles"`
}
