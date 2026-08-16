package customer

type Customer struct {
	Id   string `json:"id" postgres:"id,primarykey,default:encode(gen_random_bytes(8),'hex')"`
	Name string `json:"name" postgres:"name,unique"`
}
