package responses

type InsertUserResponse struct {
	Id string `json:"id"`
}

type GetUsersResponse struct {
	Id        string `json:"id"`
	Username  string `json:"username"`
	LastLogin string `json:"last_login"`
	IsBlocked bool   `json:"is_blocked"`
}
