package requests

type InsertUserRequest struct {
	Username  string `json:"username" bson:"username"`
	Password  string `json:"password" bson:"password"`
	IsBlocked bool   `json:"isBlocked" bson:"isBlocked"`
}

type GetUserRequest struct {
	Limit  int64 `json:"limit" bson:"limit"`
	Offset int64 `json:"offset" bson:"offset"`
}

type DeleteUserRequest struct {
	Id string `json:"id" bson:"id"`
}

type UpdateUserRequest struct {
	Id        string `json:"id" bson:"id"`
	Username  string `json:"username" bson:"username"`
	Password  string `json:"password" bson:"password"`
	IsBlocked bool   `json:"isBlocked" bson:"isBlocked"`
}
