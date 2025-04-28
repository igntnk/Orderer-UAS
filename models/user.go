package models

type User struct {
	Id             string `json:"id" bson:"id"`
	Username       string `json:"username" bson:"username"`
	HashedPassword string `json:"hashedPassword" bson:"hashedPassword"`
	Salt           string `json:"salt" bson:"salt"`
	LastLogin      string `json:"lastLogin" bson:"lastLogin"`
	IsBlocked      bool   `json:"isBlocked" bson:"isBlocked"`
}
