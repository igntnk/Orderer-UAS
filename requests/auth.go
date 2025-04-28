package requests

import "fmt"

type AuthRequest map[string]interface{}

func (r AuthRequest) GetString(key string) (string, error) {
	v, e := r[key]
	if !e {
		return "", fmt.Errorf("couldn't find key %s", key)
	}

	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("key %s's value is not a string", key)
	}

	return str, nil
}

type Login struct {
	Username string `json:"username" bson:"username" mapstructure:"username"`
	Password string `json:"password" bson:"password" mapstructure:"password"`
	Source   string `json:"source" bson:"source" mapstructure:"source"`
}

type ChangePassword struct {
	Username    string `json:"username,omitempty" bson:"username"`
	OldPassword string `json:"password" bson:"password"`
	NewPassword string `json:"newPassword" bson:"newPassword"`
}
