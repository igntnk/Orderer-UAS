package util

import (
	"github.com/igntnk/Orderer-UAS/models"
	authpb "github.com/igntnk/Orderer-UAS/proto/pb"
	"github.com/igntnk/Orderer-UAS/responses"
)

func GetUsersToAuthPb(in []*responses.GetUsersResponse) (*authpb.GetUsersResponse, error) {
	result := &authpb.GetUsersResponse{}

	for _, user := range in {
		authMes := &authpb.GetUserMessage{
			Id:        user.Id,
			Username:  user.Username,
			LastLogin: user.LastLogin,
			IsBlocked: user.IsBlocked,
		}

		result.Users = append(result.Users, authMes)
	}

	return result, nil
}

func FromUserModelsToPb(in *models.User) *authpb.GetUserMessage {
	result := &authpb.GetUserMessage{}
	result.Id = in.Id
	result.Username = in.Username
	result.LastLogin = in.LastLogin
	result.IsBlocked = in.IsBlocked
	return result
}

func FromUserModelsToResponse(in *models.User) *responses.GetUsersResponse {
	result := &responses.GetUsersResponse{}
	result.Id = in.Id
	result.Username = in.Username
	result.LastLogin = in.LastLogin
	result.IsBlocked = in.IsBlocked
	return result
}
