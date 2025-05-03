package convert

import (
	"github.com/igntnk/Orderer-UAS/models"
	"github.com/igntnk/Orderer-UAS/responses"
)

func UsersModelToResponses(in []models.User) ([]*responses.GetUsersResponse, error) {
	var err error

	response := make([]*responses.GetUsersResponse, len(in))
	for i, user := range in {
		response[i], err = UserModelToResponse(user)
		if err != nil {
			return response, err
		}
	}

	return response, nil
}

func UserModelToResponse(in models.User) (*responses.GetUsersResponse, error) {
	response := &responses.GetUsersResponse{
		Id:        in.Id,
		Username:  in.Username,
		LastLogin: in.LastLogin,
		IsBlocked: in.IsBlocked,
	}

	return response, nil
}
