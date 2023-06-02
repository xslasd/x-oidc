package storage

import (
	"context"
	"github.com/xslasd/x-oidc/constant"
	"github.com/xslasd/x-oidc/ecode"
	"github.com/xslasd/x-oidc/log"
	"github.com/xslasd/x-oidc/model"
	"github.com/xslasd/x-oidc/storage"
	"time"
)

type Storage struct {
	cliMap   map[string]storage.IClient
	aReqMap  map[string]storage.AuthRequest
	codeMap  map[string]string
	tokenMap map[string]storage.TokenModel

	userMap map[string]model.UserInfo

	logger log.Logger
}

func NewStorage() storage.IStorage {
	cliMap := map[string]storage.IClient{
		"P0001": Client{
			secret: "12345",
			responseTypes: []string{
				constant.ResponseTypeCode,
				constant.ResponseTypeIDToken,
				constant.ResponseTypeIDTokenOnly,
				constant.ResponseTypeToken,
			},
			scopes: []string{
				constant.ScopeOpenID,
				constant.ScopeProfile,
			},
			redirectURIs: []string{
				"http://localhost:5556/auth/callback",
			},
			loginURL:        "/login",
			idTokenLifetime: time.Minute * 60,
		},
	}
	return &Storage{
		cliMap:   cliMap,
		aReqMap:  make(map[string]storage.AuthRequest),
		codeMap:  make(map[string]string),
		tokenMap: make(map[string]storage.TokenModel),
	}
}
func (s *Storage) SetLogger(logger log.Logger) {
	s.logger = logger
}

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (storage.IClient, error) {
	cli, ok := s.cliMap[clientID]
	if !ok {
		return nil, ecode.ClientIDIsNull
	}
	return cli, nil
}

func (s *Storage) SaveAuthRequest(ctx context.Context, req storage.AuthRequest) error {
	s.aReqMap[req.RequestID] = req
	return nil
}

func (s *Storage) AuthRequestBindCallbackData(ctx context.Context, requestID, userID string) (*storage.AuthRequest, error) {
	aReq, ok := s.aReqMap[requestID]
	if !ok {
		return nil, ecode.AuthRequestNotExist
	}
	aReq.UserID = userID
	aReq.Done = true
	s.aReqMap[requestID] = aReq
	return &aReq, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (*storage.AuthRequest, error) {
	requestID, ok := s.codeMap[code]
	if !ok {
		return nil, ecode.AuthRequestNotExist
	}
	//code can only be used once,so delete
	delete(s.codeMap, code)
	aReq := s.aReqMap[requestID]
	return &aReq, nil
}
func (s *Storage) AuthRequestByRequestID(ctx context.Context, requestID string) (*storage.AuthRequest, error) {
	aReq := s.aReqMap[requestID]
	return &aReq, nil
}

func (s *Storage) AuthRequestByRefreshToken(ctx context.Context, refreshToken string) (*storage.TokenModel, *storage.AuthRequest, error) {
	for _, item := range s.tokenMap {
		if item.RefreshToken == refreshToken {
			aReq := s.aReqMap[item.RequestID]
			return &item, &aReq, nil
		}
	}
	return nil, nil, ecode.AuthRequestNotExist
}
func (s *Storage) AuthRequestByTokenID(ctx context.Context, tokenID string) (*storage.TokenModel, *storage.AuthRequest, error) {
	for _, item := range s.tokenMap {
		if item.TokenID == tokenID {
			aReq := s.aReqMap[item.RequestID]
			return &item, &aReq, nil
		}
	}
	return nil, nil, ecode.AuthRequestNotExist
}

func (s *Storage) AuthRequestByJWTClientToken(ctx context.Context, client storage.IClient, token model.JWTClientTokenClaims) (*storage.AuthRequest, error) {
	for _, item := range s.aReqMap {
		if item.ClientID == client.GetClientID() && item.UserID == token.Subject {
			return &item, nil
		}
	}
	return nil, ecode.AuthRequestNotExist
}

func (s *Storage) SaveAuthRequestCode(ctx context.Context, requestID, code string) error {
	s.codeMap[code] = requestID
	return nil
}

func (s *Storage) SaveTokenModel(ctx context.Context, tokenModel storage.TokenModel) error {
	s.tokenMap[tokenModel.RequestID] = tokenModel
	return nil
}

func (s *Storage) UpdateTokenModelByRefreshToken(ctx context.Context, tokenModel storage.TokenModel) error {
	s.tokenMap[tokenModel.RequestID] = tokenModel
	return nil
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, authReq storage.AuthRequest, client storage.IClient, scopes []string) (*model.UserInfo, error) {
	return &model.UserInfo{Subject: "test" + authReq.UserID}, nil
}

func (s *Storage) SetIntrospectUserinfo(ctx context.Context, authReq storage.AuthRequest, accessTokenClaims model.AccessTokenClaims) (*model.UserInfo, error) {
	return &model.UserInfo{
		Subject: authReq.UserID,
	}, nil
}
func (s *Storage) SetUserinfo(ctx context.Context, authReq storage.AuthRequest, accessTokenClaims model.AccessTokenClaims, origin string) (*model.UserInfo, error) {
	return &model.UserInfo{
		Subject: authReq.UserID,
	}, nil
}

func (s *Storage) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	for _, item := range s.tokenMap {
		if item.RefreshToken == refreshToken {
			item.RefreshToken = ""
			item.RefreshTokenExpiration = time.Now().UTC()
			s.tokenMap[item.RequestID] = item
			return nil
		}
	}
	return nil
}

func (s *Storage) RevokeAccessToken(ctx context.Context, accessTokenClaims model.AccessTokenClaims) error {
	for _, item := range s.tokenMap {
		if item.TokenID == accessTokenClaims.JWTID {
			delete(s.tokenMap, item.RequestID)
			return nil
		}
	}
	return nil
}
