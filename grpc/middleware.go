package grpc

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/igntnk/Orderer-UAS/grpc/util"
	"github.com/igntnk/Orderer-UAS/middleware"
	"github.com/igntnk/Orderer-UAS/service"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Middleware interface {
	AddAuthorizedMethod(method string)
	RemoveAuthorizedMethod(method string)
	CheckAccessMethod() []string
	AddCheckAccessMethod(method string)
	RemoveCheckAccessMethod(method string)
	Unary() grpc.UnaryServerInterceptor
	Stream() grpc.StreamServerInterceptor
}

const TokenInfo = "TokenInfo"

type grpcMiddleware struct {
	authorizedMethods map[string]any
	checkAccessMethod map[string]any
	logger            zerolog.Logger
	jwk               service.JWK
}

func NewMiddleware(
	jwk service.JWK,
	logger zerolog.Logger,
	authorizedMethods map[string]any,
	checkAccessMethod map[string]any) Middleware {
	return &grpcMiddleware{
		authorizedMethods: authorizedMethods,
		checkAccessMethod: checkAccessMethod,
		logger:            logger,
		jwk:               jwk,
	}
}

func (m *grpcMiddleware) AddAuthorizedMethod(method string) {
	m.authorizedMethods[method] = struct{}{}
}

func (m *grpcMiddleware) RemoveAuthorizedMethod(method string) {
	delete(m.authorizedMethods, method)
}

func (m *grpcMiddleware) CheckAccessMethod() []string {
	methods := make([]string, 0)
	for method, _ := range m.checkAccessMethod {
		methods = append(methods, method)
	}
	return methods
}

func (m *grpcMiddleware) RemoveCheckAccessMethod(method string) {
	delete(m.checkAccessMethod, method)
}

func (m *grpcMiddleware) AddCheckAccessMethod(method string) {
	m.checkAccessMethod[method] = struct{}{}
}

func (m *grpcMiddleware) authorize(ctx context.Context, fullMethodName string) (context.Context, error) {
	if m.authorizedMethods[fullMethodName] == nil &&
		m.checkAccessMethod[fullMethodName] == nil {
		return ctx, nil
	}

	authToken, err := util.GetAuthToken(ctx)
	if err != nil {
		return ctx, err
	}

	tokenInfo, err := middleware.ParseToken(authToken, m.jwk)
	if err != nil {
		if errors.Is(jwt.ErrTokenExpired, err) {
			return ctx, status.Errorf(codes.Unauthenticated, "Token expired")
		}
		return ctx, status.Errorf(codes.Unauthenticated, "Token invalid")
	}

	if ctx.Value(TokenInfo) == nil {
		ctx = context.WithValue(ctx, TokenInfo, tokenInfo)
	}

	return ctx, nil
}

func (m *grpcMiddleware) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		ctx, err = m.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

func newWrappedServerStream(s grpc.ServerStream, ctx context.Context) *wrappedServerStream {
	return &wrappedServerStream{
		ServerStream: s,
		ctx:          ctx,
	}
}

func (m *grpcMiddleware) Stream() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := m.authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		return handler(srv, newWrappedServerStream(ss, ctx))
	}
}
