package grpcx

import (
	"context"
	"crypto/rsa"
	"strings"

	"github.com/dfmco999/virtulapp_project/pkg/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ctxKey struct{}

type Principal struct {
	UserID   string
	TenantID string
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

func RequireIATInterceptor(pub *rsa.PublicKey) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		authz := ""
		if v := md.Get("authorization"); len(v) > 0 {
			authz = v[0]
		}
		if authz == "" || !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}

		token := strings.TrimSpace(authz[7:])
		claims, err := auth.VerifyIAT(pub, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid iat")
		}

		p := Principal{UserID: claims.UserID, TenantID: claims.TenantID}
		ctx = context.WithValue(ctx, ctxKey{}, p)
		return handler(ctx, req)
	}
}
