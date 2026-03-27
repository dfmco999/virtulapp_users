package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"os"
	"time"

	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/dfmco999/virtulapp_project/pkg/auth"
	"github.com/dfmco999/virtulapp_project/pkg/grpcx"
	"github.com/dfmco999/virtulapp_project/pkg/util"
	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/redis/go-redis/v9"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type server struct {
	usersv1.UnimplementedUsersServiceServer
	db    *sql.DB
	redis *redis.Client
}

const userCacheTTL = 5 * time.Minute

func (s *server) CreateUser(ctx context.Context, req *usersv1.CreateUserRequest) (*usersv1.CreateUserResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	id := uuid.NewString()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, tenant_id) VALUES ($1,$2,$3)`,
		id, req.GetEmail(), req.GetTenantId(),
	)
	if err != nil {
		return nil, mapPGError(err)
	}

	return &usersv1.CreateUserResponse{
		User: &usersv1.User{UserId: id, Email: req.Email, TenantId: req.TenantId},
	}, nil
}

func (s *server) GetUser(ctx context.Context, req *usersv1.GetUserRequest) (*usersv1.GetUserResponse, error) {
	if u, ok := s.getCachedUser(ctx, req.UserId); ok {
		return &usersv1.GetUserResponse{User: u}, nil
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id,email,tenant_id FROM users WHERE id=$1`, req.UserId,
	)

	var id, email, tenant string
	if err := row.Scan(&id, &email, &tenant); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	u := &usersv1.User{UserId: id, Email: email, TenantId: tenant}
	s.cacheUser(ctx, u)

	return &usersv1.GetUserResponse{User: u}, nil
}

func (s *server) ListUsers(ctx context.Context, req *usersv1.ListUsersRequest) (*usersv1.ListUsersResponse, error) {
	limit := req.GetLimit()
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id,email,tenant_id FROM users LIMIT $1 OFFSET $2`,
		limit, req.GetOffset(),
	)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	var out []*usersv1.User
	for rows.Next() {
		var id, email, tenant string
		rows.Scan(&id, &email, &tenant)
		out = append(out, &usersv1.User{UserId: id, Email: email, TenantId: tenant})
	}

	return &usersv1.ListUsersResponse{Users: out}, nil
}

func (s *server) UpdateUser(ctx context.Context, req *usersv1.UpdateUserRequest) (*usersv1.UpdateUserResponse, error) {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email=$2, tenant_id=$3 WHERE id=$1`,
		req.UserId, req.Email, req.TenantId,
	)
	if err != nil {
		return nil, mapPGError(err)
	}
	s.invalidateUserCache(ctx, req.UserId)

	return &usersv1.UpdateUserResponse{}, nil
}

func (s *server) DeleteUser(ctx context.Context, req *usersv1.DeleteUserRequest) (*usersv1.DeleteUserResponse, error) {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM users WHERE id=$1`, req.UserId,
	)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.invalidateUserCache(ctx, req.UserId)
	return &usersv1.DeleteUserResponse{}, nil
}

func (s *server) cacheUser(ctx context.Context, u *usersv1.User) {
	b, _ := json.Marshal(u)
	s.redis.Set(ctx, "users:"+u.UserId, b, userCacheTTL)
}

func (s *server) getCachedUser(ctx context.Context, id string) (*usersv1.User, bool) {
	val, err := s.redis.Get(ctx, "users:"+id).Result()
	if err != nil {
		return nil, false
	}
	var u usersv1.User
	json.Unmarshal([]byte(val), &u)
	return &u, true
}

func (s *server) invalidateUserCache(ctx context.Context, id string) {
	s.redis.Del(ctx, "users:"+id)
}

func mapPGError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23505" {
			return status.Error(codes.AlreadyExists, "duplicate")
		}
	}
	return status.Error(codes.Internal, err.Error())
}

func main() {
	db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_ADDR")})

	lis, _ := net.Listen("tcp", ":50051")

	srv := grpc.NewServer()
	usersv1.RegisterUsersServiceServer(srv, &server{db: db, redis: rdb})

	log.Println("running users service")
	srv.Serve(lis)
}
