package main

import (
	"context"
	"database/sql"
	"net"
	"os"

	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/dfmco999/virtulapp_project/pkg/auth"
	"github.com/dfmco999/virtulapp_project/pkg/grpcx"
	"github.com/dfmco999/virtulapp_project/pkg/util"
	_ "github.com/jackc/pgx/v5/stdlib"
	"google.golang.org/grpc"
)

type server struct {
	usersv1.UnimplementedUsersServiceServer
	db *sql.DB
}

func (s *server) GetUser(ctx context.Context, req *usersv1.GetUserRequest) (*usersv1.GetUserResponse, error) {
	row := s.db.QueryRowContext(ctx, `select id, email, tenant_id from users where id=$1`, req.UserId)
	var id, email, tid string
	if err := row.Scan(&id, &email, &tid); err != nil {
		return nil, err
	}
	return &usersv1.GetUserResponse{UserId: id, Email: email, TenantId: tid}, nil
}

func main() {
	// Railway inyecta PORT, usamos 50051 como fallback
	port := getenv("PORT", "50051")
	grpcAddr := ":" + port

	pub, err := auth.LoadRSAPublicKeyFromEnvOrFile(getenv("IAT_PUBLIC_KEY_PEM", ""))
	must(err)

	db, err := sql.Open("pgx", getenv("DATABASE_URL", ""))
	must(err)
	must(db.Ping())

	_ = util.ExecSchemaFromFile(db, "./sql/schema.sql")

	lis, err := net.Listen("tcp", grpcAddr)
	must(err)

	// El servidor gRPC interno NO necesita TLS si Railway maneja el borde o si es red privada
	srv := grpc.NewServer(grpc.UnaryInterceptor(grpcx.RequireIATInterceptor(pub)))
	usersv1.RegisterUsersServiceServer(srv, &server{db: db})

	println("Servidor Users escuchando en el puerto " + port)
	must(srv.Serve(lis))
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
