package main

import (
	"context"
	"errors"
	"fmt"
	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/dfmco999/virtulapp_project/pkg/auth"
	"github.com/dfmco999/virtulapp_project/pkg/grpcx"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadIATPublicKeyPEM() string {
	if v := strings.TrimSpace(os.Getenv("IAT_PUBLIC_KEY_PEM")); v != "" {
		return v
	}

	if path := strings.TrimSpace(os.Getenv("IAT_PUBLIC_KEY_PATH")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read IAT_PUBLIC_KEY_PATH: %v", err)
		}
		return string(b)
	}

	log.Fatal("missing config: define IAT_PUBLIC_KEY_PEM or IAT_PUBLIC_KEY_PATH")
	return ""
}

func normalizeListenAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ":50051"
	}
	if strings.Contains(addr, ":") {
		return addr
	}
	return ":" + addr
}

func loadDotEnv() {
	for _, path := range dotenvCandidatePaths() {
		if err := loadDotEnvFile(path); err == nil {
			log.Printf("loaded env from %s", path)
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: unable to load %s: %v", path, err)
		}
	}
}

func dotenvCandidatePaths() []string {
	seen := make(map[string]struct{})
	var paths []string
	add := func(path string) {
		if strings.TrimSpace(path) == "" {
			return
		}
		clean := filepath.Clean(path)
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		paths = append(paths, clean)
	}

	if wd, err := os.Getwd(); err == nil {
		add(filepath.Join(wd, ".env"))
		add(filepath.Join(wd, "virtulapp_users", ".env"))

		dir := wd
		for {
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			add(filepath.Join(parent, ".env"))
			dir = parent
		}
	}

	if exe, err := os.Executable(); err == nil {
		add(filepath.Join(filepath.Dir(exe), ".env"))
	}

	if _, file, _, ok := runtime.Caller(0); ok {
		add(filepath.Join(filepath.Dir(file), "..", "..", ".env"))
	}

	return paths
}

func loadDotEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:eq])
		raw := strings.TrimSpace(line[eq+1:])
		if key == "" {
			continue
		}

		value, next, err := parseDotEnvValue(raw, lines, i, key)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		i = next

		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseDotEnvValue(raw string, lines []string, index int, key string) (string, int, error) {
	if raw == "" {
		return "", index, nil
	}

	quote := raw[0]
	if quote != '"' && quote != '\'' {
		return strings.TrimSpace(raw), index, nil
	}

	value := raw[1:]
	for {
		if end := strings.IndexByte(value, quote); end >= 0 {
			return value[:end], index, nil
		}

		index++
		if index >= len(lines) {
			return "", index, fmt.Errorf("unterminated quoted value for %s", key)
		}
		value += "\n" + lines[index]
	}
}

func main() {
	loadDotEnv()

	dsn := getenv("DATABASE_URL", "")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("gorm open: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("get sql db: %v", err)
	}
	schema, err := os.ReadFile("./sql/schema.sql")
	if err != nil {
		log.Fatalf("read users schema: %v", err)
	}
	if _, err := sqlDB.Exec(string(schema)); err != nil {
		log.Fatalf("apply users schema: %v", err)
	}
	if err := bootstrapSuperAdmin(db); err != nil {
		log.Fatalf("bootstrap super admin: %v", err)
	}

	rdb := newRedisClient()

	grpcAddr := normalizeListenAddr(getenv("GRPC_ADDR", ":"+getenv("PORT", "50051")))
	pub, err := auth.LoadRSAPublicKeyFromEnvOrFile(loadIATPublicKeyPEM())
	if err != nil {
		log.Fatalf("load iat public key: %v", err)
	}

	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer(grpc.UnaryInterceptor(grpcx.RequireIATInterceptor(pub)))
	usersv1.RegisterUsersServiceServer(srv, &server{
		db:    db,
		redis: rdb,
	})

	log.Printf("running users service on %s", grpcAddr)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("grpc serve: %v", err)
	}
}

func bootstrapSuperAdmin(db *gorm.DB) error {
	password := strings.TrimSpace(os.Getenv("SUPER_ADMIN_PASSWORD"))
	if password == "" {
		return nil
	}

	email := normalizeEmail(getenv("SUPER_ADMIN_EMAIL", "admin@virtualapp.com"))
	username := strings.TrimSpace(getenv("SUPER_ADMIN_USERNAME", "superadmin"))
	if username == "" {
		username = "superadmin"
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}

	const userID = "00000000-0000-0000-0000-000000000001"
	const tenantID = "00000000-0000-0000-0000-000000000001"
	now := time.Now().UTC()

	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`
			INSERT INTO users (id, external_id, username, email, email_normalized, tenant_id, role, status, is_email_verified, is_phone_verified, created_at, updated_at)
			VALUES (?, NULL, ?, ?, ?, ?, 'SUPER_ADMIN', 'ACTIVE', true, false, ?, ?)
			ON CONFLICT (id) DO UPDATE
			SET username=EXCLUDED.username,
			    email=EXCLUDED.email,
			    email_normalized=EXCLUDED.email_normalized,
			    tenant_id=EXCLUDED.tenant_id,
			    role='SUPER_ADMIN',
			    status='ACTIVE',
			    updated_at=EXCLUDED.updated_at
		`, userID, username, email, email, tenantID, now, now).Error; err != nil {
			return err
		}
		if err := tx.Exec(`
			INSERT INTO user_credentials (user_id, password_hash, failed_login_count, locked_until, must_change_password, created_at, updated_at)
			VALUES (?, ?, 0, NULL, false, ?, ?)
			ON CONFLICT (user_id) DO UPDATE
			SET password_hash=EXCLUDED.password_hash,
			    failed_login_count=0,
			    locked_until=NULL,
			    must_change_password=false,
			    updated_at=EXCLUDED.updated_at
		`, userID, passwordHash, now, now).Error; err != nil {
			return err
		}
		if err := tx.Exec(`
			INSERT INTO user_profiles (user_id, first_name, last_name, full_name, locale, timezone, created_at, updated_at)
			VALUES (?, 'Super', 'Admin', 'Super Admin', 'es-CO', 'America/Bogota', ?, ?)
			ON CONFLICT (user_id) DO UPDATE
			SET first_name=EXCLUDED.first_name,
			    last_name=EXCLUDED.last_name,
			    full_name=EXCLUDED.full_name,
			    updated_at=EXCLUDED.updated_at
		`, userID, now, now).Error; err != nil {
			return err
		}
		if err := tx.Exec(`
			INSERT INTO user_preferences (user_id, theme, language, email_notifications, sms_notifications, push_notifications, marketing_opt_in, metadata, created_at, updated_at)
			VALUES (?, 'system', 'es', true, false, true, false, '{}', ?, ?)
			ON CONFLICT (user_id) DO NOTHING
		`, userID, now, now).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE user_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID).Error; err != nil {
			return err
		}

		log.Printf("super admin bootstrap applied for %s", email)
		return nil
	})
}

func newRedisClient() *redis.Client {
	if redisURL := strings.TrimSpace(os.Getenv("REDIS_URL")); redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Printf("redis disabled: invalid REDIS_URL: %v", err)
			return nil
		}

		rdb := redis.NewClient(opt)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("redis disabled: ping failed for REDIS_URL: %v", err)
			_ = rdb.Close()
			return nil
		}
		log.Println("redis cache enabled via REDIS_URL")
		return rdb
	}

	if redisAddr := strings.TrimSpace(os.Getenv("REDIS_ADDR")); redisAddr != "" {
		rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("redis disabled: ping failed for REDIS_ADDR=%q: %v", redisAddr, err)
			_ = rdb.Close()
			return nil
		}
		log.Printf("redis cache enabled via REDIS_ADDR=%q", redisAddr)
		return rdb
	}

	log.Println("redis disabled: REDIS_URL/REDIS_ADDR not configured")
	return nil
}
