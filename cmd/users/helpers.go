package main

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"time"
)

func (User) TableName() string { return "users" }

func (Credentials) TableName() string { return "user_credentials" }

func (UserProfile) TableName() string { return "user_profiles" }

func (UserPreference) TableName() string { return "user_preferences" }

func (PasswordEntry) TableName() string { return "user_password_history" }

func (UserAuditLog) TableName() string { return "user_audit_logs" }

func (UserSession) TableName() string { return "user_sessions" }

func (s *server) createAudit(ctx context.Context, userID *string, eventType, result, details string) error {
	audit := UserAuditLog{
		ID:          uuid.NewString(),
		UserID:      userID,
		EventType:   eventType,
		EventResult: result,
		Details:     details,
		CreatedAt:   time.Now().UTC(),
	}
	return s.db.WithContext(ctx).Create(&audit).Error
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func nilIfEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	v := strings.TrimSpace(s)
	return &v
}

func emptyToNilString(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func buildFullName(first, last string) *string {
	full := strings.TrimSpace(strings.TrimSpace(first) + " " + strings.TrimSpace(last))
	if full == "" {
		return nil
	}
	return &full
}

func buildLogoutAuditDetails(sessionRevoked bool, userAgent string) string {
	payload := map[string]any{
		"source":          "grpc",
		"session_revoked": sessionRevoked,
	}
	if trimmed := strings.TrimSpace(userAgent); trimmed != "" {
		payload["user_agent"] = trimmed
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return `{"source":"grpc","session_revoked":false}`
	}
	return string(b)
}

func ptr[T any](v T) *T {
	return &v
}

func mapGormError(err error) error {
	if err == nil {
		return nil
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "duplicate key value"),
		strings.Contains(msg, "duplicar llave"),
		strings.Contains(msg, "unique constraint"):
		return status.Error(codes.AlreadyExists, "duplicate value")
	case strings.Contains(msg, "foreign key"):
		return status.Error(codes.FailedPrecondition, "foreign key violation")
	case strings.Contains(msg, "check constraint"):
		return status.Error(codes.InvalidArgument, "check constraint violation")
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
