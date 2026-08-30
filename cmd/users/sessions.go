package main

import (
	"context"
	"errors"
	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/dfmco999/virtulapp_project/pkg/grpcx"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"log"
	"strings"
	"time"
)

func (s *server) Login(ctx context.Context, req *usersv1.LoginRequest) (*usersv1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}

	emailNormalized := normalizeEmail(req.GetEmail())
	now := time.Now().UTC()

	var user User
	err := s.db.WithContext(ctx).
		Preload("Profile").
		Preload("Preferences").
		First(&user, "email_normalized = ?", emailNormalized).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	var cred Credentials
	err = s.db.WithContext(ctx).
		First(&cred, "user_id = ?", user.ID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			_ = s.createAudit(ctx, &user.ID, "LOGIN_FAILED", "FAIL", `{"reason":"credentials_not_found"}`)
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	user.Credentials = cred

	if user.Status == "DELETED" || user.Status == "SUSPENDED" || user.Status == "INACTIVE" {
		_ = s.createAudit(ctx, &user.ID, "LOGIN_DENIED", "DENY", `{"reason":"status_blocked"}`)
		return nil, status.Error(codes.PermissionDenied, "account unavailable")
	}

	if user.Status == "LOCKED" {
		if cred.LockedUntil != nil && cred.LockedUntil.After(now) {
			_ = s.createAudit(ctx, &user.ID, "LOGIN_DENIED", "DENY", `{"reason":"locked"}`)
			return nil, status.Error(codes.PermissionDenied, "account locked")
		}

		if err := s.clearExpiredLock(ctx, user.ID); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		user.Status = "ACTIVE"
		cred.LockedUntil = nil
		cred.FailedLoginCount = 0
	} else if cred.LockedUntil != nil && cred.LockedUntil.After(now) {
		_ = s.createAudit(ctx, &user.ID, "LOGIN_DENIED", "DENY", `{"reason":"locked"}`)
		return nil, status.Error(codes.PermissionDenied, "account locked")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(req.GetPassword())); err != nil {
		lockValues := map[string]any{
			"failed_login_count":   gorm.Expr("failed_login_count + 1"),
			"last_failed_login_at": now,
		}
		if req.GetIpAddress() != "" {
			lockValues["last_failed_login_ip"] = req.GetIpAddress()
		}

		if err2 := s.db.WithContext(ctx).Model(&Credentials{}).
			Where("user_id = ?", user.ID).
			Updates(lockValues).Error; err2 != nil {
			log.Printf("update failed login count: %v", err2)
		}

		var updatedCred Credentials
		if err2 := s.db.WithContext(ctx).First(&updatedCred, "user_id = ?", user.ID).Error; err2 == nil {
			if updatedCred.FailedLoginCount >= 4 {
				lockedUntil := now.Add(15 * time.Minute)
				_ = s.db.WithContext(ctx).Model(&Credentials{}).
					Where("user_id = ?", user.ID).
					Update("locked_until", lockedUntil).Error
				_ = s.db.WithContext(ctx).Model(&User{}).
					Where("id = ?", user.ID).
					Update("status", "LOCKED").Error
			}
		}

		_ = s.createAudit(ctx, &user.ID, "LOGIN_FAILED", "FAIL", `{"reason":"invalid_password"}`)
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if !user.IsEmailVerified {
		_ = s.createAudit(ctx, &user.ID, "LOGIN_DENIED", "DENY", `{"reason":"email_not_verified"}`)
		return nil, status.Error(codes.PermissionDenied, "email not verified")
	}

	refreshHash := hashToken(uuid.NewString())

	sessionID := uuid.NewString()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Credentials{}).
			Where("user_id = ?", user.ID).
			Updates(map[string]any{
				"failed_login_count":    0,
				"locked_until":          nil,
				"last_success_login_ip": emptyToNilString(req.GetIpAddress()),
			}).Error; err != nil {
			return err
		}

		if err := tx.Model(&User{}).
			Where("id = ?", user.ID).
			Updates(map[string]any{
				"last_login_at": now,
				"status":        "ACTIVE",
			}).Error; err != nil {
			return err
		}

		sess := UserSession{
			ID:               sessionID,
			UserID:           user.ID,
			RefreshTokenHash: refreshHash,
			IPAddress:        nilIfEmpty(req.GetIpAddress()),
			UserAgent:        nilIfEmpty(req.GetUserAgent()),
			ExpiresAt:        now.Add(webSessionTTL),
			LastUsedAt:       &now,
			CreatedAt:        now,
		}
		if err := tx.Create(&sess).Error; err != nil {
			return err
		}

		audit := UserAuditLog{
			ID:          uuid.NewString(),
			UserID:      &user.ID,
			EventType:   "LOGIN_SUCCESS",
			EventResult: "SUCCESS",
			IPAddress:   nilIfEmpty(req.GetIpAddress()),
			Details:     `{"source":"grpc"}`,
			CreatedAt:   now,
		}
		if err := tx.Create(&audit).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	s.invalidateUserCache(ctx, user.ID)
	updated, err := s.loadUserAggregate(ctx, user.ID)
	if err == nil {
		s.cacheUser(ctx, updated)
	}

	return &usersv1.LoginResponse{
		User:               updated,
		MustChangePassword: cred.MustChangePassword,
		SessionId:          sessionID,
	}, nil
}

func (s *server) Logout(ctx context.Context, req *usersv1.LogoutRequest) (*usersv1.LogoutResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}

	now := time.Now().UTC()

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.First(&user, "id = ?", req.GetUserId()).Error; err != nil {
			return err
		}

		update := tx.Model(&UserSession{}).
			Where("id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?", req.GetSessionId(), req.GetUserId(), now).
			Update("revoked_at", now)
		if update.Error != nil {
			return update.Error
		}

		audit := UserAuditLog{
			ID:          uuid.NewString(),
			UserID:      ptr(req.GetUserId()),
			EventType:   "LOGOUT",
			EventResult: "SUCCESS",
			IPAddress:   nilIfEmpty(req.GetIpAddress()),
			Details:     buildLogoutAuditDetails(update.RowsAffected > 0, req.GetUserAgent()),
			CreatedAt:   now,
		}
		if err := tx.Create(&audit).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	s.invalidateUserCache(ctx, req.GetUserId())
	return &usersv1.LogoutResponse{}, nil
}

func (s *server) ValidateSession(ctx context.Context, req *usersv1.ValidateSessionRequest) (*usersv1.ValidateSessionResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	sessionID := strings.TrimSpace(req.GetSessionId())
	if userID == "" || sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and session_id required")
	}

	principal, ok := grpcx.PrincipalFromContext(ctx)
	if !ok || principal.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "session principal mismatch")
	}

	now := time.Now().UTC()
	newExpiry := now.Add(webSessionTTL)
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.Select("id", "tenant_id", "status").First(&user, "id = ?", userID).Error; err != nil {
			return err
		}
		// The active tenant may differ from the identity tenant when the user has
		// memberships in several companies. Edge only issues that context after
		// Licences validates the membership.
		if user.Status != "ACTIVE" {
			return errSessionInactive
		}

		var session UserSession
		if err := tx.First(&session, "id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?", sessionID, userID, now).Error; err != nil {
			return err
		}
		if !sameSessionFingerprint(&session, req.GetIpAddress(), req.GetUserAgent()) {
			return errSessionInactive
		}

		update := tx.Model(&UserSession{}).
			Where("id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?", sessionID, userID, now).
			Updates(map[string]any{"last_used_at": now, "expires_at": newExpiry})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return errSessionInactive
		}
		return nil
	})
	if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, errSessionInactive) {
		return nil, status.Error(codes.Unauthenticated, "session inactive or expired")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to validate session")
	}

	return &usersv1.ValidateSessionResponse{ExpiresAt: timestamppb.New(newExpiry)}, nil
}

func (s *server) clearExpiredLock(ctx context.Context, userID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Credentials{}).
			Where("user_id = ?", userID).
			Updates(map[string]any{
				"failed_login_count": 0,
				"locked_until":       nil,
			}).Error; err != nil {
			return err
		}

		if err := tx.Model(&User{}).
			Where("id = ? AND status = ?", userID, "LOCKED").
			Update("status", "ACTIVE").Error; err != nil {
			return err
		}

		return nil
	})
}

func sameSessionFingerprint(session *UserSession, ipAddress, userAgent string) bool {
	if session == nil {
		return false
	}

	if normalizeSessionValue(session.IPAddress) != normalizeSessionValue(nilIfEmpty(ipAddress)) {
		return false
	}

	if normalizeSessionValue(session.UserAgent) != normalizeSessionValue(nilIfEmpty(userAgent)) {
		return false
	}

	return true
}

func normalizeSessionValue(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}
