package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"strings"
	"time"
)

func (s *server) ChangePassword(ctx context.Context, req *usersv1.ChangePasswordRequest) (*usersv1.ChangePasswordResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if req.GetCurrentPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "current_password required")
	}
	if req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password required")
	}

	var user User
	err := s.db.WithContext(ctx).
		First(&user, "id = ?", req.GetUserId()).Error
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
			return nil, status.Error(codes.NotFound, "credentials not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(req.GetCurrentPassword())); err != nil {
		_ = s.createAudit(ctx, &user.ID, "PASSWORD_CHANGE_FAILED", "FAIL", `{"reason":"invalid_current_password"}`)
		return nil, status.Error(codes.Unauthenticated, "invalid current password")
	}

	var history []PasswordEntry
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", user.ID).
		Order("created_at DESC").
		Limit(5).
		Find(&history).Error; err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	for _, h := range history {
		if bcrypt.CompareHashAndPassword([]byte(h.PasswordHash), []byte(req.GetNewPassword())) == nil {
			return nil, status.Error(codes.InvalidArgument, "new password was already used recently")
		}
	}

	newHash, err := hashPassword(req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to hash password")
	}

	now := time.Now().UTC()

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Credentials{}).
			Where("user_id = ?", user.ID).
			Updates(map[string]any{
				"password_hash":        newHash,
				"must_change_password": false,
				"failed_login_count":   0,
				"locked_until":         nil,
				"password_expires_at":  nil,
			}).Error; err != nil {
			return err
		}

		if err := tx.Model(&User{}).
			Where("id = ?", user.ID).
			Update("password_changed_at", now).Error; err != nil {
			return err
		}

		entry := PasswordEntry{
			ID:           uuid.NewString(),
			UserID:       user.ID,
			PasswordHash: newHash,
			CreatedAt:    now,
		}
		if err := tx.Create(&entry).Error; err != nil {
			return err
		}

		if err := tx.Model(&UserSession{}).
			Where("user_id = ? AND revoked_at IS NULL", user.ID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}

		audit := UserAuditLog{
			ID:          uuid.NewString(),
			UserID:      &user.ID,
			EventType:   "PASSWORD_CHANGED",
			EventResult: "SUCCESS",
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
	return &usersv1.ChangePasswordResponse{}, nil
}

func (s *server) RequestPasswordReset(ctx context.Context, req *usersv1.RequestPasswordResetRequest) (*usersv1.RequestPasswordResetResponse, error) {
	email := normalizeEmail(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	var user User
	if err := s.db.WithContext(ctx).Where("email_normalized = ? AND deleted_at IS NULL", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &usersv1.RequestPasswordResetResponse{}, nil
		}
		return nil, status.Error(codes.Internal, "unable to request password reset")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, status.Error(codes.Internal, "unable to generate reset token")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE password_reset_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL`, now, user.ID).Error; err != nil {
			return err
		}
		return tx.Exec(`INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), user.ID, hex.EncodeToString(hash[:]), now.Add(30*time.Minute), now).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, "unable to store reset token")
	}
	_ = s.createAudit(ctx, &user.ID, "PASSWORD_RESET_REQUESTED", "SUCCESS", `{}`)
	return &usersv1.RequestPasswordResetResponse{ResetToken: token, UserId: user.ID, TenantId: user.TenantID, Email: user.Email}, nil
}

func (s *server) ResetPassword(ctx context.Context, req *usersv1.ResetPasswordRequest) (*usersv1.ResetPasswordResponse, error) {
	if len(req.GetNewPassword()) < 8 {
		return nil, status.Error(codes.InvalidArgument, "new_password must contain at least 8 characters")
	}
	hash := sha256.Sum256([]byte(strings.TrimSpace(req.GetResetToken())))
	tokenHash := hex.EncodeToString(hash[:])
	newHash, err := hashPassword(req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to hash password")
	}
	now := time.Now().UTC()
	var userID string
	errPasswordRecentlyUsed := errors.New("new password was already used recently")
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Raw(`SELECT user_id::text FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>? FOR UPDATE`, tokenHash, now).Scan(&userID).Error; err != nil {
			return err
		}
		if userID == "" {
			return gorm.ErrRecordNotFound
		}
		var history []PasswordEntry
		if err := tx.Where("user_id = ?", userID).Order("created_at DESC").Limit(5).Find(&history).Error; err != nil {
			return err
		}
		for _, entry := range history {
			if bcrypt.CompareHashAndPassword([]byte(entry.PasswordHash), []byte(req.GetNewPassword())) == nil {
				return errPasswordRecentlyUsed
			}
		}
		if err := tx.Model(&Credentials{}).Where("user_id = ?", userID).Updates(map[string]any{"password_hash": newHash, "failed_login_count": 0, "locked_until": nil, "must_change_password": false, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&User{}).Where("id = ?", userID).Update("password_changed_at", now).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO user_password_history (id, user_id, password_hash, created_at) VALUES (?, ?, ?, ?)`, uuid.NewString(), userID, newHash, now).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE password_reset_tokens SET used_at=? WHERE token_hash=?`, now, tokenHash).Error; err != nil {
			return err
		}
		return tx.Exec(`UPDATE user_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.InvalidArgument, "reset token is invalid or expired")
	}
	if errors.Is(err, errPasswordRecentlyUsed) {
		return nil, status.Error(codes.InvalidArgument, errPasswordRecentlyUsed.Error())
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to reset password")
	}
	_ = s.createAudit(ctx, &userID, "PASSWORD_RESET_COMPLETED", "SUCCESS", `{}`)
	return &usersv1.ResetPasswordResponse{}, nil
}

func hashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
