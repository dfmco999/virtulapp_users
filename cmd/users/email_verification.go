package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

func (s *server) RequestEmailVerification(ctx context.Context, req *usersv1.RequestEmailVerificationRequest) (*usersv1.RequestEmailVerificationResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	var user User
	if userID == "" || s.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", userID).First(&user).Error != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if user.IsEmailVerified {
		return &usersv1.RequestEmailVerificationResponse{UserId: user.ID, TenantId: user.TenantID, Email: user.Email}, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, status.Error(codes.Internal, "unable to generate verification token")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE email_verification_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL`, now, user.ID).Error; err != nil {
			return err
		}
		return tx.Exec(`INSERT INTO email_verification_tokens (id,user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?,?)`, uuid.NewString(), user.ID, hex.EncodeToString(sum[:]), now.Add(24*time.Hour), now).Error
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to store verification token")
	}
	return &usersv1.RequestEmailVerificationResponse{VerificationToken: token, UserId: user.ID, TenantId: user.TenantID, Email: user.Email}, nil
}

func (s *server) ConfirmEmailVerification(ctx context.Context, req *usersv1.ConfirmEmailVerificationRequest) (*usersv1.ConfirmEmailVerificationResponse, error) {
	sum := sha256.Sum256([]byte(strings.TrimSpace(req.GetVerificationToken())))
	tokenHash := hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	var userID string
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Raw(`SELECT user_id::text FROM email_verification_tokens WHERE token_hash=? AND used_at IS NULL AND expires_at>? FOR UPDATE`, tokenHash, now).Scan(&userID).Error; err != nil {
			return err
		}
		if userID == "" {
			return gorm.ErrRecordNotFound
		}
		if err := tx.Model(&User{}).Where("id = ?", userID).Updates(map[string]any{"is_email_verified": true, "updated_at": now}).Error; err != nil {
			return err
		}
		return tx.Exec(`UPDATE email_verification_tokens SET used_at=? WHERE token_hash=?`, now, tokenHash).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Error(codes.InvalidArgument, "verification token is invalid or expired")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to verify email")
	}
	s.invalidateUserCache(ctx, userID)
	return &usersv1.ConfirmEmailVerificationResponse{Verified: true}, nil
}
