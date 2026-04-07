package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"time"

	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const userCacheTTL = 5 * time.Minute

type server struct {
	usersv1.UnimplementedUsersServiceServer
	db    *gorm.DB
	redis *redis.Client
}

/*
MODELOS GORM
*/

type User struct {
	ID                string  `gorm:"type:uuid;primaryKey"`
	ExternalID        *string `gorm:"size:100;uniqueIndex"`
	Username          string  `gorm:"size:50;not null;uniqueIndex"`
	Email             string  `gorm:"size:255;not null;uniqueIndex"`
	EmailNormalized   string  `gorm:"size:255;not null;uniqueIndex"`
	Status            string  `gorm:"size:20;not null;default:ACTIVE"`
	IsEmailVerified   bool    `gorm:"not null;default:false"`
	IsPhoneVerified   bool    `gorm:"not null;default:false"`
	LastLoginAt       *time.Time
	PasswordChangedAt *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         gorm.DeletedAt `gorm:"index"`

	Credentials Credentials     `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Profile     UserProfile     `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Preferences UserPreference  `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	Sessions    []UserSession   `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	AuditLogs   []UserAuditLog  `gorm:"foreignKey:UserID"`
	PassHistory []PasswordEntry `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
}

func (User) TableName() string { return "users" }

type Credentials struct {
	UserID             string `gorm:"type:uuid;primaryKey"`
	PasswordHash       string `gorm:"type:text;not null"`
	FailedLoginCount   int32  `gorm:"not null;default:0"`
	LockedUntil        *time.Time
	LastFailedLoginAt  *time.Time
	LastFailedLoginIP  *string `gorm:"type:inet"`
	LastSuccessLoginIP *string `gorm:"type:inet"`
	MustChangePassword bool    `gorm:"not null;default:false"`
	PasswordExpiresAt  *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (Credentials) TableName() string { return "user_credentials" }

type UserProfile struct {
	UserID      string `gorm:"type:uuid;primaryKey"`
	FirstName   *string
	LastName    *string
	FullName    *string
	PhoneNumber *string `gorm:"size:20"`
	AvatarURL   *string
	Locale      string `gorm:"size:10;not null;default:es-CO"`
	Timezone    string `gorm:"size:50;not null;default:America/Bogota"`
	Bio         *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (UserProfile) TableName() string { return "user_profiles" }

type UserPreference struct {
	UserID             string `gorm:"type:uuid;primaryKey"`
	Theme              string `gorm:"size:20;not null;default:system"`
	Language           string `gorm:"size:10;not null;default:es"`
	EmailNotifications bool   `gorm:"not null;default:true"`
	SMSNotifications   bool   `gorm:"not null;default:false"`
	PushNotifications  bool   `gorm:"not null;default:true"`
	MarketingOptIn     bool   `gorm:"not null;default:false"`
	Metadata           string `gorm:"type:jsonb;not null;default:'{}'"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (UserPreference) TableName() string { return "user_preferences" }

type PasswordEntry struct {
	ID           string `gorm:"type:uuid;primaryKey"`
	UserID       string `gorm:"type:uuid;index;not null"`
	PasswordHash string `gorm:"type:text;not null"`
	CreatedAt    time.Time
}

func (PasswordEntry) TableName() string { return "user_password_history" }

type UserAuditLog struct {
	ID          string  `gorm:"type:uuid;primaryKey"`
	UserID      *string `gorm:"type:uuid;index"`
	EventType   string  `gorm:"size:50;not null;index"`
	EventResult string  `gorm:"size:20;not null"`
	IPAddress   *string `gorm:"type:inet"`
	ActorUserID *string `gorm:"type:uuid"`
	Details     string  `gorm:"type:jsonb;not null;default:'{}'"`
	CreatedAt   time.Time
}

func (UserAuditLog) TableName() string { return "user_audit_logs" }

type UserSession struct {
	ID               string `gorm:"type:uuid;primaryKey"`
	UserID           string `gorm:"type:uuid;index;not null"`
	RefreshTokenHash string `gorm:"type:text;not null"`
	DeviceInfo       *string
	IPAddress        *string `gorm:"type:inet"`
	UserAgent        *string
	ExpiresAt        time.Time  `gorm:"not null;index"`
	RevokedAt        *time.Time `gorm:"index"`
	LastUsedAt       *time.Time
	CreatedAt        time.Time
}

func (UserSession) TableName() string { return "user_sessions" }

/*
RPCs
*/

func (s *server) CreateUser(ctx context.Context, req *usersv1.CreateUserRequest) (*usersv1.CreateUserResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}

	emailNormalized := normalizeEmail(req.GetEmail())

	passwordHash, err := hashPassword(req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to hash password")
	}

	userID := uuid.NewString()
	now := time.Now().UTC()

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		u := User{
			ID:              userID,
			ExternalID:      nilIfEmpty(req.GetExternalId()),
			Username:        req.GetUsername(),
			Email:           req.GetEmail(),
			EmailNormalized: emailNormalized,
			Status:          defaultString(req.GetStatus(), "ACTIVE"),
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if err := tx.Create(&u).Error; err != nil {
			return err
		}

		cred := Credentials{
			UserID:             userID,
			PasswordHash:       passwordHash,
			FailedLoginCount:   0,
			MustChangePassword: req.GetMustChangePassword(),
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		if err := tx.Create(&cred).Error; err != nil {
			return err
		}

		profile := UserProfile{
			UserID:      userID,
			FirstName:   nilIfEmpty(req.GetFirstName()),
			LastName:    nilIfEmpty(req.GetLastName()),
			FullName:    buildFullName(req.GetFirstName(), req.GetLastName()),
			PhoneNumber: nilIfEmpty(req.GetPhoneNumber()),
			Locale:      defaultString(req.GetLocale(), "es-CO"),
			Timezone:    defaultString(req.GetTimezone(), "America/Bogota"),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := tx.Create(&profile).Error; err != nil {
			return err
		}

		pref := UserPreference{
			UserID:             userID,
			Theme:              defaultString(req.GetTheme(), "system"),
			Language:           defaultString(req.GetLanguage(), "es"),
			EmailNotifications: true,
			SMSNotifications:   false,
			PushNotifications:  true,
			MarketingOptIn:     false,
			Metadata:           "{}",
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		if err := tx.Create(&pref).Error; err != nil {
			return err
		}

		history := PasswordEntry{
			ID:           uuid.NewString(),
			UserID:       userID,
			PasswordHash: passwordHash,
			CreatedAt:    now,
		}
		if err := tx.Create(&history).Error; err != nil {
			return err
		}

		audit := UserAuditLog{
			ID:          uuid.NewString(),
			UserID:      &userID,
			EventType:   "USER_CREATED",
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
		return nil, mapGormError(err)
	}

	user, err := s.loadUserAggregate(ctx, userID)
	if err != nil {
		return nil, err
	}
	s.cacheUser(ctx, user)

	return &usersv1.CreateUserResponse{User: user}, nil
}

func (s *server) GetUser(ctx context.Context, req *usersv1.GetUserRequest) (*usersv1.GetUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	if u, ok := s.getCachedUser(ctx, req.GetUserId()); ok {
		return &usersv1.GetUserResponse{User: u}, nil
	}

	user, err := s.loadUserAggregate(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}

	s.cacheUser(ctx, user)
	return &usersv1.GetUserResponse{User: user}, nil
}

func (s *server) ListUsers(ctx context.Context, req *usersv1.ListUsersRequest) (*usersv1.ListUsersResponse, error) {
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	var users []User
	err := s.db.WithContext(ctx).
		Preload("Profile").
		Preload("Preferences").
		Preload("Credentials").
		Order("created_at DESC").
		Limit(limit).
		Offset(int(req.GetOffset())).
		Find(&users).Error
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	out := make([]*usersv1.User, 0, len(users))
	for _, u := range users {
		out = append(out, toProtoUser(&u))
	}

	return &usersv1.ListUsersResponse{Users: out}, nil
}

func (s *server) UpdateUser(ctx context.Context, req *usersv1.UpdateUserRequest) (*usersv1.UpdateUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.First(&u, "id = ?", req.GetUserId()).Error; err != nil {
			return err
		}

		u.Email = req.GetEmail()
		u.EmailNormalized = normalizeEmail(req.GetEmail())
		u.Username = req.GetUsername()
		u.Status = defaultString(req.GetStatus(), u.Status)
		u.ExternalID = nilIfEmpty(req.GetExternalId())

		if err := tx.Save(&u).Error; err != nil {
			return err
		}

		var p UserProfile
		if err := tx.First(&p, "user_id = ?", req.GetUserId()).Error; err != nil {
			return err
		}
		p.FirstName = nilIfEmpty(req.GetFirstName())
		p.LastName = nilIfEmpty(req.GetLastName())
		p.FullName = buildFullName(req.GetFirstName(), req.GetLastName())
		p.PhoneNumber = nilIfEmpty(req.GetPhoneNumber())
		p.Locale = defaultString(req.GetLocale(), p.Locale)
		p.Timezone = defaultString(req.GetTimezone(), p.Timezone)

		if err := tx.Save(&p).Error; err != nil {
			return err
		}

		var pref UserPreference
		if err := tx.First(&pref, "user_id = ?", req.GetUserId()).Error; err == nil {
			if req.GetTheme() != "" {
				pref.Theme = req.GetTheme()
			}
			if req.GetLanguage() != "" {
				pref.Language = req.GetLanguage()
			}
			if err := tx.Save(&pref).Error; err != nil {
				return err
			}
		}

		audit := UserAuditLog{
			ID:          uuid.NewString(),
			UserID:      ptr(req.GetUserId()),
			EventType:   "USER_UPDATED",
			EventResult: "SUCCESS",
			Details:     `{"source":"grpc"}`,
			CreatedAt:   time.Now().UTC(),
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
		return nil, mapGormError(err)
	}

	s.invalidateUserCache(ctx, req.GetUserId())
	user, err := s.loadUserAggregate(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	s.cacheUser(ctx, user)

	return &usersv1.UpdateUserResponse{User: user}, nil
}

func (s *server) DeleteUser(ctx context.Context, req *usersv1.DeleteUserRequest) (*usersv1.DeleteUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}

	now := time.Now().UTC()

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.First(&u, "id = ?", req.GetUserId()).Error; err != nil {
			return err
		}

		u.Status = "DELETED"
		if err := tx.Save(&u).Error; err != nil {
			return err
		}

		if err := tx.Delete(&u).Error; err != nil {
			return err
		}

		lockUntil := now.AddDate(100, 0, 0)
		if err := tx.Model(&Credentials{}).
			Where("user_id = ?", req.GetUserId()).
			Updates(map[string]any{
				"locked_until": lockUntil,
			}).Error; err != nil {
			return err
		}

		if err := tx.Model(&UserSession{}).
			Where("user_id = ? AND revoked_at IS NULL", req.GetUserId()).
			Update("revoked_at", now).Error; err != nil {
			return err
		}

		audit := UserAuditLog{
			ID:          uuid.NewString(),
			UserID:      ptr(req.GetUserId()),
			EventType:   "USER_DELETED",
			EventResult: "SUCCESS",
			Details:     `{"source":"grpc","type":"soft_delete"}`,
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
	return &usersv1.DeleteUserResponse{}, nil
}

/*
LOGIN
Asume que existe LoginRequest y LoginResponse en tu proto.
*/

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
		Preload("Credentials").
		Preload("Profile").
		Preload("Preferences").
		First(&user, "email_normalized = ?", emailNormalized).Error
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	if user.Status == "DELETED" || user.Status == "SUSPENDED" || user.Status == "INACTIVE" {
		_ = s.createAudit(ctx, &user.ID, "LOGIN_DENIED", "DENY", `{"reason":"status_blocked"}`)
		return nil, status.Error(codes.PermissionDenied, "account unavailable")
	}

	if user.Credentials.LockedUntil != nil && user.Credentials.LockedUntil.After(now) {
		_ = s.createAudit(ctx, &user.ID, "LOGIN_DENIED", "DENY", `{"reason":"locked"}`)
		return nil, status.Error(codes.PermissionDenied, "account locked")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Credentials.PasswordHash), []byte(req.GetPassword())); err != nil {
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

		var cred Credentials
		if err2 := s.db.WithContext(ctx).First(&cred, "user_id = ?", user.ID).Error; err2 == nil {
			if cred.FailedLoginCount >= 4 {
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

	refreshHash, err := hashPassword(uuid.NewString())
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to generate session")
	}

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
			ID:               uuid.NewString(),
			UserID:           user.ID,
			RefreshTokenHash: refreshHash,
			IPAddress:        nilIfEmpty(req.GetIpAddress()),
			UserAgent:        nilIfEmpty(req.GetUserAgent()),
			ExpiresAt:        now.Add(24 * time.Hour * 30),
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
		User: updated,
		// Aquí normalmente devolverías access_token y refresh_token reales,
		// emitidos por tu capa de auth/JWT.
		MustChangePassword: user.Credentials.MustChangePassword,
	}, nil
}

/*
CHANGE PASSWORD
Asume que existe ChangePasswordRequest y ChangePasswordResponse.
*/

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
		Preload("Credentials").
		First(&user, "id = ?", req.GetUserId()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Credentials.PasswordHash), []byte(req.GetCurrentPassword())); err != nil {
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

/*
HELPERS
*/

func (s *server) loadUserAggregate(ctx context.Context, userID string) (*usersv1.User, error) {
	var u User
	err := s.db.WithContext(ctx).
		Preload("Credentials").
		Preload("Profile").
		Preload("Preferences").
		First(&u, "id = ?", userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return toProtoUser(&u), nil
}

func toProtoUser(u *User) *usersv1.User {
	out := &usersv1.User{
		UserId:             u.ID,
		ExternalId:         valueOrEmpty(u.ExternalID),
		Username:           u.Username,
		Email:              u.Email,
		Status:             u.Status,
		IsEmailVerified:    u.IsEmailVerified,
		IsPhoneVerified:    u.IsPhoneVerified,
		MustChangePassword: u.Credentials.MustChangePassword,
		CreatedAt:          timestamppb.New(u.CreatedAt),
		UpdatedAt:          timestamppb.New(u.UpdatedAt),
	}

	out.FirstName = valueOrEmpty(u.Profile.FirstName)
	out.LastName = valueOrEmpty(u.Profile.LastName)
	out.PhoneNumber = valueOrEmpty(u.Profile.PhoneNumber)
	out.Locale = u.Profile.Locale
	out.Timezone = u.Profile.Timezone

	out.Language = u.Preferences.Language
	out.Theme = u.Preferences.Theme
	out.EmailNotifications = u.Preferences.EmailNotifications
	out.SmsNotifications = u.Preferences.SMSNotifications
	out.PushNotifications = u.Preferences.PushNotifications
	out.MarketingOptIn = u.Preferences.MarketingOptIn

	if u.LastLoginAt != nil {
		out.LastLoginAt = timestamppb.New(*u.LastLoginAt)
	}
	if u.PasswordChangedAt != nil {
		out.PasswordChangedAt = timestamppb.New(*u.PasswordChangedAt)
	}

	return out
}

func (s *server) cacheUser(ctx context.Context, u *usersv1.User) {
	if s.redis == nil || u == nil {
		return
	}
	b, err := json.Marshal(u)
	if err != nil {
		return
	}
	_ = s.redis.Set(ctx, "users:"+u.UserId, b, userCacheTTL).Err()
}

func (s *server) getCachedUser(ctx context.Context, id string) (*usersv1.User, bool) {
	if s.redis == nil || id == "" {
		return nil, false
	}
	val, err := s.redis.Get(ctx, "users:"+id).Result()
	if err != nil {
		return nil, false
	}
	var u usersv1.User
	if err := json.Unmarshal([]byte(val), &u); err != nil {
		return nil, false
	}
	return &u, true
}

func (s *server) invalidateUserCache(ctx context.Context, id string) {
	if s.redis == nil || id == "" {
		return
	}
	_ = s.redis.Del(ctx, "users:"+id).Err()
}

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

func hashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
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

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("gorm open: %v", err)
	}

	/*	if err := db.AutoMigrate(
			&User{},
			&Credentials{},
			&UserProfile{},
			&UserPreference{},
			&PasswordEntry{},
			&UserAuditLog{},
			&UserSession{},
		); err != nil {
			log.Fatalf("automigrate: %v", err)
		}
	*/
	rdb := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_ADDR"),
	})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	usersv1.RegisterUsersServiceServer(srv, &server{
		db:    db,
		redis: rdb,
	})

	log.Println("running users service on :50051")
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("grpc serve: %v", err)
	}
}
