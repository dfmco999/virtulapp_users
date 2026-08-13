package main

import (
	"context"
	"encoding/json"
	"errors"
	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"log"
	"time"
)

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
		if u != nil {
			log.Printf("redis cache skipped for user=%s: redis unavailable", u.UserId)
		}
		return
	}
	b, err := json.Marshal(u)
	if err != nil {
		log.Printf("redis cache marshal failed for user=%s: %v", u.UserId, err)
		return
	}
	key := "users:" + u.UserId
	if err := s.redis.Set(ctx, key, b, userCacheTTL).Err(); err != nil {
		log.Printf("redis cache set failed for key=%s: %v", key, err)
		return
	}
	log.Printf("redis cache set ok for key=%s ttl=%s", key, userCacheTTL)
}

func (s *server) getCachedUser(ctx context.Context, id string) (*usersv1.User, bool) {
	if s.redis == nil || id == "" {
		return nil, false
	}
	key := "users:" + id
	val, err := s.redis.Get(ctx, key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			log.Printf("redis cache get failed for key=%s: %v", key, err)
		}
		return nil, false
	}
	var u usersv1.User
	if err := json.Unmarshal([]byte(val), &u); err != nil {
		log.Printf("redis cache unmarshal failed for key=%s: %v", key, err)
		return nil, false
	}
	log.Printf("redis cache hit for key=%s", key)
	return &u, true
}

func (s *server) invalidateUserCache(ctx context.Context, id string) {
	if s.redis == nil || id == "" {
		return
	}
	key := "users:" + id
	if err := s.redis.Del(ctx, key).Err(); err != nil {
		log.Printf("redis cache delete failed for key=%s: %v", key, err)
		return
	}
	log.Printf("redis cache delete ok for key=%s", key)
}
