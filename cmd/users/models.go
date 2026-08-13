package main

import (
	"errors"
	usersv1 "github.com/dfmco999/virtulapp_project/gen/users/v1"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"time"
)

const (
	userCacheTTL  = 5 * time.Minute
	webSessionTTL = 15 * time.Minute
)

var errSessionInactive = errors.New("session inactive or expired")

type server struct {
	usersv1.UnimplementedUsersServiceServer
	db    *gorm.DB
	redis *redis.Client
}

type User struct {
	ID                string         `gorm:"column:id;type:uuid;primaryKey"`
	ExternalID        *string        `gorm:"column:external_id"`
	Username          string         `gorm:"column:username;size:50;not null"`
	Email             string         `gorm:"column:email;size:255;not null"`
	EmailNormalized   string         `gorm:"column:email_normalized;size:255;not null"`
	TenantID          string         `gorm:"column:tenant_id;type:uuid;not null;index"`
	Role              string         `gorm:"column:role;size:30;not null;default:OPERATIVO;index"`
	Status            string         `gorm:"column:status;size:20;not null;default:ACTIVE"`
	IsEmailVerified   bool           `gorm:"column:is_email_verified;not null;default:false"`
	IsPhoneVerified   bool           `gorm:"column:is_phone_verified;not null;default:false"`
	LastLoginAt       *time.Time     `gorm:"column:last_login_at"`
	PasswordChangedAt *time.Time     `gorm:"column:password_changed_at"`
	CreatedAt         time.Time      `gorm:"column:created_at"`
	UpdatedAt         time.Time      `gorm:"column:updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"column:deleted_at;index"`

	Credentials Credentials     `gorm:"foreignKey:UserID;references:ID"`
	Profile     UserProfile     `gorm:"foreignKey:UserID;references:ID"`
	Preferences UserPreference  `gorm:"foreignKey:UserID;references:ID"`
	Sessions    []UserSession   `gorm:"foreignKey:UserID;references:ID"`
	AuditLogs   []UserAuditLog  `gorm:"foreignKey:UserID;references:ID"`
	PassHistory []PasswordEntry `gorm:"foreignKey:UserID;references:ID"`
}

type Credentials struct {
	UserID             string     `gorm:"column:user_id;type:uuid;primaryKey"`
	PasswordHash       string     `gorm:"column:password_hash;type:text;not null"`
	FailedLoginCount   int32      `gorm:"column:failed_login_count;not null;default:0"`
	LockedUntil        *time.Time `gorm:"column:locked_until"`
	LastFailedLoginAt  *time.Time `gorm:"column:last_failed_login_at"`
	LastFailedLoginIP  *string    `gorm:"column:last_failed_login_ip;type:inet"`
	LastSuccessLoginIP *string    `gorm:"column:last_success_login_ip;type:inet"`
	MustChangePassword bool       `gorm:"column:must_change_password;not null;default:false"`
	PasswordExpiresAt  *time.Time `gorm:"column:password_expires_at"`
	CreatedAt          time.Time  `gorm:"column:created_at"`
	UpdatedAt          time.Time  `gorm:"column:updated_at"`
}

type UserProfile struct {
	UserID      string    `gorm:"column:user_id;type:uuid;primaryKey"`
	FirstName   *string   `gorm:"column:first_name"`
	LastName    *string   `gorm:"column:last_name"`
	FullName    *string   `gorm:"column:full_name"`
	PhoneNumber *string   `gorm:"column:phone_number;size:20"`
	AvatarURL   *string   `gorm:"column:avatar_url"`
	Locale      string    `gorm:"column:locale;size:10;not null;default:es-CO"`
	Timezone    string    `gorm:"column:timezone;size:50;not null;default:America/Bogota"`
	Bio         *string   `gorm:"column:bio"`
	CreatedAt   time.Time `gorm:"column:created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at"`
}

type UserPreference struct {
	UserID             string    `gorm:"column:user_id;type:uuid;primaryKey"`
	Theme              string    `gorm:"column:theme;size:20;not null;default:system"`
	Language           string    `gorm:"column:language;size:10;not null;default:es"`
	EmailNotifications bool      `gorm:"column:email_notifications;not null;default:true"`
	SMSNotifications   bool      `gorm:"column:sms_notifications;not null;default:false"`
	PushNotifications  bool      `gorm:"column:push_notifications;not null;default:true"`
	MarketingOptIn     bool      `gorm:"column:marketing_opt_in;not null;default:false"`
	Metadata           string    `gorm:"column:metadata;type:jsonb;not null;default:'{}'"`
	CreatedAt          time.Time `gorm:"column:created_at"`
	UpdatedAt          time.Time `gorm:"column:updated_at"`
}

type PasswordEntry struct {
	ID           string    `gorm:"column:id;type:uuid;primaryKey"`
	UserID       string    `gorm:"column:user_id;type:uuid;index;not null"`
	PasswordHash string    `gorm:"column:password_hash;type:text;not null"`
	CreatedAt    time.Time `gorm:"column:created_at"`
}

type UserAuditLog struct {
	ID          string    `gorm:"column:id;type:uuid;primaryKey"`
	UserID      *string   `gorm:"column:user_id;type:uuid;index"`
	EventType   string    `gorm:"column:event_type;size:50;not null;index"`
	EventResult string    `gorm:"column:event_result;size:20;not null"`
	IPAddress   *string   `gorm:"column:ip_address;type:inet"`
	ActorUserID *string   `gorm:"column:actor_user_id;type:uuid"`
	Details     string    `gorm:"column:details;type:jsonb;not null;default:'{}'"`
	CreatedAt   time.Time `gorm:"column:created_at"`
}

type UserSession struct {
	ID               string     `gorm:"column:id;type:uuid;primaryKey"`
	UserID           string     `gorm:"column:user_id;type:uuid;index;not null"`
	RefreshTokenHash string     `gorm:"column:refresh_token_hash;type:text;not null"`
	DeviceInfo       *string    `gorm:"column:device_info"`
	IPAddress        *string    `gorm:"column:ip_address;type:inet"`
	UserAgent        *string    `gorm:"column:user_agent"`
	ExpiresAt        time.Time  `gorm:"column:expires_at;not null;index"`
	RevokedAt        *time.Time `gorm:"column:revoked_at;index"`
	LastUsedAt       *time.Time `gorm:"column:last_used_at"`
	CreatedAt        time.Time  `gorm:"column:created_at"`
}
