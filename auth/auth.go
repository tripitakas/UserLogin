package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var secretKey = []byte("your-very-secure-secret") // 用于签名的密钥，建议存储在环境变量中

// User 用户结构体
type User struct {
	Username string
	Password string // 密码存储在哈希中
	Role     string // 用户角色：如admin、user等
}

// 模拟用户数据（通常会从数据库获取）
var users = map[string]User{
	"admin": {
		Username: "admin",
		Password: hashPassword("admin123"),
		Role:     "admin",
	},
	"user1": {
		Username: "user1",
		Password: hashPassword("user123"),
		Role:     "user",
	},
}

// Claims JWT结构体
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.StandardClaims
}

// 密码 加密哈希
func hashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// 创建JWT令牌
func createJWT(username, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // 设置令牌过期时间为24小时

	claims := &Claims{
		Username: username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "go-secure-login",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// 解析JWT令牌
func parseJWT(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// 用户认证（用户名和密码验证）
func authenticate(username, password string) (*User, error) {
	user, exists := users[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	// 校验密码
	if user.Password != hashPassword(password) {
		return nil, errors.New("incorrect password")
	}
	return &user, nil
}

// 权限检查
func checkRole(claims *Claims, requiredRole string) bool {
	return claims.Role == requiredRole
}
