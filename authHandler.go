package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// 登录请求处理
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// 认证用户
	user, err := authenticate(username, password)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 创建JWT令牌
	token, err := createJWT(user.Username, user.Role)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 返回令牌
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"token":"%s"}`, token)))
}

// 受保护的资源处理
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// 获取请求中的Authorization头部
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Authorization header missing or incorrect", http.StatusUnauthorized)
		return
	}
	tokenString := authHeader[len("Bearer "):]

	// 解析JWT令牌
	claims, err := parseJWT(tokenString)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 权限验证（检查角色）
	if !checkRole(claims, "admin") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 返回受保护的资源
	w.Write([]byte("This is a protected resource, only accessible by admin"))
}
