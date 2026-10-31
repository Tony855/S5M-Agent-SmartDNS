package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const userKey ctxKey = "user"

func (a *App) signToken(u *User) (string, error) {
	claims := jwt.MapClaims{
		"sub":  u.ID,
		"usr":  u.Username,
		"role": u.Role,
		"exp":  time.Now().Add(12 * time.Hour).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtKey)
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}

		t, err := jwt.Parse(strings.TrimPrefix(h, "Bearer "), func(t *jwt.Token) (any, error) {
			return a.jwtKey, nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if err != nil || t == nil || !t.Valid {
			writeErr(w, http.StatusUnauthorized, "登录已失效，请重新登录")
			return
		}

		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "登录凭证无效")
			return
		}

		username, ok := claims["usr"].(string)
		if !ok || strings.TrimSpace(username) == "" {
			writeErr(w, http.StatusUnauthorized, "登录凭证缺少用户信息")
			return
		}

		// 每次请求都读取数据库中的当前账号状态和角色。
		u, err := a.store.UserByUsername(username)
		if err != nil || u == nil || !u.Enabled {
			writeErr(w, http.StatusUnauthorized, "账号不存在或已禁用，请重新登录")
			return
		}

		ctx := context.WithValue(r.Context(), userKey, u)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin must wrap a handler already protected by auth. It checks the
// current database role instead of trusting the role claim in a JWT.
func (a *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		if u.Role != "admin" {
			writeErr(w, http.StatusForbidden, "需要管理员权限")
			return
		}
		next(w, r)
	}
}

func currentUser(r *http.Request) *User {
	if u, ok := r.Context().Value(userKey).(*User); ok {
		return u
	}
	return nil
}
