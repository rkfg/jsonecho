package jsonecho

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/random"
	"golang.org/x/crypto/bcrypt"
)

// NewJWTCasbinMiddleware provides a combined middleware of JWTWithConfig with a provided secret and a default casbin enforcer
func (a *Auth) NewJWTCasbinMiddleware(useFormToken bool, tokenExpiredMessage string) echo.MiddlewareFunc {
	jwtHeaderConfig := middleware.DefaultJWTConfig
	jwtHeaderConfig.SigningKey = a.Secret
	if useFormToken {
		jwtHeaderConfig.Skipper = func(c echo.Context) bool {
			return c.FormValue("token") != ""
		}
	}
	if useFormToken {
		jwtFormConfig := middleware.DefaultJWTConfig
		jwtFormConfig.TokenLookup = "form:token"
		jwtFormConfig.SigningKey = a.Secret
		if tokenExpiredMessage == "" {
			tokenExpiredMessage = "Токен авторизации устарел. Попробуйте ещё раз."
		}
		jwtFormConfig.ErrorHandlerWithContext = func(e error, c echo.Context) error {
			return c.HTML(401, tokenExpiredMessage)
		}
		jwtFormConfig.Skipper = func(c echo.Context) bool {
			return c.FormValue("token") == ""
		}
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return middleware.JWTWithConfig(jwtFormConfig)(middleware.JWTWithConfig(jwtHeaderConfig)(a.Enforce(next)))
		}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return middleware.JWTWithConfig(jwtHeaderConfig)(a.Enforce(next))
	}
}

// CurrentUser returns the name of the user currently logged in
func (a *Auth) CurrentUser(c echo.Context) string {
	if user, ok := c.Get("user").(*jwt.Token); ok {
		claims := user.Claims.(jwt.MapClaims)
		return strings.ToLower(claims["user"].(string))
	}
	return ""
}

func (a *Auth) newToken(username string, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": username,
		"exp":  time.Now().Add(expiration).Unix(),
	})
	return token.SignedString(a.Secret)
}

func (a *Auth) refreshCookieName() string {
	return "refresh_token_" + a.AppName
}

func (a *Auth) login(c echo.Context) error {
	var login struct {
		Name     string
		Password string
	}
	c.Bind(&login)
	login.Name = strings.ToLower(login.Name)
	var ex User
	if a.db.Find(&ex, "name = ?", login.Name).RecordNotFound() {
		return UserNotFoundError
	}
	if err := bcrypt.CompareHashAndPassword([]byte(ex.Password), []byte(login.Password)); err != nil {
		return JSONErrorMessage(c, http.StatusUnauthorized, "Неверный пароль")
	}
	token, err := a.newToken(login.Name, a.TokenDuration)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, err)
	}
	refreshToken := RefreshToken{Username: login.Name, Token: random.String(32, random.Alphanumeric), LastUsed: time.Now()}
	a.db.Save(&refreshToken)
	c.SetCookie(&http.Cookie{Name: a.refreshCookieName(),
		Value: refreshToken.Token, Expires: time.Now().Add(time.Hour * 24 * 30),
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return JSONOk(c, Result{"token": token})
}

// RoleForUser returns the user's role
func (a *Auth) RoleForUser(user string) (result string, err error) {
	var roles []string
	roles, err = a.Enforcer.GetRolesForUser(user)
	if err != nil {
		return
	}
	if len(roles) == 0 {
		return "", fmt.Errorf("не найдены роли пользователя %s", user)
	}
	result = strings.TrimPrefix(roles[0], "role:")
	return
}

// CurrentRole returns the current user's role
func (a *Auth) CurrentRole(c echo.Context) (result string, err error) {
	return a.RoleForUser(a.CurrentUser(c))
}

// Perms returns the basic permissions data for the current user
func (a *Auth) Perms(c echo.Context) (*Permissions, error) {
	name := a.CurrentUser(c)
	var u User
	if a.db.First(&u, "name = ?", name).RecordNotFound() {
		return nil, UserNotFoundError
	}
	var result Permissions
	result.Resources = make(map[string]Access)
	var err error
	result.Edit, err = a.Enforcer.Enforce(name, "/api/recs", "POST")
	if err != nil {
		return nil, err
	}
	roles, err := a.Enforcer.GetRolesForUser(name)
	if err != nil {
		return nil, err
	}
	if len(roles) > 0 {
		result.Role = strings.TrimPrefix(roles[0], "role:")
	}
	return &result, nil
}

func (a *Auth) permsJSON(c echo.Context) error {
	result, err := a.Perms(c)
	if err != nil {
		return err
	}
	return JSONOk(c, &result)
}

func (a *Auth) refreshToken(c echo.Context) error {
	a.db.Delete(&RefreshToken{}, "last_used < ?", time.Now().Add(-time.Hour*24*30))
	log.Printf("Refreshing token...")
	cookie, err := c.Cookie(a.refreshCookieName())
	if err != nil {
		log.Printf("Error getting cookie: %s", err)
		return JSONError(c, 400, err)
	}
	if cookie == nil || cookie.Value == "" {
		log.Printf("No cookie found!")
		return JSONErrorMessage(c, 400, "no refresh_token cookie")
	}
	var ref RefreshToken
	if a.db.First(&ref, "token = ?", cookie.Value).RecordNotFound() {
		log.Printf("Token %s not found in database", cookie.Value)
		return JSONErrorMessage(c, 403, "token not found")
	}
	ref.LastUsed = time.Now()
	a.db.Save(&ref)
	token, err := a.newToken(ref.Username, a.TokenDuration)
	if err != nil {
		log.Printf("Can't reissue token %s for user %s: %s", cookie.Value, ref.Username, err)
		return JSONError(c, 500, err)
	}
	log.Printf("Token reissued for user %s", ref.Username)
	return JSONOk(c, Result{"token": token})
}

func (a *Auth) logout(c echo.Context) error {
	log.Printf("Logging out user %s", a.CurrentUser(c))
	cookie, err := c.Cookie(a.refreshCookieName())
	if err != nil {
		log.Printf("Error getting cookie: %s", err)
		return JSONError(c, 400, err)
	}
	if cookie == nil || cookie.Value == "" {
		log.Printf("No cookie found!")
		return JSONErrorMessage(c, 400, "no refresh_token cookie")
	}
	a.db.Delete(&RefreshToken{}, "token = ?", cookie.Value)
	c.SetCookie(&http.Cookie{Name: a.refreshCookieName(), Expires: time.Unix(0, 0)})
	return JSONOk(c, Result{"message": "ok"})
}

// AddAuth registers authentication handlers with Echo
func (a *Auth) AddAuth(e *echo.Echo) {
	g := e.Group("/auth")
	g.POST("/login", a.login)
	g.POST("/refresh", a.refreshToken)
	g.POST("/logout", a.logout)
	g.GET("/perms", a.permsJSON, middleware.JWT(a.Secret))
}
