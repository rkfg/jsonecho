package jsonecho

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
			tokenExpiredMessage = "Токен авторизации устарел. Выполните операцию заново вместо обновления этой страницы."
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
	claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
	return strings.ToLower(claims["user"].(string))
}

func (a *Auth) newToken(username string, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": username,
		"exp":  time.Now().Add(expiration).Unix(),
	})
	return token.SignedString(a.Secret)
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
	return JSONOk(c, Result{"token": token})
}

// CurrentRole returns the current user's role
func (a *Auth) CurrentRole(c echo.Context) (result string, err error) {
	user := a.CurrentUser(c)
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

// AddAuth registers authentication handlers with Echo
func (a *Auth) AddAuth(e *echo.Echo) {
	g := e.Group("/auth")
	g.POST("/login", a.login)
	g.GET("/perms", a.permsJSON, middleware.JWT(a.Secret))
}
