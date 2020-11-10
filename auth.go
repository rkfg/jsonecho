package jsonecho

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/crypto/bcrypt"
)

// NewJWTCasbinMiddleware provides a combined middleware of JWTWithConfig with a provided secret and a default casbin enforcer
func (a *Auth) NewJWTCasbinMiddleware(useQueryToken bool, tokenExpiredMessage string) echo.MiddlewareFunc {
	jwtHeaderConfig := middleware.DefaultJWTConfig
	jwtHeaderConfig.SigningKey = a.secret
	if useQueryToken {
		jwtHeaderConfig.Skipper = func(c echo.Context) bool {
			return c.QueryParam("token") != ""
		}
	}
	if useQueryToken {
		jwtQueryConfig := middleware.DefaultJWTConfig
		jwtQueryConfig.TokenLookup = "query:token"
		jwtQueryConfig.SigningKey = a.secret
		if tokenExpiredMessage == "" {
			tokenExpiredMessage = "Токен авторизации устарел. Выполните операцию заново вместо обновления этой страницы."
		}
		jwtQueryConfig.ErrorHandlerWithContext = func(e error, c echo.Context) error {
			return c.HTML(401, tokenExpiredMessage)
		}
		jwtQueryConfig.Skipper = func(c echo.Context) bool {
			return c.QueryParam("token") == ""
		}
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return middleware.JWTWithConfig(jwtQueryConfig)(middleware.JWTWithConfig(jwtHeaderConfig)(a.Enforce(next)))
		}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return middleware.JWTWithConfig(jwtHeaderConfig)(a.Enforce(next))
	}
}

func (a *Auth) currentUser(c echo.Context) string {
	claims := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
	return claims["user"].(string)
}

func (a *Auth) newToken(username string, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": username,
		"exp":  time.Now().Add(expiration).Unix(),
	})
	return token.SignedString(a.secret)
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
		return userNotFoundError
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

func (a *Auth) perms(c echo.Context) (*Permissions, error) {
	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	name := strings.ToLower(claims["user"].(string))
	var u User
	if a.db.First(&u, "name = ?", name).RecordNotFound() {
		return nil, userNotFoundError
	}
	var result Permissions
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
	result, err := a.perms(c)
	if err != nil {
		return err
	}
	return JSONOk(c, &result)
}

// AddAuth registers authentication handlers with Echo
func (a *Auth) AddAuth(e *echo.Echo) {
	g := e.Group("/auth")
	g.POST("/login", a.login)
	g.GET("/perms", a.permsJSON, middleware.JWT(a.secret))
}
