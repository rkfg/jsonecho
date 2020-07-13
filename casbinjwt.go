package jsonecho

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

// Enforcer is a struct holding the casbin enforcer for the middleware
type Enforcer struct {
	Enforcer *casbin.Enforcer
}

// Enforce is the casbin enforcer middleware
func (e *Enforcer) Enforce(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		claims := token.Claims.(jwt.MapClaims)
		user := claims["user"]

		method := c.Request().Method
		path := c.Request().URL.Path

		result, err := e.Enforcer.Enforce(user, path, method)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		if result {
			return next(c)
		}

		return echo.ErrForbidden
	}
}
