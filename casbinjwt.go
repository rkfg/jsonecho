package jsonecho

import (
	"fmt"
	"net/http"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	gormadapter "github.com/casbin/gorm-adapter/v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo/v4"
)

var userNotFoundError = echo.NewHTTPError(http.StatusNotFound, "Пользователь не существует")

// User is a user with access rights
type User struct {
	JEBase
	Name     string `json:"name"`
	Role     string `json:"role" gorm:"-"`
	Password string `json:"password,omitempty"`
}

// Permissions describes the editing ability of the user and their roles
type Permissions struct {
	Edit bool   `json:"edit"`
	Role string `json:"role"`
}

// Auth is a struct holding the casbin enforcer for the middleware
type Auth struct {
	Enforcer      *casbin.Enforcer
	TokenDuration time.Duration
	secret        []byte
	db            *gorm.DB
}

type combinedAdapter struct {
	persist.Adapter
	fa *fileadapter.Adapter
}

func (c *combinedAdapter) LoadPolicy(model model.Model) error {
	if err := c.fa.LoadPolicy(model); err != nil {
		return err
	}
	return c.Adapter.LoadPolicy(model)
}

func (a *Auth) newCombinedAdapter(policyPath string) (persist.Adapter, error) {
	var result combinedAdapter
	var err error
	result.Adapter, err = gormadapter.NewAdapterByDB(a.db)
	if err != nil {
		return nil, err
	}
	result.fa = fileadapter.NewAdapter(policyPath)
	return &result, nil
}

// NewAuth initializes a new authentication object
func NewAuth(secret []byte, tokenDuration time.Duration, db *gorm.DB) *Auth {
	if tokenDuration == 0 {
		tokenDuration = 24 * time.Hour * 365
	}
	result := &Auth{TokenDuration: tokenDuration, secret: secret, db: db}
	adapter, err := result.newCombinedAdapter("casbin_auth_policy.csv")
	if err != nil {
		panic(fmt.Errorf("error creating casbin adapter: %s", err))
	}
	enforcer, err := casbin.NewEnforcer("casbin_auth_model.conf", adapter)
	if err != nil {
		panic(fmt.Errorf("error creating casbin enforcer: %s", err))
	}
	result.Enforcer = enforcer
	return result
}

// Enforce is the casbin enforcer middleware
func (a *Auth) Enforce(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Get("user").(*jwt.Token)
		claims := token.Claims.(jwt.MapClaims)
		user := claims["user"]

		method := c.Request().Method
		path := c.Request().URL.Path

		result, err := a.Enforcer.Enforce(user, path, method)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}

		if result {
			return next(c)
		}

		return echo.ErrForbidden
	}
}
