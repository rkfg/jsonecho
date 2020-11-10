package jsonecho

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func crudListUsers(c echo.Context, model *gorm.DB) ([]User, error) {
	var result []User
	var params struct {
		Filter map[string]string
		Rng    []int
		Sort   []string
	}
	DecodeParam(c, "range", &params.Rng)
	DecodeParam(c, "sort", &params.Sort)

	chain := model
	if len(params.Sort) == 2 {
		chain = chain.Order(params.Sort[0]+" "+params.Sort[1], true)
	}
	ids := GetFilterIds(c)
	if len(ids) > 0 {
		chain = chain.Where("id in (?)", ids)
	}
	var relatedIds map[string]interface{}
	if err := DecodeParam(c, "filter", &relatedIds); err != nil {
		fmt.Println("Error decoding User filter:", err)
		return nil, err
	}
	for k, v := range relatedIds {
		if k == "name" {
			chain = chain.Where("name LIKE ?", v.(string)+"%")
		}
		if k == "role" {
			chain = chain.Where("v1 = ?", "role:"+v.(string))
		}
	}
	var cnt int
	chain.Count(&cnt)
	if len(params.Rng) == 2 {
		chain = chain.Offset(params.Rng[0]).Limit(params.Rng[1] - params.Rng[0] + 1)
		c.Response().Header().Add("Content-Range", fmt.Sprintf("elems %d-%d/%d", params.Rng[0], params.Rng[1], cnt))
	}
	chain.Find(&result)
	for idx := range result {
		result[idx].Postprocess()
	}
	return result, nil
}

func crudDelUser(c echo.Context, db *gorm.DB) (*User, error) {
	var result User
	t := db.Model(User{})
	if t.Where("id = ?", c.Param("id")).First(&result).RecordNotFound() {
		return nil, NotFound(c)
	}
	if err := t.Delete(&result).Error; err != nil {
		return nil, err
	}
	return &result, nil
}

func crudPutUser(c echo.Context, db *gorm.DB, item *User) (*User, error) {
	var existing User
	db.First(&existing, "id = ?", c.Param("id"))
	item.ID = existing.ID
	item.Preprocess()
	db = db.Save(item)
	if err := db.Error; err != nil {
		return nil, err
	}
	return item, nil
}

func crudPostUser(c echo.Context, db *gorm.DB, item *User) (*User, error) {
	item.ID = 0
	item.Preprocess()
	if err := db.Create(item).Error; err != nil {
		return nil, err
	}
	return item, nil
}

func crudGetUser(c echo.Context, db *gorm.DB) (*User, error) {
	var item User
	db.First(&item, "id = ?", c.Param("id"))
	item.Postprocess()
	return &item, nil
}

func (a *Auth) listUsers(c echo.Context) error {
	model := a.db.Model(&User{}).Joins("LEFT JOIN casbin_rule ON v0 = users.name").Select("id, name, v1 as role")
	result, err := crudListUsers(c, model)
	return ItemResp(c, &result, err)
}

func (a *Auth) getUser(c echo.Context) error {
	model := a.db.Model(&User{}).Joins("LEFT JOIN casbin_rule ON v0 = users.name").Select("id, name, v1 as role")
	result, err := crudGetUser(c, model)
	return ItemResp(c, result, err)
}

// Preprocess hashes the password before creating/updating the user
func (u *User) Preprocess() error {
	if u.Password != "" {
		pwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
		if err != nil {
			return err
		}
		u.Password = string(pwd)
	}
	return nil
}

// Postprocess removes the password and trims the role prefix before returning the user struct
func (u *User) Postprocess() error {
	u.Password = ""
	u.Role = strings.TrimPrefix(u.Role, "role:")
	return nil
}

func (a *Auth) prepareUser(c echo.Context, u *User, db *gorm.DB, create bool) (*gorm.DB, error) {
	if err := BindJSON(c, &u); err != nil {
		return nil, err
	}
	if u.Password == "" {
		if create {
			return nil, errors.New("требуется пароль для нового пользователя")
		}
		db = db.Omit("password")
	}
	var oldUser User
	db.Find(&oldUser, "id = ?", u.ID)
	if oldUser.Name != "" {
		a.Enforcer.DeleteRolesForUser(oldUser.Name)
	}
	a.Enforcer.AddRoleForUser(u.Name, "role:"+u.Role)
	return db, nil
}

func (a *Auth) putUser(c echo.Context) error {
	var (
		u   User
		err error
	)
	model := a.db.Model(&u)
	if model, err = a.prepareUser(c, &u, model, false); err != nil {
		return ItemResp(c, nil, err)
	}
	result, err := crudPutUser(c, model, &u)
	return ItemResp(c, result, err)
}

func (a *Auth) postUser(c echo.Context) error {
	var u User
	if _, err := a.prepareUser(c, &u, a.db, true); err != nil {
		return ItemResp(c, nil, err)
	}
	result, err := crudPostUser(c, a.db, &u)
	return ItemResp(c, result, err)
}

func (a *Auth) delUser(c echo.Context) error {
	result, err := crudDelUser(c, a.db)
	return ItemResp(c, result, err)
}

// AddUserHandlers registers CRUD handlers for manipulating users
func (a *Auth) AddUserHandlers(api *echo.Group) {
	api.GET("/users", a.listUsers)
	api.GET("/users/:id", a.getUser)
	api.PUT("/users/:id", a.putUser)
	api.POST("/users", a.postUser)
	api.DELETE("/users/:id", a.delUser)
}
