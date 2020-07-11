// +build ignore

package jsonecho

import (
	"fmt"
	"strings"

	"github.com/cheekybits/genny/generic"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo/v4"
	"github.com/rkfg/jsonecho"
)

// Item is the type that you work with
type Item generic.Type

// CRUDListItems lists items from the provided (possibly already filtered) model using the query filter,
// returns itemSlicePtr itself and an error if there any
func CRUDListItems(c echo.Context, model *gorm.DB) ([]Item, error) {
	var result []Item
	var params struct {
		Filter map[string]string
		Rng    []int
		Sort   []string
	}
	jsonecho.DecodeParam(c, "range", &params.Rng)
	jsonecho.DecodeParam(c, "sort", &params.Sort)

	chain := model
	if len(params.Sort) == 2 {
		chain = chain.Order(params.Sort[0]+" "+params.Sort[1], true)
	}
	ids := jsonecho.GetFilterIds(c)
	if len(ids) > 0 {
		chain = chain.Where("id in (?)", ids)
	}
	var relatedIds map[string]uint
	jsonecho.DecodeParam(c, "filter", &relatedIds)
	for k, v := range relatedIds {
		if strings.HasSuffix(k, "_id") && model.NewScope(&result).HasColumn(k) {
			chain = chain.Where(k+" = ?", v)
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

// CRUDDelItem deletes the item with supplied id and returns the deleted object
func CRUDDelItem(c echo.Context, db *gorm.DB) (*Item, error) {
	var result Item
	t := db.Model(Item{})
	if t.Where("id = ?", c.Param("id")).First(&result).RecordNotFound() {
		return nil, jsonecho.NotFound(c)
	}
	if err := t.Delete(&result).Error; err != nil {
		return nil, err
	}
	return &result, nil
}

// CRUDPutItem updates the specified item
func CRUDPutItem(c echo.Context, db *gorm.DB, item *Item) (*Item, error) {
	var existing Item // create a new identical struct and get a pointer to it to 'old'
	db.First(&existing, "id = ?", c.Param("id"))
	if item.Bind() {
		if err := jsonecho.BindJSON(c, item); err != nil {
			return nil, err
		}
	}
	item.ID = existing.ID
	item.Preprocess()
	db = db.Save(item)
	if err := db.Error; err != nil {
		return nil, err
	}
	return item, nil
}

// CRUDPostItem creates a new item
func CRUDPostItem(c echo.Context, db *gorm.DB, item *Item) (*Item, error) {
	if item.Bind() {
		jsonecho.BindJSON(c, item)
	}
	item.ID = 0
	item.Preprocess()
	if err := db.Create(item).Error; err != nil {
		return nil, err
	}
	return item, nil
}

// CRUDGetItem returns an item by id
func CRUDGetItem(c echo.Context, db *gorm.DB) (*Item, error) {
	var item Item
	db.First(&item, "id = ?", c.Param("id"))
	item.Postprocess()
	return &item, nil
}
