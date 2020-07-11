package jsonecho

import (
	"bytes"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	jsontime "github.com/liamylian/jsontime/v2/v2"
)

// Result is a map alias for simple JSON object
type Result map[string]interface{}

var json = jsontime.ConfigWithCustomTimeFormat

// FileUpload is a string alias that supports proper JSON interop for React Admin usage
type FileUpload string

type fileUploadJSON struct {
	Src  string `json:"src"`
	Orig string `json:"orig"`
}

// JEBase is a base class for compat
type JEBase struct {
	ID uint `json:"id"`
}

// JEBased is the JEBase interface, you only need to provide the New implementation
type JEBased interface {
	Preprocess() error
	Postprocess() error
	Bind() bool
}

// Bind decides whether jsonecho should bind the object to save or if it's provided
func (j *JEBase) Bind() bool {
	return true
}

// Preprocess may change the original structure before saving
func (j *JEBase) Preprocess() error {
	return nil
}

// Postprocess may change the original structure after loading/returning
func (j *JEBase) Postprocess() error {
	return nil
}

// FromSQLDate parses the supplied date string as 2006-01-02
func FromSQLDate(d string) time.Time {
	res, err := time.Parse("2006-01-02", d)
	if err != nil {
		return time.Time{}
	}
	return res
}

func init() {
	jsontime.AddTimeFormatAlias("sql_date", "2006-01-02")
}

// BindJSON binds the request body to the provided structure using jsontime
func BindJSON(c echo.Context, target interface{}) error {
	return json.NewDecoder(c.Request().Body).Decode(target)
}

// NotFound returns 404 error with a default message
func NotFound(c echo.Context) error {
	return JSONErrorMessage(c, http.StatusNotFound, "Resource not found")
}

// JSONOk returns the provided map with http code 200
func JSONOk(c echo.Context, r interface{}) error {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(r)
	return c.JSONBlob(http.StatusOK, buf.Bytes())
}

// JSONError wraps the provided error in a JSON and returns it with the provided http error code
func JSONError(c echo.Context, code int, err error) error {
	return JSONErrorMessage(c, code, err.Error())
}

// JSONErrorMessage returns a JSON error with the provided http error code and message
func JSONErrorMessage(c echo.Context, code int, msg string) error {
	return c.JSON(code, Result{"message": msg})
}

// DecodeParam decodes the field (query parameter) into the provided target
func DecodeParam(c echo.Context, field string, target interface{}) error {
	return json.NewDecoder(strings.NewReader(c.QueryParam(field))).Decode(target)
}

// GetFilter returns the filters map for the current request
func GetFilter(c echo.Context) map[string]interface{} {
	var filter map[string]interface{}
	DecodeParam(c, "filter", &filter)
	return filter
}

// GetFilterIds returns the array of ids to return for the current request
func GetFilterIds(c echo.Context) []uint {
	var filter struct {
		ID []uint
	}
	DecodeParam(c, "filter", &filter)
	return filter.ID
}

// ItemResp renders a JSON reply either as a provided object or error and returns the result of echo.Context#JSON
func ItemResp(c echo.Context, itemPtr interface{}, err error) error {
	if err != nil {
		return JSONError(c, http.StatusBadRequest, err)
	}
	return JSONOk(c, itemPtr)
}

// MarshalJSON produces JSON for file upload field
func (f FileUpload) MarshalJSON() ([]byte, error) {
	var src string
	if f != "" {
		src = "uploads/" + string(f)
	}
	return json.Marshal(fileUploadJSON{Src: src, Orig: string(f)})
}

// UnmarshalJSON fills the Fileupload field with orig JSON field
func (f *FileUpload) UnmarshalJSON(data []byte) error {
	var tmp fileUploadJSON
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	*f = FileUpload(tmp.Orig)
	return nil
}
