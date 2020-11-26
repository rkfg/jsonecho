package jsonecho

import "os"

// LoadConfig loads config from json
func LoadConfig(configFilename string, config interface{}) error {
	if file, err := os.Open(configFilename); err == nil {
		defer file.Close()
		json.NewDecoder(file).Decode(config)
	} else {
		return err
	}
	return nil
}
