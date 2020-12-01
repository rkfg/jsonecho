package jsonecho

import "github.com/jinzhu/gorm"

// FK represents a foreign key constraint.
// Column is the model's column (usually with '_id' suffix)
// ForeignColumn is the column in another table this model refers to, usually written as 'tablename(id)'
type FK struct {
	Model         interface{}
	Column        string
	ForeignColumn string
}

// AddForeignKeys adds RESTRICT foreign key constraints to the provided models
func AddForeignKeys(db *gorm.DB, fks []FK) error {
	for i := range fks {
		if err := db.
			Model(fks[i].Model).
			AddForeignKey(fks[i].Column, fks[i].ForeignColumn, "RESTRICT", "RESTRICT").
			Error; err != nil {
			return err
		}
	}
	return nil
}
