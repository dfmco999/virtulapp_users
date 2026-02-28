package util

import (
	"database/sql"
	"os"
)

func ExecSchemaFromFile(db *sql.DB, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = db.Exec(string(b))
	return err
}
