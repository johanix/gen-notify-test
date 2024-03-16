/*
 * Johan Stenstam, johani@johani.org
 */

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

var DefaultTables = map[string]string{

	"Keys": `CREATE TABLE IF NOT EXISTS 'Keys' (
id		  INTEGER PRIMARY KEY,
parent		  TEXT,
child		  TEXT,
keyid		  INTEGER,
keyrr		  TEXT,
comment		  TEXT,
UNIQUE (parent, child, keyid)
)`,
}

// Migrating all DB access to own interface to be able to have local receiver functions.
type KeyDB struct {
	DB *sql.DB
	mu sync.Mutex
}

func (db *KeyDB) Prepare(q string) (*sql.Stmt, error) {
	return db.DB.Prepare(q)
}

func (db *KeyDB) Begin() (*sql.Tx, error) {
	return db.DB.Begin()
}

func (db *KeyDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.DB.Query(query, args...)
}

func (db *KeyDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return db.DB.QueryRow(query, args...)
}

func (db *KeyDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return db.DB.Exec(query, args...)
}

func (db *KeyDB) Close() error {
	return db.DB.Close()
}

func tableExists(db *sql.DB, name string) bool {

	var match string
	var err error

	sqlcmd := fmt.Sprintf("SELECT name FROM sqlite_master WHERE type='table' AND name='%s'", name)
	row := db.QueryRow(sqlcmd)

	switch err = row.Scan(&match); err {
	case sql.ErrNoRows:
		fmt.Printf("Error: tableExists: table %s not found.\n", name)
		return false
	case nil:
		// all ok
		fmt.Printf("tableExists: found table '%s'\n", match)
		return true
	default:
		panic(err)
	}
	return false
}

func dbSetupTables(db *sql.DB) bool {
	fmt.Printf("Setting up missing tables\n")

	for t, s := range DefaultTables {
		stmt, err := db.Prepare(s)
		if err != nil {
			log.Printf("dbSetupTables: Error from %s schema \"%s\": %v\n", t, s, err)
		}
		_, err = stmt.Exec()
		if err != nil {
			log.Fatalf("Failed to set up db schema: %s. Error: %v", s, err)
		}
	}

	return false
}

func NewKeyDB(force bool) *KeyDB {
	dbfile := viper.GetString("keydb.db")
	fmt.Printf("dbSetup: using sqlite db in file %s\n", dbfile)
	if err := os.Chmod(dbfile, 0664); err != nil {
		log.Printf("dbSetup: Error trying to ensure that db %s is writable: %v",
			err)
	}
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		log.Fatalf("NewKeyDB: Error from sql.Open:", err)
        }

	if force {
		sqlcmd := "DROP TABLE Keys"
		_, err = db.Exec(sqlcmd)
		if err != nil {
			log.Fatalf("NewKeyDB: Error when dropping table Keys:", err)
		}
	}
	dbSetupTables(db)
	return &KeyDB{DB: db}
}

