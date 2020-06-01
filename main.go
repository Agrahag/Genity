package main

import (
	"fmt"
	"strconv"
	"time"

	"encoding/base64"

	"goapp/internal/log"
	"goapp/internal/scylla"

	"github.com/d1str0/sse"
	"github.com/gocql/gocql"
	"github.com/scylladb/gocqlx/v2"
	"github.com/scylladb/gocqlx/v2/qb"
	"github.com/scylladb/gocqlx/v2/table"

	"go.uber.org/zap"
	//"crypto/ecdsa"  -- Elliptical Curve Cryptography
)

var stmts = createStatements()
var stmtsEnc = createEncStatements()
var session gocql.Session
var sessionEnc gocql.Session
var sessiong gocqlx.Session

/*
type Person struct {
	person_id        string
	first_name       string
	last_name        string
	address          string
	picture_location string
}
*/

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	fmt.Printf(" %s took %s", name, elapsed)
}

func main() {

	defer timeTrack(time.Now(), "\nSSE demo completed")
	password := []byte("smile27")
	salt, _ := sse.Salt()

	key := sse.Key(password, salt, 4096)
	fmt.Printf("Key: %x\n", key)

	recordsMax := 113
	recordsMake := recordsMax + 7
	//recordsCheck := 4

	//setup cluster and session
	logger := log.CreateLogger("info")

	cluster := scylla.CreateCluster(gocql.Quorum, "catalog", "mms_scylla-node1_1", "mms_scylla-node2_1", "mms_scylla-node3_1")
	cluster.ProtoVersion = 4

	//session for the unencrypted data
	session, err := gocql.NewSession(*cluster)
	if err != nil {
		logger.Fatal("unable to connect to scylla", zap.Error(err))
	}

	//session for the encrypted data
	sessionEnc, err := gocql.NewSession(*cluster)
	if err != nil {
		logger.Fatal("unable to connect to scylla", zap.Error(err))
	}

	//using seesiong to create keyspace if not existing
	sessiong, err := gocqlx.WrapSession(cluster.CreateSession())
	if err != nil {
		logger.Fatal("unable to connect to scylla gocqlx", zap.Error(err))
	}

	//createTables(sessiong)

	err = sessiong.ExecStmt(`CREATE TABLE IF NOT EXISTS catalog.star_data (
		person_id text,
		first_name text,
		last_name text,
		address text,
		picture_location text,
		PRIMARY KEY((person_id)));`)
	if err != nil {
		logger.Fatal("unable to create enc_star_data table", zap.Error(err))
	}

	//  already exists
	err = sessiong.ExecStmt(`CREATE TABLE IF NOT EXISTS catalog.enc_star_data (
		person_id text,
		first_name text,
		last_name text,
		address text,
		picture_location text,
		PRIMARY KEY((person_id)));`)
	if err != nil {
		logger.Fatal("unable to create enc_star_data table", zap.Error(err))
	}

	err = sessiong.ExecStmt(`TRUNCATE TABLE star_data;`)
	if err != nil {
		logger.Fatal("unable to truncate star_data table", zap.Error(err))
	}

	err = sessiong.ExecStmt(`TRUNCATE TABLE enc_star_data;`)
	if err != nil {
		logger.Fatal("unable to truncate enc_star_data table", zap.Error(err))
	}

	strPersonSliceG := ""
	origString := ""

	personSliceG := make([][]byte, recordsMake)
	fnSliceG := make([][]byte, recordsMake)
	lnSliceG := make([][]byte, recordsMake)
	addressSliceG := make([][]byte, recordsMake)
	fbSliceG := make([][]byte, recordsMake)

	encFnGBA := make([][]byte, recordsMake)
	hmacFnG := make([][]byte, recordsMake)
	decFnG := make([][]byte, recordsMake)
	encFnG := make([]string, recordsMake)
	decodedEncFnGBA := make([][]byte, recordsMake)

	encLnGBA := make([][]byte, recordsMake)
	hmacLnG := make([][]byte, recordsMake)
	decLnG := make([][]byte, recordsMake)
	encLnG := make([]string, recordsMake)
	decodedEncLnGBA := make([][]byte, recordsMake)

	encAddressGBA := make([][]byte, recordsMake)
	hmacAddressG := make([][]byte, recordsMake)
	decAddressG := make([][]byte, recordsMake)
	encAddressG := make([]string, recordsMake)
	decodedEncAddressGBA := make([][]byte, recordsMake)

	encFbGBA := make([][]byte, recordsMake)
	hmacFbG := make([][]byte, recordsMake)
	decFbG := make([][]byte, recordsMake)
	encFbG := make([]string, recordsMake)
	decodedEncFbGBA := make([][]byte, recordsMake)

	//add recordsMax records
	for i := 0; i < recordsMax; i++ {
		personSliceG[i] = []byte(strconv.Itoa(i))
		strPersonSliceG = string(personSliceG[i])
		fnSliceG[i] = []byte("fn_" + strPersonSliceG)
		lnSliceG[i] = []byte("ln_" + strPersonSliceG)
		addressSliceG[i] = []byte("address_" + strPersonSliceG)
		fbSliceG[i] = []byte("http://www.facebook.com/person" + strPersonSliceG)

		origString = string(fnSliceG[i])
		//encrypted Byte Array from original string
		//encFnGBA[i], _ = sse.Encrypt([]byte(origString), key)
		encFnGBA[i], _ = sse.Encrypt(fnSliceG[i], key)
		//encrypted string
		encFnG[i] = base64.StdEncoding.EncodeToString(encFnGBA[i])
		hmacFnG[i] = sse.HMAC(encFnGBA[i], key)
		//encrypted BA from encrypted string
		decodedEncFnGBA[i], _ = base64.StdEncoding.DecodeString(encFnG[i])
		//decrypted BA from decoded BA
		decFnG[i], _ = sse.Decrypt(decodedEncFnGBA[i], key)

		origString = string(lnSliceG[i])
		encLnGBA[i], _ = sse.Encrypt([]byte(origString), key)
		encLnG[i] = base64.StdEncoding.EncodeToString(encLnGBA[i])
		hmacLnG[i] = sse.HMAC(encLnGBA[i], key)
		decodedEncLnGBA[i], _ = base64.StdEncoding.DecodeString(encLnG[i])
		decLnG[i], _ = sse.Decrypt(decodedEncLnGBA[i], key)

		origString = string(addressSliceG[i])
		encAddressGBA[i], _ = sse.Encrypt([]byte(origString), key)
		encAddressG[i] = base64.StdEncoding.EncodeToString(encAddressGBA[i])
		hmacAddressG[i] = sse.HMAC(encAddressGBA[i], key)
		decodedEncAddressGBA[i], _ = base64.StdEncoding.DecodeString(encAddressG[i])
		decAddressG[i], _ = sse.Decrypt(decodedEncAddressGBA[i], key)

		origString = string(fbSliceG[i])
		encFbGBA[i], _ = sse.Encrypt([]byte(origString), key)
		encFbG[i] = base64.StdEncoding.EncodeToString(encFbGBA[i])
		hmacFbG[i] = sse.HMAC(encFbGBA[i], key)
		decodedEncFbGBA[i], _ = base64.StdEncoding.DecodeString(encFbG[i])

		decFbG[i], _ = sse.Decrypt(decodedEncFbGBA[i], key)
	}

	/*
		//display recordsCheck records
		for i := 0; i < recordsCheck; i++ {
			ai := strconv.Itoa(i)
			fmt.Printf("\n\tpersonSliceG["+ai+"]: %s", personSliceG[i])
			fmt.Printf("\n\tfnSliceG["+ai+"]: %s", fnSliceG[i])
			fmt.Printf("\n\tlnSliceG["+ai+"]: %s", lnSliceG[i])
			fmt.Printf("\n\taddressSliceG["+ai+"]: %s", addressSliceG[i])
			fmt.Printf("\n\tfbSliceG["+ai+"]: %s", fbSliceG[i])
			//fmt.Printf("\n\n\tencG["+ai+"]: %s", encFnG[i])
			fmt.Printf("\n\tdecFnG["+ai+"]: %s", decFnG[i])
			fmt.Printf("\n\tdecLnG["+ai+"]: %s", decLnG[i])
			fmt.Printf("\n\tdecAddressG["+ai+"]: %s", decAddressG[i])
			fmt.Printf("\n\tdecFbG["+ai+"]: %s", decFbG[i])
			fmt.Printf("\n")
		}
	*/

	//now add data to catalog.star_data
	selectQuery(session, logger)
	for ig := 0; ig < recordsMax; ig++ {
		insertQuery(session, string(personSliceG[ig]), string(fnSliceG[ig]), string(lnSliceG[ig]), string(addressSliceG[ig]), string(fbSliceG[ig]), logger)
	}
	fmt.Printf("\nAdded %d records to catalog.star_data\n\n", recordsMax)

	//now add data to catalog.enc_star_data
	selectEncryptedQuery(sessionEnc, logger)
	for ig := 0; ig < recordsMax; ig++ {
		insertEncryptedQuery(sessionEnc, string(personSliceG[ig]), encFnG[ig], encLnG[ig], encAddressG[ig], encFbG[ig], logger)
	}
	fmt.Printf("\nAdded %d records to catalog.enc_star_data\n\n", recordsMax)

	//************* TEST1 START ********************************
	//test start with string
	fmt.Printf("\n\nTest1 Start with smile now string as test data")
	testString := "smile now!"
	fmt.Printf("\ntestString: %s", testString)

	//cast as byte array and encrypt to byte array
	testEncryptedBA, _ := sse.Encrypt([]byte(testString), key)
	fmt.Printf("\ntestEncryptedBA: %s", testEncryptedBA)

	//save encrypted byte array to encrypted byte array string
	testEncryptedBAString := base64.StdEncoding.EncodeToString(testEncryptedBA)
	fmt.Printf("\ntestEncryptedBAString: %s", testEncryptedBAString)

	//decode from encrypted byte string to encrypted byte array
	testEncryptedBA2, err := base64.StdEncoding.DecodeString(testEncryptedBAString)
	fmt.Printf("\ntestEncryptedBA2: %s", testEncryptedBA2)

	//decrypt from encrypted byte array to string
	testDecryptedString, _ := sse.Decrypt(testEncryptedBA2, key)
	fmt.Printf("\ntestDecryptedString: %s", testDecryptedString)
	//************* TEST1 end ********************************

	//************* TEST2 START ********************************
	fmt.Printf("\n\nTest 2 with real data from autogenerated data")
	//test start with auto-generate data
	testString = string(fnSliceG[0])
	fmt.Printf("\ntestString: %s", fnSliceG[0])

	//cast as byte array and encrypt to byte array
	testEncryptedBA, _ = sse.Encrypt([]byte(testString), key)
	fmt.Printf("\ntestEncryptedBA: %s", testEncryptedBA)

	//save encrypted byte array to encrypted byte array string
	testEncryptedBAString = base64.StdEncoding.EncodeToString(testEncryptedBA)
	fmt.Printf("\ntestEncryptedBAString: %s", testEncryptedBAString)

	//decode from encrypted byte string to encrypted byte array
	testEncryptedBA2, err = base64.StdEncoding.DecodeString(testEncryptedBAString)
	fmt.Printf("\ntestEncryptedBA2: %s", testEncryptedBA2)

	//decrypt from encrypted byte array to string
	testDecryptedString, _ = sse.Decrypt(testEncryptedBA2, key)
	fmt.Printf("\ntestDecryptedString: %s\n\n", testDecryptedString)
	//************* TEST2 end *******************************

	//************  Search test start ************************
	//************  Move as a function to seach.go ***********

	//Search array for a value in field of interests with a decryptedString[i] == searchString
	//and return person_id[i]
	//seachWord := "fn_3"
	//searchColumn := "first_name"
	//searchWordEncryptedBA, _ := sse.Encrypt([]byte(seachWord), key)
	//searchWordEncryptedBAString := base64.StdEncoding.EncodeToString(searchWordEncryptedBA)
	//decryptedSearchWordMatchBA, _ := sse.Decrypt(searchWordEncryptedBA, key)
	//decryptedSearchWordMatchBAString := string(decryptedSearchWordMatchBA)

	/*
			//2. search encrypted records for matches and return list
			//create and run select statement with enc_star_data where first_name = "fn7"
			////******      START HERE        ************************
			//encSearchReturns[][columns] := searchEncDbForWord(searchWordEncryptedBAString, "first_name", encryptedColumn)
			logger.Info("\n\nDisplaying Search Results:")
			//var rs []Record
			//searchSql := "select person_id from catalog.enc_star_data where " + searchColumn + " = '" + decryptedSearchWordMatchBAString + "'" +
			//	" ALLOW FILTERING; "
			searchSql := "select person_id from catalog.enc_star_data where " + searchColumn + " = '" + searchWordEncryptedBAString + "'" +
				" ALLOW FILTERING; "

			fmt.Printf("searchSql: %s", searchSql)

		decSearchReturns[][columns] := decryptedMatchinRecords(searchWord,decryptedColumn)

			//3.	Decrypt matching rows

			//4. 	Return
			//		a.	search word
			//		b.	with decrypted full rows of decrypted record matches

			//************  Search test end ************************
	*/
	defer sessiong.Close()
	defer sessionEnc.Close()
	defer session.Close()
}

//searchCol can be one column name or "ALL" to search all columns
/*
func searchEncDbForWord(string searchWord, string searchCol, session *gocql.Session, logger *zap.Logger) {
	logger.Info("Displaying Search Results:")
	var rs []Record
	err := gocqlx.Query(session.Query(stmts.sel.stmt), stmts.sel.names).SelectRelease(&rs)
	if err != nil {
		logger.Warn("select catalog.enc_star_data", zap.Error(err))
		return
	}
	for _, r := range rs {
		logger.Info("\t" + r.FirstName + " " + r.LastName + ", " + r.Address + ", " + r.PictureLocation)
	}
}
*/

func createTables(session gocqlx.Session) {
	logger := log.CreateLogger("info")

	err := sessiong.ExecStmt(`CREATE TABLE IF NOT EXISTS catalog.star_data (
		person_id text,
		first_name text,
		last_name text,
		address text,
		picture_location text,
		PRIMARY KEY((person_id)));`)
	if err != nil {
		logger.Fatal("unable to create enc_star_data table", zap.Error(err))
	}

	//  already exists
	err = sessiong.ExecStmt(`CREATE TABLE IF NOT EXISTS catalog.enc_star_data (
		person_id text,
		first_name text,
		last_name text,
		address text,
		picture_location text,
		PRIMARY KEY((person_id)));`)
	if err != nil {
		logger.Fatal("unable to create enc_star_data table", zap.Error(err))
	}

	err = sessiong.ExecStmt(`TRUNCATE TABLE star_data;`)
	if err != nil {
		logger.Fatal("unable to truncate star_data table", zap.Error(err))
	}

	err = sessiong.ExecStmt(`TRUNCATE TABLE enc_star_data;`)
	if err != nil {
		logger.Fatal("unable to truncate enc_star_data table", zap.Error(err))
	}

}

func insertQuery(session *gocql.Session, personId string, firstName string, lastName string, address string, pictureLocation string, logger *zap.Logger) {
	//logger.Info("Inserting " + firstName + "......")
	r := Record{
		PersonId:        personId,
		FirstName:       firstName,
		LastName:        lastName,
		Address:         address,
		PictureLocation: pictureLocation,
	}
	err := gocqlx.Query(session.Query(stmts.ins.stmt), stmts.ins.names).BindStruct(r).ExecRelease()
	if err != nil {
		logger.Error("insert catalog.star_data", zap.Error(err))
	}
}

func insertEncryptedQuery(sessionEnc *gocql.Session, personId string, firstName string, lastName string, address string, pictureLocation string, logger *zap.Logger) {
	//logger.Info("Inserting " + firstName + "......")
	r := Record{
		PersonId:        personId,
		FirstName:       firstName,
		LastName:        lastName,
		Address:         address,
		PictureLocation: pictureLocation,
	}
	err := gocqlx.Query(sessionEnc.Query(stmtsEnc.ins.stmt), stmtsEnc.ins.names).BindStruct(r).ExecRelease()
	if err != nil {
		logger.Error("insert catalog.enc_star_data", zap.Error(err))
	}
}

func selectQuery(session *gocql.Session, logger *zap.Logger) {
	logger.Info("Displaying Results:")
	var rs []Record
	err := gocqlx.Query(session.Query(stmts.sel.stmt), stmts.sel.names).SelectRelease(&rs)
	if err != nil {
		logger.Warn("select catalog.star_data", zap.Error(err))
		return
	}
	for _, r := range rs {
		logger.Info("\t" + r.PersonId + " " + r.FirstName + " " + r.LastName + ", " + r.Address + ", " + r.PictureLocation)
	}
}

func selectEncryptedQuery(sessionEnc *gocql.Session, logger *zap.Logger) {
	logger.Info("Displaying Results:")
	var rs []Record
	err := gocqlx.Query(sessionEnc.Query(stmtsEnc.sel.stmt), stmtsEnc.sel.names).SelectRelease(&rs)
	if err != nil {
		logger.Warn("select catalog.enc_star_data", zap.Error(err))
		return
	}
	for _, r := range rs {
		logger.Info("\t" + r.PersonId + " " + r.FirstName + " " + r.LastName + ", " + r.Address + ", " + r.PictureLocation)
	}
}

func createStatements() *statements {
	m := table.Metadata{
		Name:    "star_data",
		Columns: []string{"person_id", "first_name", "last_name", "address", "picture_location"},
		PartKey: []string{"person_id"},
	}

	tbl := table.New(m)

	deleteStmt, deleteNames := tbl.Delete()
	insertStmt, insertNames := tbl.Insert()
	// Normally a select statement such as this would use `tbl.Select()` to select by
	// primary key but now we just want to display all the records...
	selectStmt, selectNames := qb.Select(m.Name).Columns(m.Columns...).ToCql()
	return &statements{
		del: query{
			stmt:  deleteStmt,
			names: deleteNames,
		},
		ins: query{
			stmt:  insertStmt,
			names: insertNames,
		},
		sel: query{
			stmt:  selectStmt,
			names: selectNames,
		},
	}
}

func createEncStatements() *statements {
	m := table.Metadata{
		Name:    "enc_star_data",
		Columns: []string{"person_id", "first_name", "last_name", "address", "picture_location"},
		PartKey: []string{"person_id"},
	}

	tbl := table.New(m)

	deleteStmt, deleteNames := tbl.Delete()
	insertStmt, insertNames := tbl.Insert()
	// Normally a select statement such as this would use `tbl.Select()` to select by
	// primary key but now we just want to display all the records...
	selectStmt, selectNames := qb.Select(m.Name).Columns(m.Columns...).ToCql()
	return &statements{
		del: query{
			stmt:  deleteStmt,
			names: deleteNames,
		},
		ins: query{
			stmt:  insertStmt,
			names: insertNames,
		},
		sel: query{
			stmt:  selectStmt,
			names: selectNames,
		},
	}
}

type query struct {
	stmt  string
	names []string
}

type statements struct {
	del query
	ins query
	sel query
}

type Record struct {
	PersonId        string `db:"person_id"`
	FirstName       string `db:"first_name"`
	LastName        string `db:"last_name"`
	Address         string `db:"address"`
	PictureLocation string `db:"picture_location"`
}

/*
func deleteQuery(session *gocql.Session, string firstName, string lastName, logger *zap.Logger) {
	logger.Info("Deleting " + firstName + "......")
	r := Record{
		FirstName: firstName,
		LastName:  lastName,
	}
	err := gocqlx.Query(session.Query(stmts.del.stmt), stmts.del.names).BindStruct(r).ExecRelease()
	if err != nil {
		logger.Error("delete catalog.star_data", zap.Error(err))
	}
}
*/
