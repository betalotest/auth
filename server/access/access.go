package access

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// config holds values from configuration file
type config struct {
	dbAddress string
	dbName    string
	userc     string
	tokenc    string
	signature string
	issuer    string
}

// conn wraps mgo session and collections
type conn struct {
	*mgo.Session
	userc  *mgo.Collection
	tokenc *mgo.Collection
}

// Access grant access to db and jwt
type Access struct {
	*conn
	Signature string
	Issuer    string
}

// User wraps data related to an auth user
type User struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	PasswordHash string `json:"passwordhash"`
	CreatedAt    string `json:"createdat"`
}

// Credential wraps data related to user access to api
type Credential struct {
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
}

// Claim wraps the info we want to pass in the JWT
type Claim struct {
	User  string `json:"user"`
	Email string `json:"email"`
	jwt.StandardClaims
}

// New - given a path to a configuration
// file grants Access to the caller
func New(configpath string) (*Access, error) {
	conf, err := loadConfig(configpath)
	if err != nil {
		return nil, errors.Wrap(err, "could not load configuration file")
	}

	sess, err := mgo.Dial(conf.dbAddress)
	if err != nil {
		return nil, errors.Wrap(err, "could not create db conn")
	}

	userc := sess.DB(conf.dbName).C(conf.userc)
	tokenc := sess.DB(conf.dbName).C(conf.tokenc)

	conn := &conn{sess, userc, tokenc}
	return &Access{conn, conf.signature, conf.issuer}, nil
}

// FindUserByEmail - use email to retrieve user's details from DB and return a user struct
func (a Access) FindUserByEmail(email string) (User, error) {
	u := User{}
	if err := a.userc.Find(bson.M{"email": email}).One(&u); err != nil {
		return User{}, errors.Wrap(err, "could not retrieve details for user "+email)
	}
	return u, nil
}

// UpdateToken - update the token document related to an user giving it a new token
func (a Access) UpdateToken(email, token string) error {
	// the index of the documment we want to modify
	doc := bson.M{"email": email}

	// the change we want to add
	change := bson.M{"$set": bson.M{"token": token, "createdAt": time.Now().String()}}

	// db time!
	if _, err := a.tokenc.Upsert(doc, change); err != nil {
		return errors.Wrap(err, "could not update token for user "+email)
	}
	return nil
}

// RegisterUser - add user to DB
func (a Access) RegisterUser(name, email, passwordHash string) error {
	u := User{
		name,
		email,
		passwordHash,
		time.Now().String(),
	}

	if err := a.userc.Insert(u); err != nil {
		return errors.Wrap(err, fmt.Sprintf("could not insert user %s in db", email))
	}
	return nil
}

// NewToken - returns a new JWT
func (a Access) NewToken(name, email string) (string, int64, error) {
	expirationDate := time.Now().Add(time.Hour * 24).Unix()
	c := Claim{
		name,
		email,
		jwt.StandardClaims{
			ExpiresAt: expirationDate,
			Issuer:    a.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	ss, err := token.SignedString([]byte(a.Signature))
	if err != nil {
		return "", 0, errors.Wrap(err, "could not create token for user "+email)
	}
	return ss, expirationDate, nil
}

func loadConfig(filepath string) (*config, error) {
	viper.SetConfigFile(filepath)
	if err := viper.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "could not read from config file "+filepath)
	}

	keys := []string{
		"db_address",
		"db_name",
		"db_user_collection",
		"db_token_collection",
		"token_signature",
		"token_issuer",
	}

	for _, v := range keys {
		if !viper.IsSet(v) {
			return nil, fmt.Errorf("could not read value from config file: %s", v)
		}
	}

	return &config{
		viper.GetString("db_address"),
		viper.GetString("db_name"),
		viper.GetString("db_user_collection"),
		viper.GetString("db_token_collection"),
		viper.GetString("token_signature"),
		viper.GetString("token_issuer"),
	}, nil
}
