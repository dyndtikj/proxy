package repository

import (
	"context"
	"encoding/json"
	"proxy/api"
	"strings"

	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type ProxyDB struct {
	db             *mongo.Database
	reqCollection  *mongo.Collection
	respCollection *mongo.Collection
}

func New(db *mongo.Database) *ProxyDB {
	return &ProxyDB{
		db:             db,
		reqCollection:  db.Collection("requests"),
		respCollection: db.Collection("responses"),
	}
}

func (r ProxyDB) AddReq(req api.Request) (string, error) {
	id, err := r.reqCollection.InsertOne(context.Background(), req)
	if err != nil {
		return "", errors.Wrap(err, "failed insert request to mongo")
	}
	res, _ := json.Marshal(id.InsertedID)
	return strings.Trim(string(res), "\""), nil
}

func (r ProxyDB) AddResp(resp api.Response) (string, error) {
	id, err := r.respCollection.InsertOne(context.Background(), resp)
	if err != nil {
		return "", errors.Wrap(err, "failed insert response to mongo")
	}
	res, _ := json.Marshal(id.InsertedID)
	return string(res), nil
}

func (r ProxyDB) GetRequests() ([]api.Request, error) {
	cur, err := r.reqCollection.Find(context.Background(), bson.D{{}})
	if err != nil {
		return nil, err
	}
	var resp []api.Request
	for cur.Next(context.TODO()) {
		var elem api.Request
		err := cur.Decode(&elem)
		if err != nil {
			return nil, err
		}
		resp = append(resp, elem)
	}

	return resp, nil
}

func (r ProxyDB) GetRequestByID(id string) (*api.Request, error) {
	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, errors.New("wrong id format cant convert")
	}

	cur, err := r.reqCollection.Find(context.Background(), bson.M{"_id": objectId})
	if err != nil {
		return nil, err
	}
	var resp *api.Request
	for cur.Next(context.TODO()) {
		var elem api.Request
		err := cur.Decode(&elem)
		if err != nil {
			return nil, err
		}
		resp = &elem
		break
	}

	return resp, nil
}

func (r ProxyDB) GetResponses() ([]api.Response, error) {
	cur, err := r.respCollection.Find(context.Background(), bson.D{{}})
	if err != nil {
		return nil, err
	}
	var resp []api.Response
	for cur.Next(context.TODO()) {
		var elem api.Response
		err := cur.Decode(&elem)
		if err != nil {
			return nil, err
		}
		resp = append(resp, elem)
	}

	return resp, nil
}

func (r ProxyDB) GetResponseByReqID(id string) (*api.Response, error) {
	cur, err := r.respCollection.Find(context.Background(), bson.M{"req_id": id})
	if err != nil {
		return nil, err
	}
	var resp *api.Response
	for cur.Next(context.TODO()) {
		var elem api.Response
		err := cur.Decode(&elem)
		if err != nil {
			return nil, err
		}
		resp = &elem
		break
	}

	return resp, nil
}
