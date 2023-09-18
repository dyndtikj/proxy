package api

import "go.mongodb.org/mongo-driver/bson/primitive"

type Request struct {
	ID         primitive.ObjectID  `json:"_id,omitempty" bson:"_id,omitempty"`
	Method     string              `json:"method" bson:"method"`
	Path       string              `json:"path" bson:"path"`
	GetParams  map[string][]string `json:"get_params" bson:"get_params"`
	Headers    map[string][]string `json:"headers" bson:"headers"`
	Cookies    map[string]string   `json:"cookies" bson:"cookies"`
	PostParams map[string][]string `json:"post_params" bson:"post_params"`
	Body       string              `json:"body" bson:"body"`
}

type Response struct {
	ID      primitive.ObjectID  `json:"_id,omitempty" bson:"_id,omitempty"`
	ReqID   string              `json:"req_id,omitempty" bson:"req_id,omitempty"`
	Code    uint32              `json:"code" bson:"code"`
	Message string              `json:"message" bson:"message"`
	Headers map[string][]string `json:"headers" bson:"headers"`
	Body    interface{}         `json:"body" bson:"body"`
}
