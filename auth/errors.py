class InternalServerError(Exception):
    pass
class SchemaValidationError(Exception):
    pass
class EmailDoesnotExistsError(Exception):
    pass
class BadTokenError(Exception):
   pass

errors = {
    "InternalServerError": {
        "message": "Something went wrong",
        "status": 500
        } ,
     "SchemaValidationError": {
         "message": "Request is missing required fields",
         "status": 400 },
    "EmailDoesnotExistsError": {
         "message": "Couldn't find the user with given email address",
        "status": 400},
    "BadTokenError": {
        "message": "Invalid token",
        "status": 403
      }


         }
