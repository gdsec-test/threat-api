"""\
Test cases for update_api.py
Tests - swagger inclusion from every json in apis folder
"""

import unittest
import unittest.mock as mock

from update_api import generate_swagger
from update_api import generate_api_definitions

# mocks the json retrieved from apigateway
JSON_TEMPLATE = {
    "openapi": "3.0.1",
    "paths": {
        "/swagger": {
            "get": {
                "responses": {
                    "200": {
                        "description": "200 response",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Empty"}
                            }
                        },
                    }
                },
                "x-amazon-apigateway-integration": {
                    "uri": "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-west-2:345790377847:function:SwaggerUI/invocations",
                },
            }
        },
    },
}

# mocks the swagger json present in each api folder
SWAGGER_TEST_JSON = {
    "openapi": "3.0.1",
    "info": {
        "title": "Threat API v2",
        "version": "1.0.1",
        "description": "Available APIs provided by the InfoSec TI team",
        "contact": {"name": "GoDaddy Threat Intelligence team"},
    },
    "paths": {
        "/lambda1": {
            "get": {
                "description": "Hello world in Python",
                "responses": {"200": {"description": "JSON response", "content": {}}},
                "tags": ["Python APIs"],
            }
        }
    },
    "components": {},
    "tags": [{"name": "Python APIs", "description": "Set of APIs written in Python"}],
}


class TestUpdate(unittest.TestCase):
    """\
        Test class
    """

    @mock.patch("update_api.json")
    @mock.patch("update_api.os.walk")
    @mock.patch("builtins.open")
    def test_generate_swagger(self, mock_open, mock_os_walk, mock_json):
        """\
            Tests cases for the following :
            '/lambda1' is present in the swagger structure after generate_swagger is called.
            """
        mock_os_walk.return_value = [
            ("/api", (), ("test_swagger.json",)),
        ]
        mock_json.load.return_value = SWAGGER_TEST_JSON

        swagger_json = generate_swagger(JSON_TEMPLATE)
        mock_open.assert_called_once_with("/api/test_swagger.json", "r")

        self.assertIn("/lambda1", swagger_json["paths"].keys())

    @mock.patch("update_api.json")
    @mock.patch("update_api.os.walk")
    @mock.patch("builtins.open")
    def test_generate_api_definitions(self, mock_open, mock_os_walk, mock_json):
        """\
            Tests cases for the following :
            paths : '/lambda1' & '/swagger' is present
            Dictionary additions :
                'x-amazon-apigateway-integration'  & 'security' is inserted in every method of path
            uri has account id 'test' and '/lambda1' inserted
        """

        mock_os_walk.return_value = [
            ("/api", (), ("test_swagger.json",)),
        ]
        mock_json.load.return_value = SWAGGER_TEST_JSON

        api_json = generate_api_definitions("test", JSON_TEMPLATE, "test_apigateway")
        mock_open.assert_called_once_with("/api/test_swagger.json", "r")

        self.assertIn("/swagger", api_json["paths"].keys())
        self.assertIn("/lambda1", api_json["paths"].keys())

        self.assertIn(
            "x-amazon-apigateway-integration",
            api_json["paths"]["/lambda1"]["get"].keys(),
        )

        self.assertEqual(
            api_json["paths"]["/lambda1"]["get"]["x-amazon-apigateway-integration"][
                "uri"
            ],
            "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-west-2:test:function:lambda1/invocations",
        )

        self.assertIn(
            "security",
            api_json["paths"]["/lambda1"]["get"].keys(),
        )

        self.assertIn(
            "test_apigateway-JWTAuthorizer",
            api_json["paths"]["/lambda1"]["get"]["security"][0].keys(),
        )


if __name__ == "__main__":
    unittest.main()
