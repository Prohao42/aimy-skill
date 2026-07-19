import re
import pytest
import requests
import responses
from tools.graphql_abuser import GraphQLAbuser


class TestGraphQLAbuser:
    @responses.activate
    def test_introspection_detected(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            json={"data": {"__schema": {"types": [{"name": "User"}], "queryType": {"name": "Query"}}}},
            status=200,
        )
        abuser = GraphQLAbuser(sess=sess)
        result = abuser.check("http://test.com/api")
        assert result.get("vulnerable", False) is True
        assert any(f["method"] == "full_introspection" for f in result.get("findings", []))

    @responses.activate
    def test_depth_abuse(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            json={"data": {"users": [{"name": "admin"}]}},
            status=200,
        )
        abuser = GraphQLAbuser(sess=sess)
        result = abuser.check("http://test.com/api")
        assert isinstance(result, dict)
        assert "vulnerable" in result

    @responses.activate
    def test_batch_abuse(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            json={"data": {"__typename": "Query"}},
            status=200,
        )
        abuser = GraphQLAbuser(sess=sess)
        result = abuser.check("http://test.com/api")
        assert isinstance(result, dict)

    @responses.activate
    def test_no_graphql(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            body="not graphql",
            status=200,
        )
        abuser = GraphQLAbuser(sess=sess)
        result = abuser.check("http://test.com/api")
        assert result.get("vulnerable", False) is False

    @responses.activate
    def test_field_suggestions(self):
        sess = requests.Session()
        responses.add(
            responses.POST,
            re.compile(".*"),
            json={"errors": [{"message": "Cannot query field 'adminn'. Did you mean 'admin'?"}]},
            status=200,
        )
        abuser = GraphQLAbuser(sess=sess)
        result = abuser.check("http://test.com/api")
        assert isinstance(result, dict)
