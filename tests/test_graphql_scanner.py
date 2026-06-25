import re
import pytest
import responses
from tools.graphql_scanner import check, has_graphql_schema


class TestHasGraphqlSchema:
    def test_valid_schema(self):
        body = '{"data":{"__schema":{"types":[{"name":"Query","fields":[]}]}}}'
        assert has_graphql_schema(body) is True

    def test_no_schema(self):
        assert has_graphql_schema('{"error":"not found"}') is False
        assert has_graphql_schema('not json') is False
        assert has_graphql_schema('{}') is False


class TestGraphQLScanner:
    @responses.activate
    def test_introspection_enabled(self):
        body = '{"data":{"__schema":{"types":[{"name":"Query","fields":[]}]}}}'
        responses.add(
            responses.POST, 'http://test.com/page/graphql',
            body=body, status=200,
        )
        result = check('http://test.com/page')
        assert result['vulnerable'] is True
        assert result['introspection'] is True

    @responses.activate
    def test_mutation_accepted(self):
        def callback(req):
            b = req.body.decode('utf-8') if isinstance(req.body, bytes) else (req.body or '')
            if 'mutation' in b:
                return (200, {}, '{"data":{"login":{"token":"abc"}}}')
            return (200, {}, '{}')

        responses.add_callback(responses.POST, re.compile(r'http://test\.com.*'), callback)

        result = check('http://test.com/graphql')
        assert result['vulnerable'] is True

    @responses.activate
    def test_no_graphql(self):
        responses.add(
            responses.POST, 'http://test.com/graphql',
            body='{"error":"not found"}', status=404,
        )
        responses.add(
            responses.GET, 'http://test.com/graphql',
            body='not found', status=404,
        )
        result = check('http://test.com/page')
        assert result['vulnerable'] is False
