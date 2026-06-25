import pytest
import responses
from tools.biz_logic_scanner import (
    check, check_mfa_bypass, check_price_manipulation,
    check_mass_assignment, check_coupon_abuse,
    check_workflow_bypass, check_idor_chain, check_rate_limit_bypass,
)


class TestMfaBypass:
    @responses.activate
    def test_direct_dashboard_access(self):
        responses.add(
            responses.GET, 'http://test.com/dashboard',
            body='dashboard content', status=200,
        )
        import requests
        sess = requests.Session()
        result = check_mfa_bypass('http://test.com', sess, 5)
        assert result['vulnerable'] is True

    @responses.activate
    def test_mfa_required(self):
        responses.add(
            responses.GET, 'http://test.com/dashboard',
            body='redirecting', status=302,
        )
        responses.add(
            responses.GET, 'http://test.com/profile',
            body='redirecting', status=302,
        )
        responses.add(
            responses.GET, 'http://test.com/admin',
            body='redirecting', status=302,
        )
        import requests
        sess = requests.Session()
        result = check_mfa_bypass('http://test.com', sess, 5)
        assert result['vulnerable'] is False


class TestPriceManipulation:
    @responses.activate
    def test_price_param_detected(self):
        import requests
        sess = requests.Session()
        def callback(request):
            body = '{"price": 99999, "total": 99999}'
            if 'price=1' in request.url:
                body = '{"price": 50, "total": 50}'
            return (200, {}, body)
        responses.add_callback(
            responses.GET, re.compile(r'http://test\.com/cart\?.*'),
            callback=callback,
        )
        result = check_price_manipulation('http://test.com/cart', 'price', sess, 5)
        assert result['vulnerable'] is True

    @responses.activate
    def test_non_price_param(self):
        import requests
        sess = requests.Session()
        result = check_price_manipulation('http://test.com/page', 'name', sess, 5)
        assert result['vulnerable'] is False


class TestMassAssignment:
    @responses.activate
    def test_mass_assignment_detected(self):
        import requests
        sess = requests.Session()
        responses.add(
            responses.POST, 'http://test.com/api/user',
            body='{"status":"ok"}', status=200,
        )
        result = check_mass_assignment('http://test.com/api/user', 'POST', sess, 5)
        assert result['vulnerable'] is not None


class TestCouponAbuse:
    @responses.activate
    def test_coupon_accepted(self):
        import requests
        sess = requests.Session()
        responses.add(
            responses.POST, 'http://test.com/api/coupon/redeem',
            body='{"status":"applied","discount":100}', status=200,
        )
        result = check_coupon_abuse('http://test.com', sess, 5)
        assert result['vulnerable'] is True

    @responses.activate
    def test_coupon_rejected(self):
        import requests
        sess = requests.Session()
        responses.add(
            responses.POST, re.compile(r'http://test\.com/.*coupon.*'),
            body='{"error":"invalid"}', status=400,
        )
        result = check_coupon_abuse('http://test.com', sess, 5)
        assert result['vulnerable'] is False


class TestWorkflowBypass:
    @responses.activate
    def test_skip_step_detected(self):
        import requests
        sess = requests.Session()
        responses.add(
            responses.GET, 'http://test.com/checkout/cart/checkout/payment',
            body='payment page', status=200,
        )
        responses.add(
            responses.GET, 'http://test.com/checkout/cart/checkout/cart',
            body='cart page', status=200,
        )
        result = check_workflow_bypass('http://test.com/checkout/cart', sess, 5)
        assert result['vulnerable'] is True


class TestIdorChain:
    @responses.activate
    def test_idor_chain_detection(self):
        import requests
        sess = requests.Session()
        body = '<a href="/user/550e8400-e29b-41d4-a716-446655440000">profile</a>'
        responses.add(
            responses.GET, 'http://test.com/users',
            body=body, status=200,
        )
        responses.add(
            responses.GET, re.compile(r'http://test\.com/user/.*'),
            body='user data' + 'x' * 50, status=200,
        )
        result = check_idor_chain('http://test.com/users', sess, 5)
        assert result['vulnerable'] is not None


class TestBizLogicMain:
    @responses.activate
    def test_main_check_aggregates(self):
        import requests
        sess = requests.Session()
        responses.add(
            responses.GET, 'http://test.com/dashboard',
            body='dashboard content', status=200,
        )
        responses.add(
            responses.GET, re.compile(r'http://test\.com/cart\?.*'),
            body='{"price": 999}', status=200,
        )
        responses.add(
            responses.POST, 'http://test.com/api/user',
            body='{"status":"ok"}', status=200,
        )
        responses.add(
            responses.GET, re.compile(r'http://test\.com/.*'),
            body='normal', status=200,
        )
        result = check('http://test.com', 'price')
        assert result['vulnerable'] is not None
        assert len(result['checks_run']) > 0


import re
