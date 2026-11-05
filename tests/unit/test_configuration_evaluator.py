
from vulnx.matching.configuration_evaluator import (
    evaluate_configuration_node,
    evaluate_cve_configurations,
)


LOG4J_MATCH = {
    "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
    "vulnerable": True,
}


def test_or_operator_matches_one_condition():
    node = {
        "operator": "OR",
        "negate": False,
        "matches": [LOG4J_MATCH],
        "children": [],
    }

    result = evaluate_configuration_node(
        node, "Apache", "Log4j", "2.14.1"
    )

    assert result is True


def test_and_operator_matches_all_conditions():
    node = {
        "operator": "AND",
        "negate": False,
        "matches": [
            {
                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "vulnerable": True,
            },
            {
                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "vulnerable": True,
            },
        ],
        "children": [],
    }

    result = evaluate_configuration_node(
        node, "Apache", "Log4j", "2.14.1"
    )

    assert result is True


def test_and_operator_fails_when_one_condition_fails():
    node = {
        "operator": "AND",
        "negate": False,
        "matches": [
            LOG4J_MATCH,
            {
                "criteria": "cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*",
                "vulnerable": True,
            },
        ],
        "children": [],
    }

    result = evaluate_configuration_node(
        node, "Apache", "Log4j", "2.14.1"
    )

    assert result is False


def test_not_operator():
    node = {
        "operator": "OR",
        "negate": True,
        "matches": [
            LOG4J_MATCH
        ],
        "children": [],
    }

    result = evaluate_configuration_node(
        node, "Apache", "Log4j", "2.14.1"
    )

    assert result is False


def test_unknown_result_for_empty_node():
    node = {
        "operator": "OR",
        "negate": False,
        "matches": [],
        "children": [],
    }

    result = evaluate_configuration_node(
        node, "Apache", "Log4j", "2.14.1"
    )

    assert result is None


def test_empty_configuration_list():
    result = evaluate_cve_configurations(
        [], "Apache", "Log4j", "2.14.1"
    )

    assert result is None


def test_nested_configuration():
    node = {
        "operator": "AND",
        "negate": False,
        "matches": [LOG4J_MATCH],
        "children": [
            {
                "operator": "OR",
                "negate": False,
                "matches": [LOG4J_MATCH],
                "children": [],
            }
        ],
    }

    result = evaluate_configuration_node(
        node, "Apache", "Log4j", "2.14.1"
    )

    assert result is True
