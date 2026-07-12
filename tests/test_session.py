from unittest.mock import patch
from secureops.core.aws_session import get_aws_session


def test_session_created_without_profile():
    """
    Test that calling get_aws_session with no args passes None/None to boto3.Session.
    """
    with patch("boto3.Session") as mock_session_class:
        get_aws_session()
        mock_session_class.assert_called_once_with(profile_name=None, region_name=None)


def test_session_created_with_profile():
    """
    Test that calling get_aws_session with a profile passes it to boto3.Session.
    """
    with patch("boto3.Session") as mock_session_class:
        get_aws_session(profile_name="my-profile")
        mock_session_class.assert_called_once_with(profile_name="my-profile", region_name=None)


def test_session_created_with_profile_and_region():
    """
    Test that calling get_aws_session with both profile and region passes them to boto3.Session.
    """
    with patch("boto3.Session") as mock_session_class:
        get_aws_session(profile_name="my-profile", region_name="us-west-2")
        mock_session_class.assert_called_once_with(profile_name="my-profile", region_name="us-west-2")


def test_session_created_with_region_only():
    """
    Test that calling get_aws_session with a region only passes it to boto3.Session.
    """
    with patch("boto3.Session") as mock_session_class:
        get_aws_session(region_name="eu-west-1")
        mock_session_class.assert_called_once_with(profile_name=None, region_name="eu-west-1")
