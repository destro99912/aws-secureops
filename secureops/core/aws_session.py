import boto3
from boto3.session import Session

def get_aws_session(
    profile_name: str | None = None,
    region_name: str | None = None,
) -> Session:
    """
    Creates and returns a boto3 Session.
    
    If profile_name or region_name are omitted, boto3 resolves credentials and region
    using its standard resolution chain (environment variables, config files, instance profiles, etc.).
    """
    return boto3.Session(profile_name=profile_name, region_name=region_name)
