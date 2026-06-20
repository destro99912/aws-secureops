import boto3

def get_aws_session(profile_name="secureops", region_name="us-east-1"):
    """
    Creates and returns a boto3 Session using the specified AWS CLI profile and region.
    
    Args:
        profile_name (str): The name of the AWS CLI profile to use.
        region_name (str): The AWS region to associate with the session.
        
    Returns:
        boto3.Session: A boto3 Session object configured with the specified profile and region.
    """
    return boto3.Session(profile_name=profile_name, region_name=region_name)
