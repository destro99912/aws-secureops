import sys
import botocore.exceptions
from core.aws_session import get_aws_session

def main():
    print("=" * 60)
    print(" AWS SecureOps - Initializing Posture Scanner")
    print("=" * 60)
    
    profile = "secureops"
    
    try:
        # Initialize AWS session using the profile
        session = get_aws_session(profile_name=profile)
        
        # Initialize the STS client to verify identity
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()
        
        print("\n[+] Successfully connected to AWS!")
        print(f"    Account:  {identity.get('Account')}")
        print(f"    Arn:      {identity.get('Arn')}")
        print(f"    UserId:   {identity.get('UserId')}")
        print("\nAWS SecureOps is ready.")
        
    except botocore.exceptions.ProfileNotFound:
        print(f"\n[-] Error: The AWS profile '{profile}' was not found.")
        print("    Please ensure you have configured this profile in your AWS credentials file.")
        print(f"    You can create it by running: aws configure --profile {profile}")
        sys.exit(1)
        
    except botocore.exceptions.NoCredentialsError:
        print("\n[-] Error: No AWS credentials could be found.")
        print("    Please set up your AWS credentials using the AWS CLI or environment variables.")
        sys.exit(1)
        
    except botocore.exceptions.ClientError as e:
        print(f"\n[-] AWS Client Error: {e}")
        print("    Please check if your credentials are valid and have not expired.")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n[-] Unexpected Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
