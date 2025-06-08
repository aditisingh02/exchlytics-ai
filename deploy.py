from azure.ai.ml import MLClient
from azure.ai.ml.entities import ManagedOnlineEndpoint, ManagedOnlineDeployment
from azure.identity import DefaultAzureCredential
import os

def deploy_to_azure():
    # Get Azure credentials
    credential = DefaultAzureCredential()
    
    # Get Azure ML client
    ml_client = MLClient(
        credential=credential,
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        resource_group_name=os.getenv("AZURE_RESOURCE_GROUP"),
        workspace_name=os.getenv("AZURE_WORKSPACE_NAME")
    )
    
    # Create endpoint
    endpoint = ManagedOnlineEndpoint(
        name="pcap-analyzer-endpoint",
        description="PCAP Trading Data Analyzer using Streamlit",
        auth_mode="key"
    )
    
    ml_client.online_endpoints.begin_create_or_update(endpoint).wait()
    
    # Create deployment
    deployment = ManagedOnlineDeployment(
        name="pcap-analyzer-deployment",
        endpoint_name="pcap-analyzer-endpoint",
        model=None,  # No ML model needed
        code_configuration={
            "code": ".",
            "scoring_script": "ui/streamlit_app.py"
        },
        environment="pcap-analyzer-env",
        instance_type="Standard_DS3_v2",
        instance_count=1,
        app_insights_enabled=True,
        request_settings={
            "max_concurrent_requests_per_instance": 1,
            "request_timeout_ms": 90000
        }
    )
    
    ml_client.online_deployments.begin_create_or_update(deployment).wait()
    
    # Set traffic rules
    ml_client.online_endpoints.update_traffic(
        endpoint_name="pcap-analyzer-endpoint",
        traffic={"pcap-analyzer-deployment": 100}
    )
    
    print("Deployment completed successfully!")
    print(f"Endpoint URL: {ml_client.online_endpoints.get('pcap-analyzer-endpoint').scoring_uri}")

if __name__ == "__main__":
    deploy_to_azure() 