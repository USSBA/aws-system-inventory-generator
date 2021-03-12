 
import boto3
import csv
import json
import os
import time

# Create a local s3 resource for saving generated files at end
storage_s3 = boto3.resource('s3')
timestamp = int(time.time())

# account_id = os.environ.get('ACCOUNT')

def lambda_handler(event, context):
  account_id = event['account']
  print(account_id)
  # assume a role in another account and generate clients/resources
  sts_connection = boto3.client('sts')
  acct_b = sts_connection.assume_role(
    RoleArn="arn:aws:iam::" + account_id + ":role/ca-scanner",
    RoleSessionName="cross_acct_lambda_scanner"
  )
  
  ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
  SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
  SESSION_TOKEN = acct_b['Credentials']['SessionToken']
  
  # create service clients/resources using the assumed role credentials
  ec2 = boto3.resource(
    'ec2',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  ec2c = boto3.client(
    'ec2',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  elb = boto3.client(
    'elb',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
    )
    
  elbv2 = boto3.client(
    'elbv2',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
    )
  
  rds = boto3.client(
    'rds',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  dynamodb = boto3.client(
    'dynamodb',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  elasticache = boto3.client(
    'elasticache',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  apigateway = boto3.client(
    'apigateway',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  apigatewayv2 = boto3.client(
    'apigatewayv2',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  s3 = boto3.resource(
    's3',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  codebuild = boto3.client(
    'codebuild',
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    aws_session_token=SESSION_TOKEN,
  )
  
  # generate system inventory by mapping raw data to standard fields
  # consists of three lists: devices, interfaces, artifacts
  
  # === DEVICES ===
  devices = []

  # EC2
  for instance in ec2.instances.all():
    # Get related objects and attributes
    image_name = 'n/a'
    image = ec2.Image(instance.image_id)
    if hasattr(image, "name"):
      print(image.name)
      image_name = image.name
    # if ec2.Image(instance.image_id) is not None:
    #   image = ec2.Image(instance.image_id)
    #   print(image)
    #   if 'name' in image.keys():
    #     image_name = image.name
      
    tag_name = 'n/a'
    tag_environ = 'n/a'
    for tag in instance.tags:
      if tag['Key'] == 'Name':
        tag_name = tag['Value']
      if tag['Key'] == 'Environment':
        tag_environ = tag['Value']

    # Get data for each instance
    device = {
      "hostname"       : instance.private_dns_name,
      "status"         : instance.state['Name'],
      "launch_time"    : instance.launch_time,
      "private_ip"     : instance.private_ip_address,
      "public_ip"      : instance.public_ip_address,
      "baseline_image" : instance.image_id,
      "os_name"        : image_name,
      "antivirus"      : 'n/a',
      "device_type"    : 'server',
      "gfe_type"       : 'endpoint',
      "purpose"        : tag_name,
      "environment"    : tag_environ,
      "model"          : instance.instance_type,
      "os_logs"        : 'n/a',
      "server_type"    : 'virtual',
      "location"       : instance.vpc_id, # Need to add region here somehow
      "asset_serial"   : instance.id
    }
    devices.append(device)

  # ELB (classic)
  loadbalancers = elb.describe_load_balancers()
  for loadbalancer in loadbalancers['LoadBalancerDescriptions']:
    # Get listener, assuming listeners == 1 and no more!
    loadbalancerlistener = loadbalancer['ListenerDescriptions'].pop()
    # Get data for each instance
    device = {
      "hostname"       : loadbalancer['LoadBalancerName'],
      "status"         : loadbalancer['Scheme'],
      "launch_time"    : str(loadbalancer['CreatedTime']),
      "private_ip"     : loadbalancerlistener['Listener']['InstanceProtocol'] + ":" + str(loadbalancerlistener['Listener']['InstancePort']),
      "public_ip"      : loadbalancerlistener['Listener']['Protocol'] + ":" + str(loadbalancerlistener['Listener']['LoadBalancerPort']),
      "baseline_image" : 'n/a',
      "os_name"        : 'n/a',
      "antivirus"      : 'n/a',
      "device_type"    : 'load balancer',
      "gfe_type"       : 'endpoint',
      "purpose"        : 'n/a',
      "environment"    : 'n/a',
      "model"          : 'classic',
      "os_logs"        : 'n/a',
      "server_type"    : 'virtual',
      "location"       : loadbalancer['VPCId'], # Need to add region here somehow
      "asset_serial"   : loadbalancer['Instances']
    }
    devices.append(device)

  # ELBv2 (application/network)
  loadbalancers = elbv2.describe_load_balancers()
  for loadbalancer in loadbalancers['LoadBalancers']:
    # private_ips = []
    # public_ips  = []
    # for az in loadbalancer['AvailabilityZones']:
    #   for address in az['LoadBalancerAddresses']:
    #     private_ips.append(address['IpAddress'])
    #     public_ips.append(address['PrivateIPv4Address'])
    # Get data for each instance
    device = {
      # "hostname"       : loadbalancer['DNSName'],
      "hostname"       : loadbalancer['LoadBalancerName'],
      "status"         : loadbalancer['State']['Code'],
      "launch_time"    : str(loadbalancer['CreatedTime']),
      "private_ip"     : loadbalancer['AvailabilityZones'],
      # "private_ip"     : private_ips,
      "public_ip"      : loadbalancer['DNSName'],
      # "public_ip"      : public_ips,
      "baseline_image" : 'n/a',
      "os_name"        : 'n/a',
      "antivirus"      : 'n/a',
      "device_type"    : 'load balancer',
      "gfe_type"       : 'endpoint',
      "purpose"        : loadbalancer['Scheme'],
      "environment"    : 'n/a',
      "model"          : loadbalancer['Type'],
      "os_logs"        : 'n/a',
      "server_type"    : 'virtual',
      "location"       : loadbalancer['VpcId'], # Need to add region here somehow
      "asset_serial"   : loadbalancer['LoadBalancerArn']
    }
    devices.append(device)

  # === INTERFACES ===
  interfaces = []

  # VPC
  for vpc in ec2.vpcs.all():
    if vpc.tags is None:
      tag_name = 'n/a'
      tag_environ = 'n/a'
    else:
      for tag in vpc.tags:
        if tag['Key'] == 'Name':
          tag_name = tag['Value']
        if tag['Key'] == 'Environment':
          tag_environ = tag['Value']

    interface = {
      "hostname"       : tag_name,
      "status"         : vpc.state,
      "uri"            : 'n/a',
      "type"           : 'virtual private cloud',
      "authentication" : 'n/a',
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : vpc.cidr_block,
      "public_ip"      : 'n/a',
      "port"           : 'n/a',
      "protocol"       : 'n/a',
      "service"        : 'n/a',
      "environment"    : tag_environ,
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : 'Parent network object',
      "asset_serial"   : vpc.id,
    }
    interfaces.append(interface)

    # INTERNET GATEWAYS
    for gateway in vpc.internet_gateways.all():
      
      # Get related tag data
      tag_name = 'n/a'
      tag_environ = 'n/a'
      for tag in gateway.tags:
        if tag['Key'] == 'Name':
          tag_name = tag['Value']
          print(tag_name)
        if tag['Key'] == 'Environment':
          tag_environ = tag['Value']
          print(tag_environ)
      
      attach_status = 'n/a'
      attach_private_ip = 'n/a'
      # Get VPC attachments
      if len(gateway.attachments) > 1:
        attach_status = 'see private_ip for list'
        attach_private_ip = gateway.attachments
      else:
        for attachment in gateway.attachments:
          attach_status = attachment['State']
          attach_private_ip = attachment['VpcId']
      
      # Get data for each instance
      interface = {
        "hostname"       : tag_name,
        "status"         : attach_status,
        "uri"            : 'n/a',
        "type"           : 'internet gateway',
        "authentication" : 'n/a',
        "account_id"     : "AWS: " + gateway.owner_id,
        "private_ip"     : attach_private_ip,
        "public_ip"      : 'n/a',
        "port"           : 'n/a',
        "protocol"       : 'n/a',
        "service"        : 'n/a',
        "environment"    : tag_environ,
        "admin_email"    : 'n/a',
        "admin_phone"    : 'n/a',
        "activity_log"   : 'n/a',
        "comments"       : 'Logical connection between VPC and Internet',
        "asset_serial"   : gateway.internet_gateway_id,
      }
      interfaces.append(interface)

  # SUBNETS
  for subnet in ec2.subnets.all():
    if subnet.tags is None:
      tag_name = 'n/a'
    else:
      for tag in subnet.tags:
        if tag['Key'] == 'Name':
          tag_name = tag['Value']
        if tag['Key'] == 'Environment':
          tag_environ = tag['Value']
  
    interface = {
      "hostname"       : tag_name,
      "status"         : subnet.state,
      "uri"            : 'n/a',
      "type"           : 'subnet',
      "authentication" : 'n/a',
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : subnet.cidr_block,
      "public_ip"      : 'n/a',
      "port"           : 'n/a',
      "protocol"       : 'n/a',
      "service"        : 'n/a',
      "environment"    : tag_environ,
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : 'Subdivison of: ' + subnet.vpc_id, 
      "asset_serial"   : subnet.id,
    }
    interfaces.append(interface)
  
  # NAT GATEWAYS
  gateways = ec2c.describe_nat_gateways()
  for gateway in gateways['NatGateways']:
    print(gateway)
    # Get related tag data
    tag_name = 'n/a'
    tag_environ = 'n/a'
    for tag in gateway['Tags']:
      if tag['Key'] == 'Name':
        tag_name = tag['Value']
      if tag['Key'] == 'Environment':
        tag_environ = tag['Value']
    
    gateway_private_ip = 'n/a'
    gateway_public_ip = 'n/a'
    if len(gateway['NatGatewayAddresses']) > 1:
      gateway_private_ip = gateway['NatGatewayAddresses']
      gateway_public_ip = 'see private_ip for list of addresses'
    else:
      gateway_address = gateway['NatGatewayAddresses'].pop()
      gateway_private_ip = gateway_address['PrivateIp']
      gateway_public_ip = gateway_address['PublicIp']
      
    # Get data for each instance
    interface = {
      "hostname"       : tag_name,
      "status"         : gateway['State'],
      "uri"            : 'n/a',
      "type"           : 'nat gateway',
      "authentication" : 'n/a',
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : gateway_private_ip,
      "public_ip"      : gateway_public_ip,
      "port"           : 'n/a',
      "protocol"       : 'n/a',
      "service"        : 'n/a',
      "environment"    : tag_environ,
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : 'NAT to allow access to internet',
      "asset_serial"   : gateway['NatGatewayId'],
    }
    interfaces.append(interface)
  
  # RDS    
  instances = rds.describe_db_instances()
  for instance in instances['DBInstances']:
    interface = {
      # instance['DBName'] <--this isn't super useful right now
        "hostname"       : instance['DBInstanceIdentifier'],
        "status"         : instance['DBInstanceStatus'],
        "uri"            : instance.get('Endpoint').get('Address'),
        "type"           : 'relational database service',
        "authentication" : 'n/a',
        "account_id"     : "AWS: " + account_id,
        "private_ip"     : 'n/a',
        "public_ip"      : instance['PubliclyAccessible'],
        "port"           : str(instance.get('Endpoint').get('Port')),
        "protocol"       : instance['Engine'] + ", v" + instance['EngineVersion'],
        "service"        : instance['DBInstanceClass'] ,
        "environment"    : instance['AvailabilityZone'] + " (Multi AZ Enabled? " + str(instance['MultiAZ']) + ")",
        "admin_email"    : 'n/a',
        "admin_phone"    : 'n/a',
        "activity_log"   : 'n/a',
        "comments"       : 'Encrypted? ' + str(instance['StorageEncrypted']) + '; Backup Retention Period? ' + str(instance['BackupRetentionPeriod']),
        "asset_serial"   : instance['DBInstanceArn']
    }
    interfaces.append(interface)
  
  # DYNAMODB
  databases = dynamodb.describe_endpoints()
  for endpoint in databases['Endpoints']:
  
    tables = dynamodb.list_tables()
    for table in tables['TableNames']:
      dtable = dynamodb.describe_table(TableName=str(table))

      # Get data for each instance
      interface = {
        "hostname"       : dtable['Table']['TableName'],
        "status"         : dtable['Table']['TableStatus'],
        "uri"            : endpoint['Address'],
        "type"           : 'dynamodb table',
        "authentication" : 'n/a',
        "account_id"     : "AWS: " + account_id,
        "private_ip"     : 'n/a',
        "public_ip"      : 'n/a',
        "port"           : 'n/a',
        "protocol"       : 'n/a',
        "service"        : 'n/a',
        "environment"    : 'tbd',
        "admin_email"    : 'n/a',
        "admin_phone"    : 'n/a',
        "activity_log"   : 'n/a',
        "comments"       : 'Managed database service for non-relational data',
        "asset_serial"   : dtable['Table']['TableArn'],
      }
      interfaces.append(interface)
  
  # ELASTICACHE
  clusters = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True)
  for cluster in clusters['CacheClusters']:
    # Guard against cases where only 1 node exists
    cluster_endpoint = 'n/a'
    cluster_port = 'n/a'
    if (cluster['NumCacheNodes'] == 1):
      cluster_node = cluster['CacheNodes'].pop()
      cluster_endpoint = cluster_node['Endpoint']['Address']
      cluster_port = cluster_node['Endpoint']['Port']
    else:
      cluster_endpoint = cluster['ConfigurationEndpoint']['Address']
      cluster_port = cluster['ConfigurationEndpoint']['Port']

    # Get details for each interface
    interface = {
      "hostname"       : cluster['CacheClusterId'],
      "status"         : cluster['CacheClusterStatus'],
      "uri"            : cluster_endpoint,
      "type"           : 'elasticache cluster',
      "authentication" : cluster['AuthTokenEnabled'],
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : 'n/a',
      "public_ip"      : 'n/a',
      "port"           : str(cluster_port),
      "protocol"       : cluster['Engine'] + ", v" + cluster['EngineVersion'],
      "service"        : cluster['CacheNodeType'],
      "environment"    : 'n/a',
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : 'Managed in-memory data store and cache service. Encrypted at rest? ' + str(cluster['AtRestEncryptionEnabled']) + '; Encrypted in transit? ' + str(cluster['TransitEncryptionEnabled']),
      "asset_serial"   : cluster['CacheClusterId'],
    }
    interfaces.append(interface)
  
  
  # API GATEWAY (v1)
  apis = apigateway.get_rest_apis()
  for api in apis['items']:
    # Get details for each interface
    interface = {
      "hostname"       : api['name'],
      "status"         : 'n/a',
      "uri"            : 'n/a',
      "type"           : 'api gateway',
      "authentication" : 'n/a',
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : 'n/a',
      "public_ip"      : 'n/a',
      "port"           : 'n/a',
      "protocol"       : 'n/a',
      "service"        : 'n/a',
      "environment"    : 'n/a',
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : 'n/a',
      "asset_serial"   : api['id'],
    }
    interfaces.append(interface)
    
  # API GATEWAY (v2)
  apis = apigatewayv2.get_apis()
  for api in apis['Items']:
    # Get details for each interface
    interface = {
      "hostname"       : api['Name'],
      "status"         : 'n/a',
      "uri"            : api['ApiEndpoint'],
      "type"           : 'api gateway',
      "authentication" : 'n/a',
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : 'n/a',
      "public_ip"      : 'n/a',
      "port"           : 'n/a',
      "protocol"       : api['ProtocolType'],
      "service"        : 'n/a',
      "environment"    : 'n/a',
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : api['Description'],
      "asset_serial"   : api['ApiId'],
    }
    interfaces.append(interface)

  # Security team does NOT currently want every network interface (12/30/19)
  # for network_interface in ec2.network_interfaces.all():
  #   interface = {
  #     "name"           : network_interface.mac_address,
  #     "id"             : network_interface.id,
  #     "description"    : network_interface.description,
  #     "private_ip"     : network_interface.private_ip_address,
  #     "public_ip"      : network_interface.association_attribute,
  #     "ip_ranges"      : network_interface.private_ip_addresses
  #   }
  #   interfaces.append(interface)

  projects = codebuild.list_projects()
  for project in projects['projects']:
    # Get details for each interface
    interface = {
      "hostname"       : str(project),
      "status"         : 'n/a',
      "uri"            : 'n/a',
      "type"           : 'codebuild project',
      "authentication" : 'n/a',
      "account_id"     : "AWS: " + account_id,
      "private_ip"     : 'n/a',
      "public_ip"      : 'n/a',
      "port"           : 'n/a',
      "protocol"       : 'n/a',
      "service"        : 'n/a',
      "environment"    : 'n/a',
      "admin_email"    : 'n/a',
      "admin_phone"    : 'n/a',
      "activity_log"   : 'n/a',
      "comments"       : 'Fully managed build service',
      "asset_serial"   : str(project),
    }
    interfaces.append(interface)

  # === ARTIFACTS ===
  artifacts = []

  for bucket in s3.buckets.all():
    #   print (bucket)
    artifact = {
      "name"           : bucket.name,
      "status"         : 'n/a',
      "id"             : bucket.name,
      "type"           : 'S3 Bucket',
      "description"    : 'Object storage container',
      "comments"       : 'Creation Date: ' + str(bucket.creation_date),
    }
    artifacts.append(artifact)
    
  for security_group in ec2.security_groups.all():
    artifact = {
      "name"           : security_group.group_name,
      "status"         : 'n/a',
      "id"             : security_group.group_id,
      "type"           : 'Security Group',
      "description"    : security_group.description,
      "comments"      : security_group.ip_permissions
    }
    artifacts.append(artifact)
  
  # Local print to debug
  print("DEVICES")
  print(devices)
  print("INTERFACES")
  print(interfaces)
  print("ARTIFACTS")
  print(artifacts)
  
  # Print the inventory to local file system then upload to S3

  # Upload devices list to S3 Object
  with open('/tmp/devices.csv', 'w', newline='') as csvfile:
    fieldnames = ['hostname', 'status', 'launch_time', 'private_ip', 'public_ip', 'baseline_image', 'os_name', 'antivirus', 'device_type', 'gfe_type', 'purpose', 'environment', 'model', 'os_logs', 'server_type', 'location', 'asset_serial']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for d in devices:
      writer.writerow(d)

  device_file = account_id + "/" + str(timestamp) + '-devices.csv'
  bucket = storage_s3.Bucket("system-inventory-test").upload_file('/tmp/devices.csv', device_file)

  # Upload interface list to S3 Object
  with open('/tmp/interfaces.csv', 'w', newline='') as csvfile:
    fieldnames = ['hostname', 'status', 'uri', 'type', 'authentication', 'account_id', 'private_ip', 'public_ip', 'port', 'protocol', 'service', 'environment', 'admin_email', 'admin_phone', 'activity_log', 'comments', 'asset_serial']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for i in interfaces:
      writer.writerow(i)

  interface_file = account_id + "/" + str(timestamp) + '-interfaces.csv'
  bucket = storage_s3.Bucket("system-inventory-test").upload_file('/tmp/interfaces.csv', interface_file)

  # Upload artifact list to S3 Object
  with open('/tmp/artifacts.csv', 'w', newline='') as csvfile:
    fieldnames = ['name', 'status', 'id', 'type', 'description', 'comments']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for a in artifacts:
      writer.writerow(a)

  artifact_file = account_id + "/" + str(timestamp) + '-artifacts.csv'
  bucket = storage_s3.Bucket("system-inventory-test").upload_file('/tmp/artifacts.csv', artifact_file)

  return {
    'statusCode': 200,
    'body': json.dumps('Inventory created for: ' + account_id)
  }
