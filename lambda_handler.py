import boto3
import requests
from botocore.config import Config

session = boto3.Session(profile_name='default')
boto3.setup_default_session(profile_name='default')

def get_allocation_id(event):
    event_name =   event["detail"]["eventName"]
    if event_name == 'DisassociateAddress':
        if "requestParameters" in event:    
            allocation_id = event['detail']['responseElements']['allocationId']
        else:
            print("This event has no allocation ID")
    else:
        return False
    
    return allocation_id



def eip_of_allocation_id(allocation_id):
    my_config = Config(
    region_name='ap-south-1') # define the region you are searching in
    ec2 =  boto3.client('ec2', config=my_config)
    response = ec2.describe_addresses(AllocationIds=allocation_id)
    for i in response['Addresses']:
        public_ip = i['PublicIp']
        if 'Tags' in i:
            for j in i['Tags']:
                tag = j['Value']
    
    return public_ip, tag




def searching_eip_in_R53(public_ip):
    ip = public_ip
    r53 = boto3.client('route53')
    try:
        r53_paginator = r53.get_paginator('list_hosted_zones')
        r53_page_iterator = r53_paginator.paginate()
        for page in r53_page_iterator:
            h_zones = page['HostedZones']
            for h_zone in h_zones:
                if not h_zone["Config"]['PrivateZone']:
                    try:
                        p_records = r53.get_paginator('list_resource_record_sets')
                        page_records =  p_records.paginate(HostedZoneId=h_zone['Id'])
                        for pages_records in page_records:
                            r_sets =  pages_records['ResourceRecordSets']
                            
                            for record in r_sets:
                                if record['Type'] == 'A':
                                    if 'ResourceRecords' in record:
                                        for i in record['ResourceRecords']:
                                            if i['Value'] == ip:
                                                Name = record['Name']
                                                Elastic_ip = i['Value']
                                                return Name, Elastic_ip
                                            else:
                                                return None
                            


                                #print(record['Name'])
                    except:
                        pass
    except:
        pass

def slack_alerts(Name, Elastic_ip, tag, allocation_id):
    template = {}
    template['attachments'] = [{}]
    template['attachments'][0]['fallback'] = 'unable to display this message !'
    template['attachments'][0]['color'] = '#F75D59'
    template['attachments'][0]['pretext'] = "Detecting IP that can be taken over "
    template['attachments'][0]['title'] = "Elastic IP Misconfiguration"
    template['attachments'][0]['fields'] = [{"title": "Elastic IP that can be vulnerable to Takeover"}]
    template['attachments'][0]['fields'].append({"title": "Domain elastic ip is mapped to"})
    template['attachments'][0]['fields'].append({"value": Name})
    template['attachments'][0]['fields'].append({"title": "Elastic IP"})
    template['attachments'][0]['fields'].append({"value": Elastic_ip})
    template['attachments'][0]['fields'].append({"title": " Tag on Elastic IP"})
    template['attachments'][0]['fields'].append({"value": tag})
    template['attachments'][0]['fields'].append({"title": "Allocation ID"})
    template['attachments'][0]['fields'].append({"value": allocation_id})



            

    json_template = json.dumps(template)
    requests.post(url='Incoming Webhook URL', data=json_template)


def lambda_handler(event, context):
    allocation_id =  get_allocation_id(event)
    public_ip, tag = get_allocation_id(allocation_id)
    if searching_eip_in_R53(public_ip):
        Name, Elastic_ip = searching_eip_in_R53(public_ip)
        slack_alerts(Name, Elastic_ip, tag, allocation_id)

    else:
        print("You are safe")




