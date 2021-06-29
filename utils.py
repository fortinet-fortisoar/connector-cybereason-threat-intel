from connectors.core.connector import Connector, get_logger, ConnectorError
from netaddr import *
import copy

logger = get_logger('cybereasonTI')

#Utils
def payload_builder(params):
    '''
    Build POST JSON Body
    '''
    payload = {'requestData':[]}
    operation = params.get('operation')
    keys = params.get('keys')
    keys = keys.split(',') if ',' in keys else [keys]
    if isinstance(keys,list):
        for item in keys:
            if operation == 'file_batch':
                payload['requestData'].append({"requestKey": {resolve_hash_type(item): item}})
            elif operation == 'ip_batch':
                payload['requestData'].append({"requestKey": {'ipAddress': item,'addressType': validate_ip(item)}})
            elif operation == 'domain_batch':
                payload['requestData'].append({"requestKey": {"domain": item}})

    return payload

def resolve_hash_type(hash):
    '''
    lookup hash type
    '''
    if len(hash) == 32:
        return 'md5'
    elif len(hash) == 40:
        return 'sha1'
    else:
        logger.exception('Invalid Hash Code: {}'.format(hash))
        raise ConnectorError('Invalid Hash Code: {}'.format(hash))


def validate_ip(ip):
    '''
    Validate input address
    '''
    if valid_ipv4(ip):
        return 'Ipv4'
    elif valid_ipv6(ip):
        return 'Ipv6'
    else:
        logger.exception('Invalid Ipv4/Ipv6 Address: {}'.format(ip))
        raise ConnectorError('Invalid Ipv4/Ipv6 Address: {}'.format(ip))